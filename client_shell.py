#!/usr/bin/env python3
"""Client-facing launcher for the WLM sorting service.

Shows a minimal status window and runs the Flask server (app.py) on a
background thread, in-process. The client never sees a URL, login screen,
or the sorting UI here — only WLM's team, connecting separately over
Tailscale with the shared password, does.

Runs Flask in-thread rather than as a subprocess so this can be frozen into
a single PyInstaller executable: a frozen binary has no separate `python`
interpreter or app.py file on disk to subprocess out to.

First launch shows a setup screen (Tailscale steps + a folder picker) before
ever touching the filesystem. `app.py` is only imported once a folder is
chosen, because PHOTOS_DIR must be set before that import — importing it
against the client's entire home directory would make macOS's privacy
prompts fire once per protected category (Desktop, Documents, Downloads,
iCloud Drive, ...) the moment it's scanned, instead of once for the one
folder the client actually agreed to.
"""
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox

from PIL import Image, ImageTk

APP_VERSION = "1.0.0"


def _bundle_dir() -> Path:
    """Where our own bundled files (static/, resources/) live: next to this
    script in dev, or inside PyInstaller's extracted bundle dir once
    packaged. sys._MEIPASS is PyInstaller's own answer to "where did my
    datas/binaries actually land" — on macOS .app bundles that's
    Contents/Resources, not next to the executable in Contents/MacOS, so
    don't derive this from sys.executable."""
    if getattr(sys, 'frozen', False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def _resource_dir() -> Path:
    """Where bundled ffmpeg/exiftool live."""
    return _bundle_dir() / 'resources'


def _setup_bundled_tools():
    """Put our bundled ffmpeg/exiftool ahead of PATH so app.py's bare
    'ffmpeg'/'exiftool' subprocess calls find them without the client needing
    either installed. exiftool is a Perl script with Homebrew's absolute
    Cellar path hardcoded into its own `unshift @INC` lines; those entries
    just won't exist on a client machine and get silently skipped, so we
    supply the real module path via PERL5LIB instead of relying on them."""
    res = _resource_dir()
    exiftool_dir = res / 'exiftool'
    lib_dir = exiftool_dir / 'lib' / 'perl5'
    if not res.is_dir():
        return  # dev machine without resources/ set up yet — falls back to system PATH
    os.environ['PATH'] = f"{res}{os.pathsep}{exiftool_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    existing_perl5lib = os.environ.get('PERL5LIB', '')
    os.environ['PERL5LIB'] = f"{lib_dir}{os.pathsep}{existing_perl5lib}" if existing_perl5lib else str(lib_dir)


_setup_bundled_tools()

# macOS's AirPlay Receiver listens on 5000 (and sometimes 7000) by default on
# most Macs out of the box — Flask's own default port would collide with it
# on a fresh client machine. Docker deploys set PORT themselves via compose,
# so this only fills the gap for a plain double-clicked client build.
os.environ.setdefault('PORT', '2514')

CONFIG_DIR = Path.home() / 'Library' / 'Application Support' / 'WLM Sorting Service'
CONFIG_FILE = CONFIG_DIR / 'config.json'

WLM_TAILSCALE_SHARE_EMAIL = "whitelightsmediauk@gmail.com"

SETUP_STEPS_TEXT = (
    "1. Download and install Tailscale (button below).\n\n"
    "2. Open Tailscale and sign in — any Google, Microsoft, or email account "
    "works. This creates your own free Tailscale account, completely "
    "separate from White Lights Media's.\n\n"
    "3. Open the Tailscale admin console (button below), go to the DNS tab, "
    "and turn on \"HTTPS Certificates\". This is a one-time setting for your "
    "account — it lets this app connect securely.\n\n"
    "4. Click the Tailscale icon in your menu bar, choose \"Share...\", "
    "select this computer, and share it with:\n"
    f"        {WLM_TAILSCALE_SHARE_EMAIL}\n\n"
    "5. Choose the folder below for White Lights Media to work in, then "
    "click Done."
)

_COL_BG = "#181818"
_COL_FG = "#e0e0e0"
_COL_FG_DIM = "#707070"
_COL_ACCENT = "#d4a017"
_COL_BTN = "#404040"
_COL_BTN_FG = "#ffffff"
_COL_BTN_DISABLED = "#2a2a2a"
_COL_BTN_SUBTLE = "#262626"
_COL_GREEN = "#2ecc71"
_COL_YELLOW = "#e6b800"
_COL_RED = "#e74c3c"

# Keyed status states: each drives both the dot color and the message text,
# kept together so they can never drift out of sync with each other.
STATUS_STATES = {
    'starting': {'text': "Starting sorting service...", 'color': _COL_FG_DIM},
    'waiting': {'text': "Not connected\n(waiting for Tailscale)", 'color': _COL_YELLOW},
    'ready': {'text': "Connected\nReady for White Lights Media", 'color': _COL_GREEN},
    'crashed': {'text': "Sorting service stopped unexpectedly\nPlease contact White Lights Media", 'color': _COL_RED},
}


def _make_button(parent, text, command, bg, fg, bold=False, font_size=12):
    """Plain tk.Button mostly ignores custom bg/fg on macOS — it always
    renders as a native gray Aqua button regardless of what's passed in,
    which is why buttons looked washed out. A Label styled and bound as a
    button sidesteps that and actually shows our colors."""
    btn = tk.Label(
        parent, text=text, bg=bg, fg=fg,
        font=("-apple-system", font_size, "bold" if bold else "normal"),
        padx=14, pady=9, cursor="pointinghand",
    )
    btn.bind("<Button-1>", lambda e: command())
    return btn


def _load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def _save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg))


def _restart_app():
    """Full process restart so app.py (and its module-level BASE) picks up
    a newly-chosen PHOTOS_DIR. Once `app` is imported, BASE is fixed for the
    life of the process — there's no clean way to re-point it in place.

    Spawns a genuinely new process rather than self-exec'ing in place
    (os.execv): PyInstaller's frozen macOS bootloader does a one-time
    task-policy setup that breaks when re-exec'd into the same process,
    leaving the app stuck with the old server still bound to the port.
    Launching fresh via `open -n` and then exiting avoids that; the new
    process's own bind-retry loop (see _run_server) absorbs the brief
    window where the old process hasn't released the port yet."""
    if getattr(sys, 'frozen', False):
        app_bundle = Path(sys.executable).resolve().parents[2]  # Contents/MacOS/exe -> the .app itself
        subprocess.Popen(['open', '-n', str(app_bundle)])
    else:
        subprocess.Popen([sys.executable, os.path.abspath(__file__)])
    os._exit(0)


LAUNCH_AGENT_LABEL = "com.whitelightsmedia.wlmsortingservice"
LAUNCH_AGENT_PLIST = Path.home() / 'Library' / 'LaunchAgents' / f'{LAUNCH_AGENT_LABEL}.plist'


def _set_launch_at_login(enabled: bool):
    """Best-effort — a client's Mac rebooting mid-competition (software
    update, power blip) would otherwise silently take the service offline
    until someone notices and manually relaunches it. Only meaningful for
    the packaged .app; a no-op in dev mode since there's no fixed bundle
    path to point a LaunchAgent at."""
    try:
        if not enabled:
            if LAUNCH_AGENT_PLIST.exists():
                subprocess.run(['launchctl', 'unload', str(LAUNCH_AGENT_PLIST)], capture_output=True)
                LAUNCH_AGENT_PLIST.unlink()
            return
        if not getattr(sys, 'frozen', False):
            return
        app_bundle = Path(sys.executable).resolve().parents[2]
        plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/open</string>
        <string>-g</string>
        <string>-a</string>
        <string>{app_bundle}</string>
    </array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
'''
        LAUNCH_AGENT_PLIST.parent.mkdir(parents=True, exist_ok=True)
        LAUNCH_AGENT_PLIST.write_text(plist)
        subprocess.run(['launchctl', 'load', str(LAUNCH_AGENT_PLIST)], capture_output=True)
    except Exception:
        pass  # non-critical — worst case, the client just has to relaunch manually after a reboot


def _gather_diagnostics(folder: str) -> str:
    try:
        ts_bin = server_app._tailscale_binary()
        result = subprocess.run([ts_bin, 'ip', '-4'], capture_output=True, text=True, timeout=5)
        ts_ip = result.stdout.strip().splitlines()[0] if result.returncode == 0 and result.stdout.strip() else "not connected"
    except Exception:
        ts_ip = "tailscale not found"
    try:
        hostname = server_app._get_tailscale_hostname() or "not available yet"
    except Exception:
        hostname = "not available yet"
    port = os.environ.get('PORT', 5000)
    return "\n".join([
        "WLM Sorting Service diagnostics",
        f"Version: {APP_VERSION}",
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Working folder: {folder}",
        f"Tailscale IP: {ts_ip}",
        f"Address for White Lights Media to use: https://{hostname}:{port}",
        f"ffmpeg found: {bool(shutil.which('ffmpeg'))}",
        f"exiftool found: {bool(shutil.which('exiftool'))}",
        f"Cache folder: {os.environ.get('THUMB_DIR', 'n/a')}",
    ])


def _import_server_app(photos_dir: str):
    os.environ['PHOTOS_DIR'] = photos_dir
    # On the NAS deploy, THUMB_DIR (default /tmp/wlm_thumbs) is deliberately
    # bind-mounted to persistent storage so the thumbnail cache survives
    # container restarts. A bare-metal Mac has no such mount — macOS
    # periodically sweeps files in /tmp that haven't been touched in a few
    # days — so point it at our own persistent app-support folder instead.
    # This is independent of PHOTOS_DIR/BASE, so changing folder later never
    # touches or clears it.
    os.environ.setdefault('THUMB_DIR', str(CONFIG_DIR / 'thumbs'))
    global server_app
    import app as server_app


class ServiceShell:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("WLM Sorting Service")
        self.root.resizable(False, False)
        self.root.configure(bg=_COL_BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._stopped = False
        self._chosen_folder = tk.StringVar(value="No folder chosen yet")
        self._launch_at_login_var = tk.BooleanVar(value=True)

        # WM_DELETE_WINDOW only fires on a clean window close. A force-quit
        # or `kill` sends SIGTERM/SIGINT straight past Tkinter — harmless now
        # that Flask runs on a daemon thread in this same process (it dies
        # with the process either way), but we still exit cleanly rather
        # than leaving Tkinter in a half-torn-down state.
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

        cfg = _load_config()
        folder = cfg.get('photos_dir')
        if folder and Path(folder).is_dir():
            self._begin_serving(folder)
        else:
            self._build_setup_screen()

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _logo_image(self, width):
        """Cached per-width PhotoImage of the WLM logo. Tkinter drops an
        image the moment nothing keeps a Python reference to it, so the
        cache dict living on self is what keeps it on screen, not just an
        optimization."""
        if not hasattr(self, '_logo_cache'):
            self._logo_cache = {}
        if width not in self._logo_cache:
            try:
                img = Image.open(_bundle_dir() / 'static' / 'wlm_logo.png')
                ratio = img.height / img.width
                img = img.resize((width, round(width * ratio)), Image.LANCZOS)
                self._logo_cache[width] = ImageTk.PhotoImage(img)
            except Exception:
                self._logo_cache[width] = None
        return self._logo_cache[width]

    # ── First-run setup screen ──────────────────────────────────────────

    def _build_setup_screen(self):
        self._clear()
        self.root.geometry("440x660")
        pad = {'padx': 24}

        logo = self._logo_image(240)
        if logo:
            tk.Label(self.root, image=logo, bg=_COL_BG).pack(pady=(28, 16))
        else:
            tk.Label(
                self.root, text="Welcome to the WLM Sorting Service", fg=_COL_FG, bg=_COL_BG,
                font=("-apple-system", 15, "bold"), wraplength=390, justify="left",
            ).pack(pady=(24, 12), **pad)

        tk.Label(
            self.root, text=SETUP_STEPS_TEXT, fg="#c8c8c8", bg=_COL_BG,
            font=("-apple-system", 12), wraplength=390, justify="left",
        ).pack(pady=(0, 14), **pad)

        _make_button(
            self.root, "Open Tailscale download page",
            lambda: webbrowser.open('https://tailscale.com/download'),
            bg=_COL_BTN, fg=_COL_BTN_FG,
        ).pack(pady=(0, 10), **pad)

        _make_button(
            self.root, "Open Tailscale admin console (for step 3)",
            lambda: webbrowser.open('https://login.tailscale.com/admin/dns'),
            bg=_COL_BTN, fg=_COL_BTN_FG,
        ).pack(pady=(0, 20), **pad)

        tk.Frame(self.root, bg="#333", height=1).pack(fill='x', **pad)

        tk.Label(
            self.root, text="Choose the folder for White Lights Media to work in:",
            fg=_COL_FG, bg=_COL_BG, font=("-apple-system", 12, "bold"),
            wraplength=390, justify="left",
        ).pack(pady=(20, 6), **pad)

        tk.Label(
            self.root, textvariable=self._chosen_folder, fg=_COL_ACCENT, bg=_COL_BG,
            font=("-apple-system", 11), wraplength=390, justify="left",
        ).pack(pady=(0, 14), **pad)

        _make_button(
            self.root, "Browse...", self._on_browse, bg=_COL_BTN, fg=_COL_BTN_FG,
        ).pack(pady=(0, 16), **pad)

        tk.Checkbutton(
            self.root, text="Launch automatically when this Mac starts (recommended)",
            variable=self._launch_at_login_var, fg=_COL_FG, bg=_COL_BG,
            selectcolor=_COL_BTN, activebackground=_COL_BG, activeforeground=_COL_FG,
            font=("-apple-system", 11), wraplength=390, justify="left",
            highlightthickness=0, bd=0,
        ).pack(pady=(0, 16), **pad)

        self._done_btn = _make_button(
            self.root, "Done", self._on_setup_done, bg=_COL_BTN_DISABLED, fg=_COL_FG_DIM, bold=True,
        )
        self._done_btn.unbind("<Button-1>")
        self._done_btn.configure(cursor="arrow")
        self._done_btn.pack(pady=(0, 24), **pad)

    def _on_browse(self):
        folder = filedialog.askdirectory(title="Choose a folder for White Lights Media")
        if folder:
            self._chosen_folder.set(folder)
            self._done_btn.configure(bg=_COL_ACCENT, fg=_COL_BG, cursor="pointinghand")
            self._done_btn.bind("<Button-1>", lambda e: self._on_setup_done())

    def _on_setup_done(self):
        folder = self._chosen_folder.get()
        _save_config({'photos_dir': folder})
        _set_launch_at_login(self._launch_at_login_var.get())
        self._begin_serving(folder)

    # ── Running status screen ────────────────────────────────────────────

    def _begin_serving(self, folder):
        self._clear()
        self.root.geometry("360x410")

        logo = self._logo_image(180)
        if logo:
            tk.Label(self.root, image=logo, bg=_COL_BG).pack(pady=(28, 12))
        else:
            dot = tk.Canvas(self.root, width=16, height=16, bg=_COL_BG, highlightthickness=0)
            dot.create_oval(2, 2, 14, 14, fill=_COL_ACCENT, outline="")
            dot.pack(pady=(24, 8))

        status_row = tk.Frame(self.root, bg=_COL_BG)
        status_row.pack(pady=4, expand=True)

        self._status_dot = tk.Canvas(status_row, width=12, height=12, bg=_COL_BG, highlightthickness=0)
        self._status_dot_oval = self._status_dot.create_oval(2, 2, 10, 10, fill=_COL_FG_DIM, outline="")
        self._status_dot.pack(side="left", padx=(0, 8))

        self.status_var = tk.StringVar(value=STATUS_STATES['starting']['text'])
        tk.Label(
            status_row, textvariable=self.status_var, fg=_COL_FG, bg=_COL_BG,
            font=("-apple-system", 13), wraplength=280, justify="left",
        ).pack(side="left")

        tk.Label(
            self.root, text=f"Working folder: {folder}", fg=_COL_FG_DIM, bg=_COL_BG,
            font=("-apple-system", 10), wraplength=320, justify="center",
        ).pack(pady=(0, 6))

        self.stats_var = tk.StringVar(value="")
        self.stats_label = tk.Label(
            self.root, textvariable=self.stats_var, fg=_COL_FG_DIM, bg=_COL_BG,
            font=("-apple-system", 10),
        ).pack(pady=(0, 10))

        _make_button(
            self.root, "Change folder...", self._on_change_folder,
            bg=_COL_BTN_SUBTLE, fg=_COL_FG_DIM, font_size=10,
        ).pack(pady=(0, 2))

        _make_button(
            self.root, "Delete cache...", self._on_delete_cache,
            bg=_COL_BTN_SUBTLE, fg=_COL_FG_DIM, font_size=10,
        ).pack(pady=(0, 2))

        _make_button(
            self.root, "Restart service...", self._on_restart_service,
            bg=_COL_BTN_SUBTLE, fg=_COL_FG_DIM, font_size=10,
        ).pack(pady=(0, 2))

        _make_button(
            self.root, "Copy diagnostics...", lambda: self._on_copy_diagnostics(folder),
            bg=_COL_BTN_SUBTLE, fg=_COL_FG_DIM, font_size=10,
        ).pack(pady=(0, 4))

        tk.Label(
            self.root, text=f"White Lights Media · v{APP_VERSION}", fg=_COL_FG_DIM, bg=_COL_BG,
            font=("-apple-system", 10),
        ).pack(side="bottom", pady=14)

        _import_server_app(folder)
        threading.Thread(target=self._run_server, daemon=True).start()
        self._update_stats()

    def _update_stats(self):
        try:
            stats = server_app._get_system_stats()
            cpu = stats['cpu_percent']
            prefix = "Generating cache…  ·  " if stats.get('generating_cache') else ""
            self.stats_var.set(
                f"{prefix}CPU {cpu:.0f}%  ·  "
                f"↑ {stats['upload_mbps']:.1f}  ↓ {stats['download_mbps']:.1f} Mbps"
            )
            self.stats_label.configure(fg=_COL_RED if cpu >= 85 else _COL_YELLOW if cpu >= 60 else _COL_FG_DIM)
        except Exception:
            pass
        if not self._stopped:
            self.root.after(2000, self._update_stats)

    def _on_copy_diagnostics(self, folder):
        text = _gather_diagnostics(folder)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Diagnostic info copied — paste it into an email to White Lights Media.")

    def _on_change_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder for White Lights Media")
        if folder:
            _save_config({'photos_dir': folder})
            self._stopped = True
            _restart_app()

    def _on_restart_service(self):
        """Re-detects the Tailscale IP and rebinds from scratch. Our server
        only checks the Tailscale IP once at startup and binds to it for
        good — if that IP ever changes underneath it (network switch,
        Tailscale hiccup), status would stay stuck without this. Doesn't
        touch Tailscale itself, just our own connection to it."""
        proceed = messagebox.askyesno(
            "Restart sorting service?",
            "This briefly disconnects White Lights Media while the service "
            "restarts. Use this if the status has been stuck on \"Not "
            "connected\" for a while.\n\nRestart now?",
        )
        if proceed:
            self._stopped = True
            _restart_app()

    def _on_delete_cache(self):
        proceed = messagebox.askyesno(
            "Delete cache?",
            "Only delete the cache once White Lights Media has finished "
            "working on this competition — deleting it early may slow down "
            "their workflow while they're still sorting your photos.\n\n"
            "Delete cache now?",
            icon='warning',
        )
        if not proceed:
            return
        try:
            count = server_app._wipe_all_cache()
            messagebox.showinfo("Cache deleted", f"Cache cleared ({count} thumbnails removed).")
        except Exception:
            messagebox.showerror("Error", "Could not delete the cache. Please contact White Lights Media.")

    def _set_status(self, state_key):
        state = STATUS_STATES[state_key]

        def _update():
            self.status_var.set(state['text'])
            self._status_dot.itemconfig(self._status_dot_oval, fill=state['color'])
        self.root.after(0, _update)

    def _run_server(self):
        # Outer loop re-fetches Tailscale IP/hostname/cert on every bind
        # failure rather than retrying the same address — Tailscale can
        # stop/restart with a different (or the same, briefly-stale) address
        # mid-session, and _get_tailscale_https_info() itself blocks
        # correctly on "not really connected" or "cert not available yet"
        # now. This runs indefinitely rather than giving up, since Tailscale
        # being down could last anywhere from a second (the old-process
        # handoff on a folder change) to however long the client takes to
        # notice and reconnect it, or to enable HTTPS Certificates.
        port = int(os.environ.get('PORT', 5000))
        while not self._stopped:
            try:
                self._set_status('waiting')
                bind_host, hostname, certfile, keyfile = server_app._get_tailscale_https_info()
                if self._stopped:
                    return
                self._set_status('ready')
                server_app.app.run(
                    host=bind_host, port=port, threaded=True, use_reloader=False,
                    ssl_context=(certfile, keyfile),
                )
                return  # app.run() only returns on a real shutdown, not expected here
            except OSError:
                if self._stopped:
                    return
                time.sleep(2)
            except Exception:
                break
        if not self._stopped:
            self._set_status('crashed')

    def _on_signal(self, signum, frame):
        self._stopped = True
        os._exit(0)

    def _on_close(self):
        self._stopped = True
        self.root.destroy()
        os._exit(0)  # Flask's dev server has no clean in-thread stop call; exiting the process is the only reliable way to take it down.

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    ServiceShell().run()
