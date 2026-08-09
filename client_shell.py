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
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog

from PIL import Image, ImageTk


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
    "3. Click the Tailscale icon in your menu bar, choose \"Share...\", "
    "select this computer, and share it with:\n"
    f"        {WLM_TAILSCALE_SHARE_EMAIL}\n\n"
    "4. Choose the folder below for White Lights Media to work in, then "
    "click Done."
)

STATUS_STARTING = "Starting sorting service..."
STATUS_WAITING_TAILSCALE = "Waiting for Tailscale connection...\n(make sure you're signed in to Tailscale)"
STATUS_READY = "Sorting service ready\nWaiting for connection"
STATUS_CRASHED = "Sorting service stopped unexpectedly\nPlease contact White Lights Media"

_COL_BG = "#181818"
_COL_FG = "#e0e0e0"
_COL_FG_DIM = "#707070"
_COL_ACCENT = "#d4a017"
_COL_BTN = "#404040"
_COL_BTN_FG = "#ffffff"
_COL_BTN_DISABLED = "#2a2a2a"


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


def _import_server_app(photos_dir: str):
    os.environ['PHOTOS_DIR'] = photos_dir
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
        self.root.geometry("440x540")
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
        ).pack(pady=(0, 20), **pad)

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
        self._begin_serving(folder)

    # ── Running status screen ────────────────────────────────────────────

    def _begin_serving(self, folder):
        self._clear()
        self.root.geometry("360x240")

        logo = self._logo_image(180)
        if logo:
            tk.Label(self.root, image=logo, bg=_COL_BG).pack(pady=(28, 12))
        else:
            dot = tk.Canvas(self.root, width=16, height=16, bg=_COL_BG, highlightthickness=0)
            dot.create_oval(2, 2, 14, 14, fill=_COL_ACCENT, outline="")
            dot.pack(pady=(24, 8))

        self.status_var = tk.StringVar(value=STATUS_STARTING)
        tk.Label(
            self.root, textvariable=self.status_var, fg=_COL_FG, bg=_COL_BG,
            font=("-apple-system", 13), wraplength=320, justify="center",
        ).pack(pady=4, expand=True)

        _make_button(
            self.root, "Change folder...", self._on_change_folder,
            bg=_COL_BG, fg=_COL_FG_DIM, font_size=10,
        ).pack(pady=(0, 4))

        tk.Label(
            self.root, text="White Lights Media", fg=_COL_FG_DIM, bg=_COL_BG,
            font=("-apple-system", 10),
        ).pack(side="bottom", pady=14)

        _import_server_app(folder)
        threading.Thread(target=self._run_server, daemon=True).start()

    def _on_change_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder for White Lights Media")
        if folder:
            _save_config({'photos_dir': folder})
            self._stopped = True
            _restart_app()

    def _set_status(self, text):
        self.root.after(0, lambda: self.status_var.set(text))

    def _run_server(self):
        try:
            self._set_status(STATUS_WAITING_TAILSCALE)
            bind_host = server_app._get_tailscale_ip()
            if self._stopped:
                return
            self._set_status(STATUS_READY)
            port = int(os.environ.get('PORT', 5000))
            # A folder change spawns a new process before the old one has
            # necessarily released the port yet (see _restart_app) — retry
            # the bind for a few seconds rather than surfacing that brief
            # overlap as a crash.
            for attempt in range(10):
                try:
                    server_app.app.run(host=bind_host, port=port, threaded=True, use_reloader=False)
                    break
                except OSError:
                    if attempt == 9 or self._stopped:
                        raise
                    time.sleep(1)
        except Exception:
            pass
        if not self._stopped:
            self._set_status(STATUS_CRASHED)

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
