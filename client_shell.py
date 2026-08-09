#!/usr/bin/env python3
"""Client-facing launcher for the WLM sorting service.

Shows a minimal status window and runs the Flask server (app.py) on a
background thread, in-process. The client never sees a URL, login screen,
or the sorting UI here — only WLM's team, connecting separately over
Tailscale with the shared password, does.

Runs Flask in-thread rather than as a subprocess so this can be frozen into
a single PyInstaller executable: a frozen binary has no separate `python`
interpreter or app.py file on disk to subprocess out to.
"""
import atexit
import os
import signal
import threading
import tkinter as tk
from pathlib import Path

# Must be set before `app` is imported — PHOTOS_DIR is read at module load
# time. Bare-metal (non-Docker) runs need a real default; Docker deploys set
# PHOTOS_DIR themselves via docker-compose, so this only fills the gap for a
# plain double-clicked client build.
os.environ.setdefault('PHOTOS_DIR', str(Path.home()))

import app as server_app  # noqa: E402  (must follow the PHOTOS_DIR default above)

STATUS_STARTING = "Starting sorting service..."
STATUS_WAITING_TAILSCALE = "Waiting for Tailscale connection...\n(make sure you're signed in to Tailscale)"
STATUS_READY = "Sorting service ready\nWaiting for connection"
STATUS_CRASHED = "Sorting service stopped unexpectedly\nPlease contact White Lights Media"


class ServiceShell:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("WLM Sorting Service")
        self.root.geometry("360x180")
        self.root.resizable(False, False)
        self.root.configure(bg="#181818")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        dot = tk.Canvas(self.root, width=16, height=16, bg="#181818", highlightthickness=0)
        dot.create_oval(2, 2, 14, 14, fill="#d4a017", outline="")
        dot.pack(pady=(28, 10))

        self.status_var = tk.StringVar(value=STATUS_STARTING)
        tk.Label(
            self.root, textvariable=self.status_var, fg="#e0e0e0", bg="#181818",
            font=("-apple-system", 13), wraplength=320, justify="center",
        ).pack(pady=4, expand=True)

        tk.Label(
            self.root, text="White Lights Media", fg="#707070", bg="#181818",
            font=("-apple-system", 10),
        ).pack(side="bottom", pady=14)

        self._stopped = False

        # WM_DELETE_WINDOW only fires on a clean window close. A force-quit
        # or `kill` sends SIGTERM/SIGINT straight past Tkinter — harmless now
        # that Flask runs on a daemon thread in this same process (it dies
        # with the process either way), but we still exit cleanly rather
        # than leaving Tkinter in a half-torn-down state.
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

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
            server_app.app.run(host=bind_host, port=port, threaded=True, use_reloader=False)
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
        threading.Thread(target=self._run_server, daemon=True).start()
        self.root.mainloop()


if __name__ == '__main__':
    ServiceShell().run()
