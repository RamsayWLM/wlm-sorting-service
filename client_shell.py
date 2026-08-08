#!/usr/bin/env python3
"""Client-facing launcher for the WLM sorting service.

Shows a minimal status window and runs the Flask server (app.py) as a
background process. The client never sees a URL, login screen, or the
sorting UI here — only WLM's team, connecting separately over Tailscale
with the shared password, does.
"""
import atexit
import os
import signal
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
APP_PY = APP_DIR / 'app.py'

STATUS_STARTING = "Starting sorting service..."
STATUS_WAITING_TAILSCALE = "Waiting for Tailscale connection...\n(make sure you're signed in to Tailscale)"
STATUS_READY = "Sorting service ready\nWaiting for connection"
STATUS_STOPPED = "Sorting service stopped"
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

        self.proc = None
        self._stopped = False

        # WM_DELETE_WINDOW only fires on a clean window close. A force-quit,
        # crash, or `kill` sends SIGTERM/SIGINT straight past Tkinter, which
        # would otherwise leave the Flask server orphaned and still running
        # on the client's machine indefinitely.
        atexit.register(self._kill_child)
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

    def _set_status(self, text):
        self.root.after(0, lambda: self.status_var.set(text))

    def _run_server(self):
        env = os.environ.copy()
        # Bare-metal (non-Docker) run needs a real default — Docker deploys set
        # PHOTOS_DIR themselves via docker-compose, so this only fills the gap
        # for a plain double-clicked client build.
        env.setdefault('PHOTOS_DIR', str(Path.home()))

        try:
            self.proc = subprocess.Popen(
                [sys.executable, '-u', str(APP_PY)],
                cwd=str(APP_DIR),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError:
            self._set_status(STATUS_CRASHED)
            return

        self._set_status(STATUS_WAITING_TAILSCALE)
        for line in self.proc.stdout:
            if 'Binding to Tailscale IP' in line:
                self._set_status(STATUS_READY)

        if not self._stopped:
            self._set_status(STATUS_CRASHED)

    def _kill_child(self):
        self._stopped = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    def _on_signal(self, signum, frame):
        self._kill_child()
        os._exit(0)

    def _on_close(self):
        self._kill_child()
        self.root.destroy()

    def run(self):
        threading.Thread(target=self._run_server, daemon=True).start()
        self.root.mainloop()


if __name__ == '__main__':
    ServiceShell().run()
