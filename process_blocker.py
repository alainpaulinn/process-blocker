# -*- coding: utf-8 -*-
r"""
Windows 11 Process Blocker (Tray App)
- Blocks processes whose name/cmdline matches a configurable pattern (default: "ManageEngine")
- Real-time (WMI) or polling detection
- System tray menu for controls
- Persistent config in %APPDATA%\ProcessBlocker\config.json
- Rotating audit logs in %LOCALAPPDATA%\ProcessBlocker\logs\app.log
- Optional "Start with Windows" via HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Tested on Python 3.10+ on Windows 11.

Dependencies:
  pip install psutil pystray pillow wmi pywin32

Packaging (recommended):
  pyinstaller -y --noconsole --onefile --name ProcessBlocker process_blocker.py
"""

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
import re
import time
import threading
from datetime import datetime
import ctypes
import traceback
import subprocess

import psutil

# --- Optional/GUI deps (import lazily later where possible)
# pystray needs a PIL.Image for the tray icon
from PIL import Image, ImageDraw
import pystray

# WMI real-time events (Win32_ProcessStartTrace / watch_for creation)
try:
    import wmi  # type: ignore
    HAVE_WMI = True
except Exception:
    HAVE_WMI = False


APP_NAME = "ProcessBlocker"
DEFAULT_PATTERN = "ManageEngine"
APPDATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
LOCALAPPDATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_NAME)
CONFIG_PATH = os.path.join(APPDATA_DIR, "config.json")
LOG_DIR = os.path.join(LOCALAPPDATA_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "app.log")
RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------
def ensure_dirs():
    os.makedirs(APPDATA_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def get_executable_for_startup() -> str:
    # When packaged with PyInstaller --onefile, sys.frozen is set and sys.executable is the exe
    if getattr(sys, "frozen", False):
        return sys.executable
    # If running as .py, use pythonw.exe to avoid a console window on login
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if os.path.exists(pythonw):
        return f'"{pythonw}" "{os.path.abspath(__file__)}"'
    else:
        return f'"{sys.executable}" "{os.path.abspath(__file__)}"'

def set_start_with_windows(enabled: bool):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, get_executable_for_startup())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass

def get_start_with_windows() -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            _ = winreg.QueryValueEx(key, APP_NAME)
            return True
    except FileNotFoundError:
        return False

def build_icon(size=64) -> Image.Image:
    # Simple shield-like circle with ban mark
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r = size // 2 - 2
    center = (size // 2, size // 2)
    d.ellipse([(center[0]-r, center[1]-r), (center[0]+r, center[1]+r)], outline=(0,0,0,255), width=2, fill=(255,255,255,255))
    # slash
    d.line([(size*0.25, size*0.75), (size*0.75, size*0.25)], fill=(0,0,0,255), width=6)
    return img

def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------------------------------------------------
# Configuration & Logging
# ---------------------------------------------------------------------
DEFAULT_CONFIG = {
    "enabled": True,
    "pattern": DEFAULT_PATTERN,          # substring or regex (see config["use_regex"])
    "use_regex": False,
    "mode": "realtime",                  # "realtime" or "polling"
    "poll_interval_sec": 3,              # used when mode == "polling"
    "start_with_windows": False,
    "log_level": "INFO",
    "kill_children": True,               # also try to kill child processes
}

class Config:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.data = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        with self.lock:
            if os.path.exists(self.path):
                try:
                    with open(self.path, "r", encoding="utf-8") as f:
                        disk = json.load(f)
                    # merge with defaults to add new keys over time
                    merged = DEFAULT_CONFIG.copy()
                    merged.update(disk if isinstance(disk, dict) else {})
                    self.data = merged
                except Exception:
                    # keep defaults if corrupt
                    self.data = DEFAULT_CONFIG.copy()
            else:
                self.save()

    def save(self):
        with self.lock:
            tmp = self.data.copy()
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(tmp, f, indent=2)

    # helper getters/setters
    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def set(self, key, value):
        with self.lock:
            self.data[key] = value
            self.save()

# Setup logging
def setup_logging(level: str):
    ensure_dirs()
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    fh = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(fh)
    # optional console while running as script
    if not getattr(sys, "frozen", False):
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(ch)
    return logger

# ---------------------------------------------------------------------
# Blocker Core
# ---------------------------------------------------------------------
class ProcessBlocker:
    def __init__(self, cfg: Config, logger: logging.Logger):
        self.cfg = cfg
        self.log = logger
        self.stop_event = threading.Event()
        self.threads = []
        self.regex_cache = None
        self._compile_pattern()

    def _compile_pattern(self):
        pat = self.cfg.get("pattern", DEFAULT_PATTERN)
        if self.cfg.get("use_regex", False):
            try:
                self.regex_cache = re.compile(pat, re.IGNORECASE)
            except re.error as e:
                self.log.error(f"Invalid regex '{pat}': {e}. Falling back to plain substring.")
                self.cfg.set("use_regex", False)
                self.regex_cache = None
        else:
            self.regex_cache = None

    def update_pattern(self, new_pattern: str, use_regex: bool):
        self.cfg.set("pattern", new_pattern.strip())
        self.cfg.set("use_regex", bool(use_regex))
        self._compile_pattern()
        self.log.info(f"Pattern updated: '{new_pattern}' (regex={use_regex})")

    def match_process(self, name: str, cmdline: str) -> bool:
        pat = self.cfg.get("pattern", DEFAULT_PATTERN)
        if not pat:
            return False
        hay = f"{name} {cmdline}".lower()
        if self.regex_cache:
            return bool(self.regex_cache.search(hay))
        return pat.lower() in hay

    def kill_process_tree(self, pid: int):
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        procs = [p]
        if self.cfg.get("kill_children", True):
            try:
                procs += p.children(recursive=True)
            except Exception:
                pass

        # Terminate then kill if still alive
        for proc in procs:
            try:
                info = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "exe": (proc.exe() if proc.is_running() else ""),
                    "cmdline": " ".join(proc.cmdline()) if proc.is_running() else "",
                    "username": (proc.username() if proc.is_running() else ""),
                }
                self.log.info(f"TERMINATE request | pid={info['pid']} name={info['name']} user={info['username']} exe={info['exe']} cmd='{info['cmdline']}'")
                proc.terminate()
            except psutil.AccessDenied:
                self.log.warning(f"AccessDenied terminating pid={proc.pid}. Try kill() (requires admin).")
                try:
                    proc.kill()
                    self.log.info(f"KILLED pid={proc.pid}")
                except Exception as e:
                    self.log.error(f"Failed to kill pid={proc.pid}: {e}")
            except Exception as e:
                self.log.error(f"Error terminating pid={proc.pid}: {e}")

        # Wait briefly then force kill survivors
        gone, alive = psutil.wait_procs(procs, timeout=3)
        for proc in alive:
            try:
                proc.kill()
                self.log.info(f"Force KILLED pid={proc.pid}")
            except Exception as e:
                self.log.error(f"Failed force kill pid={proc.pid}: {e}")

    def scan_existing(self):
        # On startup or when toggled, clean up any already-running matches
        count = 0
        for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                name = p.info.get("name") or ""
                cmd = " ".join(p.info.get("cmdline") or [])
                if self.match_process(name, cmd):
                    count += 1
                    self.log.info(f"Match existing | pid={p.pid} name={name} cmd='{cmd}'")
                    self.kill_process_tree(p.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if count:
            self.log.info(f"Existing matches terminated: {count}")

    # ----------------- Real-time watcher (WMI)
    def _wmi_watch_loop(self):
        if not HAVE_WMI:
            self.log.error("WMI module not available. Switch to polling or install 'wmi'.")
            return
        # Initialize COM for this background thread (required by WMI/pywin32)
        try:
            import pythoncom  # type: ignore
        except Exception as e:
            self.log.error(f"pythoncom not available. Install 'pywin32'. Error: {e}")
            return
        pythoncom.CoInitialize()
        try:
            try:
                c = wmi.WMI()
                watcher = c.Win32_Process.watch_for("creation")
                self.log.info("WMI real-time watcher started.")
                while not self.stop_event.is_set():
                    try:
                        evt = watcher(timeout_ms=1000)  # 1s timeout to allow stop checks
                        if evt is None:
                            continue
                        pid = int(evt.ProcessId)
                        name = (evt.Caption or evt.Name or "").strip()
                        cmdline = (evt.CommandLine or "").strip()
                        if self.match_process(name, cmdline) and self.cfg.get("enabled", True):
                            self.log.info(f"Match create | pid={pid} name={name} cmd='{cmdline}'")
                            self.kill_process_tree(pid)
                    except wmi.x_wmi_timed_out:
                        continue
                    except Exception as e:
                        self.log.error(f"WMI watch error: {e}")
                        time.sleep(1)
            except Exception as e:
                self.log.error(f"Failed to start WMI watcher: {e}\n{traceback.format_exc()}")
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    # ----------------- Polling watcher
    def _poll_loop(self):
        self.log.info("Polling watcher started.")
        seen = set()  # optional: reduce duplicate logs
        while not self.stop_event.is_set():
            interval = max(1, int(self.cfg.get("poll_interval_sec", 3)))
            enabled = self.cfg.get("enabled", True)
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                    try:
                        name = p.info.get("name") or ""
                        cmd = " ".join(p.info.get("cmdline") or [])
                        if enabled and self.match_process(name, cmd):
                            key = (p.pid, name)
                            if key not in seen:
                                self.log.info(f"Match poll | pid={p.pid} name={name} cmd='{cmd}'")
                                seen.add(key)
                            self.kill_process_tree(p.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                self.log.error(f"Polling error: {e}")
            for _ in range(interval * 10):
                if self.stop_event.is_set():
                    break
                time.sleep(0.1)

    def start(self):
        # initial sweep
        if self.cfg.get("enabled", True):
            self.scan_existing()

        mode = self.cfg.get("mode", "realtime").lower()
        if mode == "realtime" and HAVE_WMI:
            t = threading.Thread(target=self._wmi_watch_loop, name="WMIWatch", daemon=True)
            t.start()
            self.threads.append(t)
        else:
            t = threading.Thread(target=self._poll_loop, name="PollWatch", daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=2)

# ---------------------------------------------------------------------
# Tray UI
# ---------------------------------------------------------------------
class TrayApp:
    def __init__(self, blocker: ProcessBlocker, cfg: Config, logger: logging.Logger):
        self.blocker = blocker
        self.cfg = cfg
        self.log = logger
        self.icon = pystray.Icon(APP_NAME, build_icon(), title=APP_NAME, menu=self._build_menu())

    def _build_menu(self):
        def _toggle_enabled(icon, item):
            new = not self.cfg.get("enabled", True)
            self.cfg.set("enabled", new)
            state = "ENABLED" if new else "DISABLED"
            self.log.info(f"Protection {state}")
            if new:
                self.blocker.scan_existing()
            self.icon.menu = self._build_menu()

        def _toggle_startup(icon, item):
            new = not self.cfg.get("start_with_windows", False)
            try:
                set_start_with_windows(new)
                self.cfg.set("start_with_windows", new)
                self.log.info(f"Startup set to {new}")
            except Exception as e:
                self.log.error(f"Failed to set startup: {e}")
            self.icon.menu = self._build_menu()

        def _set_mode_realtime(icon, item):
            self.cfg.set("mode", "realtime")
            self.log.info("Mode set to REAL-TIME (WMI)")
            # Restart watcher threads
            self.blocker.stop()
            self.blocker.stop_event.clear()
            self.blocker.threads = []
            self.blocker.start()
            self.icon.menu = self._build_menu()

        def _set_mode_polling(icon, item):
            self.cfg.set("mode", "polling")
            self.log.info("Mode set to POLLING")
            self.blocker.stop()
            self.blocker.stop_event.clear()
            self.blocker.threads = []
            self.blocker.start()
            self.icon.menu = self._build_menu()

        def _set_freq(sec: int):
            def inner(icon, item):
                self.cfg.set("poll_interval_sec", sec)
                self.log.info(f"Polling interval set to {sec}s")
                if self.cfg.get("mode") == "polling":
                    self.blocker.stop()
                    self.blocker.stop_event.clear()
                    self.blocker.threads = []
                    self.blocker.start()
                self.icon.menu = self._build_menu()
            return inner

        def _edit_pattern(icon, item):
            # Simple console prompt (works even when packaged without console? Not ideal.)
            # Better: use a tiny Tk dialog.
            try:
                import tkinter as tk
                from tkinter import simpledialog, messagebox

                root = tk.Tk()
                root.withdraw()
                current = self.cfg.get("pattern", DEFAULT_PATTERN)
                new_pat = simpledialog.askstring(APP_NAME, f"Enter process match pattern:\n(substring or regex)", initialvalue=current)
                if new_pat is None:
                    return
                use_regex = messagebox.askyesno(APP_NAME, "Use REGEX matching?\n(Yes = regex, No = simple substring)")
                self.blocker.update_pattern(new_pat, use_regex)
                messagebox.showinfo(APP_NAME, f"Pattern saved:\n{new_pat}\nregex={use_regex}")
            except Exception as e:
                self.log.error(f"Pattern edit failed: {e}")

        def _open_logs(icon, item):
            try:
                os.startfile(LOG_DIR)
            except Exception as e:
                self.log.error(f"Open logs failed: {e}")

        def _quit(icon, item):
            self.icon.visible = False
            self.icon.stop()

        # Checked states
        enabled_checked = self.cfg.get("enabled", True)
        startup_checked = self.cfg.get("start_with_windows", False)
        mode = self.cfg.get("mode", "realtime").lower()
        poll_int = int(self.cfg.get("poll_interval_sec", 3))

        return pystray.Menu(
            pystray.MenuItem(f"Protection: {'On' if enabled_checked else 'Off'}", _toggle_enabled, checked=lambda item: enabled_checked),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Mode",
                pystray.Menu(
                    pystray.MenuItem("Real-time (WMI)", _set_mode_realtime, checked=lambda item: mode == "realtime"),
                    pystray.MenuItem("Polling", _set_mode_polling, checked=lambda item: mode == "polling"),
                )
            ),
            pystray.MenuItem(
                f"Polling interval ({poll_int}s)",
                pystray.Menu(
                    pystray.MenuItem("1s", _set_freq(1), checked=lambda item: poll_int == 1),
                    pystray.MenuItem("3s", _set_freq(3), checked=lambda item: poll_int == 3),
                    pystray.MenuItem("5s", _set_freq(5), checked=lambda item: poll_int == 5),
                    pystray.MenuItem("10s", _set_freq(10), checked=lambda item: poll_int == 10),
                    pystray.MenuItem("30s", _set_freq(30), checked=lambda item: poll_int == 30),
                )
            ),
            pystray.MenuItem("Edit pattern…", _edit_pattern),
            pystray.MenuItem("Start with Windows", _toggle_startup, checked=lambda item: startup_checked),
            pystray.MenuItem("Open log folder", _open_logs),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", _quit),
        )

    def run(self):
        self.icon.run()

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    ensure_dirs()
    cfg = Config(CONFIG_PATH)
    logger = setup_logging(cfg.get("log_level", "INFO"))

    logger.info(f"{APP_NAME} starting. Admin={is_admin()}  Frozen={getattr(sys, 'frozen', False)}  WMI={'yes' if HAVE_WMI else 'no'}")
    # Ensure registry reflects current config
    try:
        if cfg.get("start_with_windows", False) != get_start_with_windows():
            set_start_with_windows(cfg.get("start_with_windows", False))
    except Exception as e:
        logger.error(f"Startup sync failed: {e}")

    blocker = ProcessBlocker(cfg, logger)
    blocker.start()

    # Tray UI
    try:
        app = TrayApp(blocker, cfg, logger)
        app.run()
    finally:
        blocker.stop()
        logger.info(f"{APP_NAME} exited.")

if __name__ == "__main__":
    if os.name != "nt":
        print("This application is intended for Windows.")
        sys.exit(1)
    main()
