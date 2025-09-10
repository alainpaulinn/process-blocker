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

def get_asset_path(relative_path: str) -> str:
    """Return absolute path to an asset.
    Works both when running from source and when packaged by PyInstaller.
    """
    try:
        # PyInstaller extracts to a temp folder and sets _MEIPASS
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def load_app_icon_image(size: int = 64, rounded: bool = True) -> Image.Image:
    """Load the app icon from assets and optionally apply a circular alpha mask."""
    img = None
    try:
        logo_path = get_asset_path(os.path.join("assets", "logo.png"))
        if os.path.exists(logo_path):
            img = Image.open(logo_path).convert("RGBA")
    except Exception:
        img = None
    if img is None:
        # fallback simple mark
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        r = size // 2 - 2
        center = (size // 2, size // 2)
        d.ellipse([(center[0]-r, center[1]-r), (center[0]+r, center[1]+r)], outline=(0,0,0,255), width=2, fill=(255,255,255,255))
        d.line([(size*0.25, size*0.75), (size*0.75, size*0.25)], fill=(0,0,0,255), width=6)
    if img.size != (size, size):
        try:
            img = img.resize((size, size), Image.LANCZOS)
        except Exception:
            img = img.resize((size, size))
    if rounded:
        try:
            mask = Image.new("L", (size, size), 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0, 0, size-1, size-1), fill=255)
            img = img.copy()
            img.putalpha(mask)
        except Exception:
            pass
    return img

def set_tk_window_icon(win):
    """Set Tk window icon to app icon and retain reference to avoid GC."""
    try:
        from PIL import ImageTk  # type: ignore
        img = load_app_icon_image(size=256, rounded=True)
        win._pb_icon_imgtk = ImageTk.PhotoImage(img)
        win.iconphoto(True, win._pb_icon_imgtk)
    except Exception:
        pass

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def enable_debug_privilege():
    """Enable SeDebugPrivilege for the current process when running as admin."""
    try:
        SE_DEBUG_NAME = "SeDebugPrivilege"
        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x8
        SE_PRIVILEGE_ENABLED = 0x2

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", ctypes.c_uint32)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.c_uint32), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        token = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
            return
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
    except Exception:
        pass

def restart_as_admin() -> bool:
    """Attempt to restart the current program with elevated rights.
    Returns True if elevation was initiated, False otherwise.
    """
    try:
        # Build command
        if getattr(sys, "frozen", False):
            executable = sys.executable
            params = ""
        else:
            executable = sys.executable
            script_path = os.path.abspath(__file__)
            args = " ".join(f'"{a}"' for a in sys.argv[1:])
            params = f'"{script_path}" {args}'.strip()

        # ShellExecuteW returns >32 on success
        ShellExecuteW = ctypes.windll.shell32.ShellExecuteW
        ret = ShellExecuteW(None, "runas", executable, params, None, 1)
        return ret > 32
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
    return load_app_icon_image(size=size, rounded=True)

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
    # New configuration options
    "rules": [],                         # list of {type: name|path|cmdline|regex, pattern: str, case_sensitive?: bool}
    "auto_elevate_on_access_denied": True,
}

class Config:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.data = DEFAULT_CONFIG.copy()
        self._mtime = 0.0
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
                    # Migrate legacy single-pattern to multi-rules if rules empty
                    rules = merged.get("rules")
                    if not rules:
                        legacy_pat = (merged.get("pattern") or "").strip()
                        legacy_regex = bool(merged.get("use_regex", False))
                        if legacy_pat:
                            if legacy_regex:
                                merged["rules"] = [{"type": "regex", "pattern": legacy_pat, "case_sensitive": False}]
                            else:
                                merged["rules"] = [
                                    {"type": "name", "pattern": legacy_pat, "case_sensitive": False},
                                    {"type": "path", "pattern": legacy_pat, "case_sensitive": False},
                                    {"type": "cmdline", "pattern": legacy_pat, "case_sensitive": False},
                                ]
                    self.data = merged
                    try:
                        self._mtime = os.path.getmtime(self.path)
                    except Exception:
                        pass
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
            try:
                self._mtime = os.path.getmtime(self.path)
            except Exception:
                pass

    def load_if_changed(self):
        try:
            if os.path.exists(self.path):
                mtime = os.path.getmtime(self.path)
                if mtime > (self._mtime or 0):
                    self.load()
        except Exception:
            pass

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
        self._elevation_attempted = False

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

    def match_process(self, name: str, exe_path: str, cmdline: str) -> bool:
        """Return True if the process matches current blocking rules.
        Supports legacy single pattern or new multi-rule config.
        """
        # Prefer multi-rules if present
        rules = self.cfg.get("rules", []) or []
        if rules:
            exe_norm = exe_path or ""
            name_norm = name or os.path.basename(exe_norm)
            cmd_norm = cmdline or ""
            for rule in rules:
                try:
                    r_type = (rule.get("type") or "").strip().lower()
                    pattern = str(rule.get("pattern") or "")
                    if not pattern:
                        continue
                    case_sensitive = bool(rule.get("case_sensitive", False))
                    if not case_sensitive:
                        pattern_cmp = pattern.lower()
                        name_cmp = (name_norm or "").lower()
                        exe_cmp = (exe_norm or "").lower()
                        cmd_cmp = (cmd_norm or "").lower()
                    else:
                        pattern_cmp = pattern
                        name_cmp = name_norm or ""
                        exe_cmp = exe_norm or ""
                        cmd_cmp = cmd_norm or ""

                    if r_type == "name":
                        # Match against provided name or basename of exe
                        if pattern_cmp in name_cmp or pattern_cmp in os.path.basename(exe_cmp):
                            return True
                    elif r_type == "path":
                        if pattern_cmp in exe_cmp:
                            return True
                    elif r_type == "cmdline":
                        if pattern_cmp in cmd_cmp:
                            return True
                    elif r_type == "regex":
                        flags = 0 if case_sensitive else re.IGNORECASE
                        try:
                            rx = re.compile(pattern, flags)
                            combined = f"{name_norm} {exe_norm} {cmd_norm}"
                            if rx.search(combined):
                                return True
                        except re.error as _:
                            # Skip invalid regex silently; user can fix in UI
                            continue
                except Exception:
                    continue
            return False

        # Legacy single-pattern behavior
        pat = self.cfg.get("pattern", DEFAULT_PATTERN)
        if not pat:
            return False
        hay = f"{name} {exe_path} {cmdline}".lower()
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
                # Try elevating if configured
                if not is_admin() and self.cfg.get("auto_elevate_on_access_denied", True) and not self._elevation_attempted:
                    self._elevation_attempted = True
                    self.log.warning("Attempting to restart as Administrator due to AccessDenied…")
                    if restart_as_admin():
                        # Exit current instance; elevated instance will continue
                        os._exit(0)
                    else:
                        self.log.error("Elevation failed or was cancelled.")
                else:
                    # As a last resort, try taskkill /F if admin
                    if is_admin():
                        try:
                            subprocess.run(["taskkill", "/PID", str(proc.pid), "/F", "/T"], check=True, capture_output=True)
                            self.log.info(f"TASKKILL /F success pid={proc.pid}")
                        except Exception as e2:
                            self.log.error(f"TASKKILL /F failed pid={proc.pid}: {e2}")
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
        for p in psutil.process_iter(attrs=["pid", "name", "cmdline", "exe"]):
            try:
                name = p.info.get("name") or ""
                exe_path = p.info.get("exe") or ""
                cmd = " ".join(p.info.get("cmdline") or [])
                if self.match_process(name, exe_path, cmd):
                    count += 1
                    self.log.info(f"Match existing | pid={p.pid} name={name} exe='{exe_path}' cmd='{cmd}'")
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
                    # Hot-reload config/rules
                    self.cfg.load_if_changed()
                    try:
                        evt = watcher(timeout_ms=1000)  # 1s timeout to allow stop checks
                        if evt is None:
                            continue
                        pid = int(evt.ProcessId)
                        # Start with event-provided values
                        name = (evt.Caption or evt.Name or "").strip()
                        cmdline_evt = (evt.CommandLine or "").strip()
                        exe_path = ""
                        cmdline = cmdline_evt
                        # Use psutil to get reliable exe and cmdline
                        try:
                            p = psutil.Process(pid)
                            try:
                                name = p.name() or name
                            except Exception:
                                pass
                            try:
                                exe_path = p.exe() or ""
                            except Exception:
                                exe_path = ""
                            try:
                                cmdline = " ".join(p.cmdline())
                            except Exception:
                                cmdline = cmdline_evt
                        except Exception:
                            # process may have already exited
                            pass
                        if self.match_process(name, exe_path, cmdline) and self.cfg.get("enabled", True):
                            self.log.info(f"Match create | pid={pid} name={name} exe='{exe_path}' cmd='{cmdline}'")
                            self.kill_process_tree(pid)
                    except wmi.x_wmi_timed_out:
                        continue
                    except Exception as e:
                        # Ignore transient errors when process exits between event and inspection
                        if isinstance(e, psutil.NoSuchProcess):
                            continue
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
            # Hot-reload config/rules
            self.cfg.load_if_changed()
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "cmdline", "exe"]):
                    try:
                        name = p.info.get("name") or ""
                        exe = p.info.get("exe") or ""
                        cmd = " ".join(p.info.get("cmdline") or [])
                        if enabled and self.match_process(name, exe, cmd):
                            key = (p.pid, name)
                            if key not in seen:
                                self.log.info(f"Match poll | pid={p.pid} name={name} exe='{exe}' cmd='{cmd}'")
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

        def _edit_rules(icon, item):
            # Launch a separate process that runs the Tk editor in the main thread
            try:
                args = [sys.executable, os.path.abspath(__file__), "--rules-editor"]
                subprocess.Popen(args, creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
            except Exception as e:
                self.log.error(f"Rules editor launch failed: {e}")

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
            pystray.MenuItem("Block rules…", _edit_rules),
            pystray.MenuItem("Restart as Administrator", lambda icon, item: self._restart_admin()),
            pystray.MenuItem("Start with Windows", _toggle_startup, checked=lambda item: startup_checked),
            pystray.MenuItem("Open log folder", _open_logs),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", _quit),
        )

    def run(self):
        self.icon.run()

    def _restart_admin(self):
        if is_admin():
            self.log.info("Already running as Administrator.")
            return
        self.log.info("Restarting as Administrator…")
        if restart_as_admin():
            # terminate current to allow elevated instance to take over
            os._exit(0)
        else:
            self.log.error("Elevation failed or cancelled.")

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    ensure_dirs()
    cfg = Config(CONFIG_PATH)
    logger = setup_logging(cfg.get("log_level", "INFO"))

    # Special mode: run Rules Editor in standalone process (Tk must be in main thread)
    if len(sys.argv) > 1 and sys.argv[1] == "--rules-editor":
        try:
            import tkinter as tk
            from tkinter import ttk

            root = tk.Tk()
            root.title(f"{APP_NAME} - Block Rules")
            root.geometry("900x520")
            root.minsize(760, 400)
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            set_tk_window_icon(root)

            frame = ttk.Frame(root, padding=10)
            frame.grid(sticky="nsew")
            frame.columnconfigure(0, weight=1)
            frame.rowconfigure(1, weight=1)

            # Toolbar
            toolbar = ttk.Frame(frame)
            toolbar.grid(row=0, column=0, sticky="ew", pady=(0,8))
            ttk.Label(toolbar, text="Add rule:").pack(side=tk.LEFT)
            type_var = tk.StringVar(value="name")
            type_cb = ttk.Combobox(toolbar, textvariable=type_var, values=["name","path","cmdline","regex"], width=10, state="readonly")
            type_cb.pack(side=tk.LEFT, padx=(6,6))
            pattern_var = tk.StringVar()
            pattern_entry = ttk.Entry(toolbar, textvariable=pattern_var)
            pattern_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            cs_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(toolbar, text="Case sensitive", variable=cs_var).pack(side=tk.LEFT, padx=(8,8))
            def add_rule():
                pat = pattern_var.get().strip()
                if not pat:
                    return
                rules = cfg.get("rules", []) or []
                rules.append({"type": type_var.get(), "pattern": pat, "case_sensitive": bool(cs_var.get())})
                cfg.set("rules", rules)
                refresh()
                pattern_var.set("")
            ttk.Button(toolbar, text="Add", command=add_rule).pack(side=tk.LEFT)
            def seed_manageengine():
                defaults = [
                    {"type": "name", "pattern": "ManageEngine", "case_sensitive": False},
                    {"type": "path", "pattern": "ManageEngine", "case_sensitive": False},
                    {"type": "cmdline", "pattern": "ManageEngine", "case_sensitive": False},
                ]
                rules = cfg.get("rules", []) or []
                rules.extend(defaults)
                cfg.set("rules", rules)
                refresh()
            ttk.Button(toolbar, text="Seed", command=seed_manageengine).pack(side=tk.LEFT, padx=(8,0))

            # Tree
            columns = ("type","pattern","case")
            tv = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
            tv.heading("type", text="Type")
            tv.heading("pattern", text="Pattern")
            tv.heading("case", text="Case sensitive")
            tv.column("type", width=150, anchor=tk.W)
            tv.column("pattern", width=600, anchor=tk.W)
            tv.column("case", width=120, anchor=tk.W)
            tv.grid(row=1, column=0, sticky="nsew")
            vsb = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
            tv.configure(yscroll=vsb.set)
            vsb.grid(row=1, column=1, sticky="ns")

            # Actions
            btns = ttk.Frame(frame)
            btns.grid(row=2, column=0, sticky="e", pady=(8,0))
            def delete_selected():
                sel = tv.selection()
                if not sel:
                    return
                idx = int(sel[0])
                rules = cfg.get("rules", []) or []
                if 0 <= idx < len(rules):
                    del rules[idx]
                    cfg.set("rules", rules)
                    refresh()
            ttk.Button(btns, text="Delete", command=delete_selected).pack(side=tk.RIGHT)

            def refresh():
                tv.delete(*tv.get_children())
                rules = cfg.get("rules", []) or []
                for i, r in enumerate(rules):
                    tv.insert("", "end", iid=str(i), values=(r.get("type",""), r.get("pattern",""), "Yes" if r.get("case_sensitive") else "No"))

            refresh()
            root.mainloop()
        except Exception as e:
            logger.error(f"Rules editor crashed: {e}")
        return

    logger.info(f"{APP_NAME} starting. Admin={is_admin()}  Frozen={getattr(sys, 'frozen', False)}  WMI={'yes' if HAVE_WMI else 'no'}")
    if is_admin():
        enable_debug_privilege()
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
