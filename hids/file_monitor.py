"""
File sensor - Phase 5 HIDS browser credential monitor.

Watches the files infostealers (RedLine, Vidar, Lumma, Raccoon) go after and logs
who touched them to hids/logs/file_events_YYYY-MM-DD.csv.

Targets (every profile, auto-resolved for the current user):
  Chrome, Edge, Brave, Vivaldi, Opera, Opera GX
      Login Data, Login Data For Account, Cookies, Network/Cookies, Web Data, Local State
  Firefox   logins.json, key4.db, cookies.sqlite
  Bitcoin   wallet.dat

Modes:
  audit  (Administrator)  Windows object-access auditing. The sensor enables the
         "File System" audit subcategory, puts an audit rule (SACL) on each target
         and reads event 4663 from the Security log. Every open of a target for
         reading, writing or deleting is logged with the real PID and executable
         path of the process that did it. This is the only mode that sees reads,
         i.e. a stealer copying a cookie or password database.
  poll   (no Admin)  Detects CREATE / MODIFY / DELETE by watching file identity,
         size and mtime. Reads are invisible and the process is unknown, so these
         rows have no pid and cannot be sent to SOAR.

Audit rules stay on the files after the sensor stops (they only produce log entries).
Remove them with --remove-audit.

Run from repo root (Administrator PowerShell for audit mode):
  python -m hids.file_monitor [--mode auto|audit|poll] [--duration 0]
  python -m hids.file_monitor --list-targets
  python -m hids.file_monitor --remove-audit
"""
from __future__ import annotations

import argparse
import ctypes
import glob
import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from hids.process_monitor import DailyCsvWriter

POLL_INTERVAL = 1.0
RESCAN_EVERY = 60.0
DEDUP_WINDOW = 2.0
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_PREFIX = "file_events"

FIELDS = [
    "timestamp", "time_iso", "event_type",
    "pid", "create_time", "process_name", "exe_path", "parent_name",
    "file_path", "file_type", "browser", "accessor_is_owner",
    "access_mask", "source",
]

# GUID instead of the name so auditpol works on non-English Windows
FILE_SYSTEM_SUBCATEGORY = "{0CCE921D-69AE-11D9-BED3-505054503030}"
EVERYONE_SID = "S-1-1-0"
AUDIT_RIGHTS = "ReadData, WriteData, AppendData, Delete"
EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

READ_DATA = 0x1
WRITE_DATA = 0x2
APPEND_DATA = 0x4
DELETE = 0x10000


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Browser:
    exe: str
    install_marker: str  # lower-case path fragment of a genuine install


BROWSERS: Dict[str, Browser] = {
    "Chrome": Browser("chrome.exe", "\\google\\chrome\\application\\"),
    "Edge": Browser("msedge.exe", "\\microsoft\\edge\\application\\"),
    "Brave": Browser("brave.exe", "\\bravesoftware\\brave-browser\\application\\"),
    "Vivaldi": Browser("vivaldi.exe", "\\vivaldi\\application\\"),
    "Opera": Browser("opera.exe", "\\programs\\opera\\"),
    "Opera GX": Browser("opera.exe", "\\programs\\opera gx\\"),
    "Firefox": Browser("firefox.exe", "\\mozilla firefox\\"),
    "Bitcoin Core": Browser("bitcoin-qt.exe", "\\bitcoin\\"),
}

# (env var, user data folder, browser, profile folder globs relative to it)
CHROMIUM_ROOTS: List[Tuple[str, str, str, Tuple[str, ...]]] = [
    ("LOCALAPPDATA", "Google\\Chrome\\User Data", "Chrome", ("Default", "Profile *")),
    ("LOCALAPPDATA", "Microsoft\\Edge\\User Data", "Edge", ("Default", "Profile *")),
    ("LOCALAPPDATA", "BraveSoftware\\Brave-Browser\\User Data", "Brave", ("Default", "Profile *")),
    ("LOCALAPPDATA", "Vivaldi\\User Data", "Vivaldi", ("Default", "Profile *")),
    ("APPDATA", "Opera Software\\Opera Stable", "Opera", (".", "Default")),
    ("APPDATA", "Opera Software\\Opera GX Stable", "Opera GX", (".", "Default")),
]
CHROMIUM_PROFILE_FILES = ("Login Data", "Login Data For Account", "Cookies", "Network\\Cookies", "Web Data")
FIREFOX_FILES = ("logins.json", "key4.db", "cookies.sqlite")

# Same category names SOAR's host agent uses for risk weights and MITRE mapping
FILE_TYPES = {
    "login data": "Saved Passwords DB",
    "login data for account": "Saved Passwords DB",
    "cookies": "CookieDB",
    "web data": "Autofill & Credit Cards",
    "local state": "LocalState (Master Key)",
    "logins.json": "Firefox Saved Passwords",
    "key4.db": "Firefox Key Database",
    "cookies.sqlite": "Firefox CookieDB",
    "wallet.dat": "Crypto Wallet",
}


@dataclass(frozen=True)
class Target:
    path: str
    browser: str
    file_type: str


def file_type_for(path: str) -> str:
    return FILE_TYPES.get(os.path.basename(path).lower(), "")


def _candidate_targets(env: Mapping[str, str]) -> Iterable[Target]:
    for var, folder, browser, profile_globs in CHROMIUM_ROOTS:
        base = env.get(var)
        if not base:
            continue
        root = os.path.join(base, folder)
        yield Target(os.path.join(root, "Local State"), browser, file_type_for("Local State"))
        profiles = set()
        for pattern in profile_globs:
            profiles.update(glob.glob(os.path.join(root, pattern)))
        for profile in sorted(profiles):
            for name in CHROMIUM_PROFILE_FILES:
                path = os.path.normpath(os.path.join(profile, name))
                yield Target(path, browser, file_type_for(path))

    appdata = env.get("APPDATA")
    if appdata:
        for profile in sorted(glob.glob(os.path.join(appdata, "Mozilla", "Firefox", "Profiles", "*"))):
            for name in FIREFOX_FILES:
                yield Target(os.path.join(profile, name), "Firefox", file_type_for(name))
        bitcoin = os.path.join(appdata, "Bitcoin")
        for path in [os.path.join(bitcoin, "wallet.dat")] + sorted(
            glob.glob(os.path.join(bitcoin, "wallets", "*", "wallet.dat"))
        ):
            yield Target(path, "Bitcoin Core", file_type_for(path))


def resolve_targets(env: Optional[Mapping[str, str]] = None) -> List[Target]:
    """Every sensitive file that exists right now for the current user."""
    seen: Dict[str, Target] = {}
    for target in _candidate_targets(os.environ if env is None else env):
        key = target.path.lower()
        if key not in seen and os.path.isfile(target.path):
            seen[key] = target
    return list(seen.values())


def get_all_watch_paths() -> List[Path]:
    return [Path(t.path) for t in resolve_targets()]


SENSITIVE_GLOBS = [
    "**/<Chromium browser>/User Data/<profile>/Login Data",
    "**/<Chromium browser>/User Data/<profile>/Login Data For Account",
    "**/<Chromium browser>/User Data/<profile>/Cookies",
    "**/<Chromium browser>/User Data/<profile>/Network/Cookies",
    "**/<Chromium browser>/User Data/<profile>/Web Data",
    "**/<Chromium browser>/User Data/Local State",
    "**/Mozilla/Firefox/Profiles/*/logins.json",
    "**/Mozilla/Firefox/Profiles/*/key4.db",
    "**/Mozilla/Firefox/Profiles/*/cookies.sqlite",
    "**/Bitcoin/**/wallet.dat",
]


def describe_watch_targets() -> List[str]:
    return list(SENSITIVE_GLOBS)


def path_looks_sensitive(path: str | Path) -> bool:
    return bool(file_type_for(str(path)))


# ---------------------------------------------------------------------------
# Process attribution
# ---------------------------------------------------------------------------

def accessor_is_owner(exe_path: str, browser: str) -> Optional[bool]:
    """True only for the browser's own executable in its real install folder."""
    owner = BROWSERS.get(browser)
    if not exe_path or owner is None:
        return None
    lower = exe_path.lower()
    return os.path.basename(lower) == owner.exe and owner.install_marker in lower


def describe_process(pid: int, exe_path: str = "") -> Dict[str, Any]:
    """create_time and parent of a live PID, empty if it exited or the PID was reused."""
    try:
        import psutil

        proc = psutil.Process(pid)
        with proc.oneshot():
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, OSError):
                exe = ""
            if exe_path and exe and os.path.normcase(exe) != os.path.normcase(exe_path):
                return {}
            info: Dict[str, Any] = {"create_time": round(proc.create_time(), 3)}
            try:
                parent = proc.parent()
                if parent is not None and parent.create_time() <= proc.create_time():
                    info["parent_name"] = parent.name()
            except (psutil.Error, OSError):
                pass
            return info
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

def build_row(
    ts: float,
    event_type: str,
    target: Target,
    source: str,
    pid: Optional[int] = None,
    exe_path: str = "",
    process_name: str = "",
    create_time: Optional[float] = None,
    parent_name: str = "",
    access_mask: Optional[int] = None,
) -> Dict[str, Any]:
    owner = accessor_is_owner(exe_path, target.browser)
    return {
        "timestamp": round(ts, 3),
        "time_iso": datetime.fromtimestamp(ts).isoformat(timespec="milliseconds"),
        "event_type": event_type,
        "pid": pid if pid else "",
        "create_time": create_time if create_time else "",
        "process_name": process_name or (os.path.basename(exe_path) if exe_path else "unknown"),
        "exe_path": exe_path,
        "parent_name": parent_name,
        "file_path": target.path,
        "file_type": target.file_type,
        "browser": target.browser,
        "accessor_is_owner": "" if owner is None else int(owner),
        "access_mask": f"0x{access_mask:x}" if access_mask is not None else "",
        "source": source,
    }


HOST_EVENT_KEYS = ("pid", "process_name", "exe_path", "parent_name", "file_path", "file_type", "event_type")


def to_host_event(row: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Row -> dict accepted by SOAR (process_host_event / POST /api/host/events/ingest)."""
    if not row.get("pid"):
        return None
    event = {key: row[key] for key in HOST_EVENT_KEYS if row.get(key) not in (None, "")}
    event["pid"] = int(event["pid"])
    return event


class Deduper:
    """Drops repeats of the same (pid, file, event) inside a short window."""

    def __init__(self, window: float = DEDUP_WINDOW):
        self.window = window
        self._last: Dict[Tuple[Any, str, str], float] = {}

    def allow(self, row: Mapping[str, Any]) -> bool:
        key = (row.get("pid"), str(row.get("file_path", "")).lower(), str(row.get("event_type")))
        ts = float(row["timestamp"])
        last = self._last.get(key)
        if last is not None and ts - last < self.window:
            return False
        self._last[key] = ts
        if len(self._last) > 10000:
            cutoff = ts - self.window
            self._last = {k: v for k, v in self._last.items() if v >= cutoff}
        return True


# ---------------------------------------------------------------------------
# Windows auditing (event 4663)
# ---------------------------------------------------------------------------

Runner = Callable[..., subprocess.CompletedProcess]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def set_audit_policy(enabled: bool, run: Runner = subprocess.run) -> bool:
    flag = "enable" if enabled else "disable"
    result = run(
        ["auditpol", "/set", f"/subcategory:{FILE_SYSTEM_SUBCATEGORY}", f"/success:{flag}"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


_SACL_SCRIPT = """
$ErrorActionPreference = 'Stop'
$sid = New-Object System.Security.Principal.SecurityIdentifier('{sid}')
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, '{rights}', 'None', 'None', 'Success')
foreach ($p in $env:SENTINEL_AUDIT_PATHS.Split('|')) {{
    try {{
        $acl = [System.IO.File]::GetAccessControl($p, [System.Security.AccessControl.AccessControlSections]::Audit)
        {action}
        [System.IO.File]::SetAccessControl($p, $acl)
        "OK`t$p"
    }} catch {{
        "FAIL`t$p`t$($_.Exception.Message)"
    }}
}}
"""


def set_audit_rules(paths: List[str], add: bool = True, run: Runner = subprocess.run) -> Dict[str, str]:
    """Add (or remove) the audit rule on each file. Returns {path: error} for failures.

    Only the SACL is written; owner and permissions are untouched.
    """
    if not paths:
        return {}
    action = "$acl.AddAuditRule($rule)" if add else "[void]$acl.RemoveAuditRuleAll($rule)"
    script = _SACL_SCRIPT.format(sid=EVERYONE_SID, rights=AUDIT_RIGHTS, action=action)
    env = dict(os.environ, SENTINEL_AUDIT_PATHS="|".join(paths))
    result = run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, env=env, timeout=120,
    )
    done = set()
    failures: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] == "OK":
            done.add(parts[1])
        elif len(parts) >= 2 and parts[0] == "FAIL":
            failures[parts[1]] = parts[2] if len(parts) > 2 else "unknown error"
    for path in paths:
        if path not in done and path not in failures:
            failures[path] = (result.stderr or "no output from PowerShell").strip()
    return failures


def parse_system_time(value: str) -> float:
    """'2026-10-01T11:47:00.1234567Z' -> epoch seconds."""
    text = value.strip().rstrip("Z")
    if "." in text:
        head, frac = text.split(".", 1)
        text = f"{head}.{(frac + '000000')[:6]}"
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


def parse_events_xml(text: str) -> List[Dict[str, Any]]:
    """wevtutil /f:xml output (concatenated <Event> elements) -> list of events."""
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("<?xml"))
    if not body.strip():
        return []
    events = []
    for node in ET.fromstring(f"<Events>{body}</Events>"):
        system = node.find(f"{EVENT_NS}System")
        if system is None:
            continue
        created = system.find(f"{EVENT_NS}TimeCreated")
        data = {
            item.get("Name"): (item.text or "")
            for item in node.iter(f"{EVENT_NS}Data")
            if item.get("Name")
        }
        events.append({
            "event_id": int(system.findtext(f"{EVENT_NS}EventID") or 0),
            "record_id": int(system.findtext(f"{EVENT_NS}EventRecordID") or 0),
            "time": parse_system_time(created.get("SystemTime")) if created is not None else time.time(),
            "data": data,
        })
    return events


def access_event_type(mask: int) -> Optional[str]:
    if mask & DELETE:
        return "DELETE"
    if mask & (WRITE_DATA | APPEND_DATA):
        return "MODIFY"
    if mask & READ_DATA:
        return "READ"
    return None


def _int(value: str) -> Optional[int]:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def audit_row(
    event: Mapping[str, Any],
    targets: Mapping[str, Target],
    exclude_pids: Iterable[int] = (),
) -> Optional[Dict[str, Any]]:
    """4663 event -> CSV row, or None if it isn't about one of our targets."""
    if event.get("event_id") != 4663:
        return None
    data = event.get("data", {})
    target = targets.get(os.path.normcase(data.get("ObjectName", "")))
    if target is None:
        return None
    pid = _int(data.get("ProcessId", ""))
    mask = _int(data.get("AccessMask", ""))
    if not pid or pid in set(exclude_pids) or mask is None:
        return None
    event_type = access_event_type(mask)
    if event_type is None:
        return None
    return build_row(
        event["time"], event_type, target, "audit",
        pid=pid, exe_path=data.get("ProcessName", ""), access_mask=mask,
    )


class EventLogApi:
    """In-process wevtapi access returning the same XML as `wevtutil qe /f:xml`.

    The sensor polls every second. Starting wevtutil (plus a console host) that often is
    expensive, and every XPath query makes the Event Log service rescan the whole channel.
    A pull subscription only hands over events written after it was opened.
    """

    QUERY_CHANNEL_PATH = 0x1
    QUERY_FORWARD = 0x100
    QUERY_REVERSE = 0x200
    SUBSCRIBE_TO_FUTURE = 1
    RENDER_XML = 1
    ERROR_NO_MORE_ITEMS = 259
    ERROR_INSUFFICIENT_BUFFER = 122

    def __init__(self) -> None:
        from ctypes import wintypes

        api = ctypes.WinDLL("wevtapi", use_last_error=True)
        self._query = api.EvtQuery
        self._query.restype = ctypes.c_void_p
        self._query.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        self._subscribe = api.EvtSubscribe
        self._subscribe.restype = ctypes.c_void_p
        self._subscribe.argtypes = [
            ctypes.c_void_p, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
        ]
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateEventW.restype = wintypes.HANDLE
        self._kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self._kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
        self._kernel32.SetEvent.argtypes = [wintypes.HANDLE]
        self._next = api.EvtNext
        self._next.restype = wintypes.BOOL
        self._next.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        self._render = api.EvtRender
        self._render.restype = wintypes.BOOL
        self._render.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ]
        self._close = api.EvtClose
        self._close.argtypes = [ctypes.c_void_p]
        self._buf = ctypes.create_unicode_buffer(16 * 1024)

    @staticmethod
    def available() -> bool:
        if os.name != "nt":
            return False
        try:
            ctypes.WinDLL("wevtapi")
        except OSError:
            return False
        return True

    def _xml(self, event: int) -> str:
        from ctypes import wintypes

        used, props = wintypes.DWORD(0), wintypes.DWORD(0)
        size = ctypes.sizeof(self._buf)
        if not self._render(None, event, self.RENDER_XML, size, self._buf, ctypes.byref(used), ctypes.byref(props)):
            if ctypes.get_last_error() != self.ERROR_INSUFFICIENT_BUFFER:
                raise OSError(ctypes.get_last_error(), "EvtRender failed")
            self._buf = ctypes.create_unicode_buffer(used.value // ctypes.sizeof(ctypes.c_wchar) + 1)
            if not self._render(None, event, self.RENDER_XML, ctypes.sizeof(self._buf), self._buf,
                                ctypes.byref(used), ctypes.byref(props)):
                raise OSError(ctypes.get_last_error(), "EvtRender failed")
        return self._buf.value

    def _drain(self, results: int, count: int) -> List[str]:
        from ctypes import wintypes

        parts: List[str] = []
        handles = (ctypes.c_void_p * 64)()
        while len(parts) < count:
            returned = wintypes.DWORD(0)
            if not self._next(results, min(64, count - len(parts)), handles, 0, 0, ctypes.byref(returned)):
                if ctypes.get_last_error() == self.ERROR_NO_MORE_ITEMS:
                    break
                raise RuntimeError(f"EvtNext failed: error {ctypes.get_last_error()}")
            for i in range(returned.value):
                try:
                    parts.append(self._xml(handles[i]))
                finally:
                    self._close(handles[i])
        return parts

    def query(self, channel: str, xpath: str, count: int, newest_first: bool = False) -> str:
        flags = self.QUERY_CHANNEL_PATH | (self.QUERY_REVERSE if newest_first else self.QUERY_FORWARD)
        results = self._query(None, channel, xpath, flags)
        if not results:
            raise RuntimeError(f"EvtQuery failed: error {ctypes.get_last_error()}")
        try:
            return "\n".join(self._drain(results, count))
        finally:
            self._close(results)

    def subscribe(self, channel: str, xpath: str) -> "EventLogSubscription":
        signal = self._kernel32.CreateEventW(None, True, True, None)
        if not signal:
            raise OSError(ctypes.get_last_error(), "CreateEvent failed")
        handle = self._subscribe(None, signal, channel, xpath, None, None, None, self.SUBSCRIBE_TO_FUTURE)
        if not handle:
            error = ctypes.get_last_error()
            self._kernel32.CloseHandle(signal)
            raise RuntimeError(f"EvtSubscribe failed: error {error}")
        return EventLogSubscription(self, handle, signal)


class EventLogSubscription:
    def __init__(self, api: EventLogApi, handle: int, signal: int) -> None:
        self._api = api
        self._handle = handle
        self._signal = signal

    def read(self, count: int) -> str:
        """Events written since the last read ("" when none). Never blocks."""
        kernel32 = self._api._kernel32
        if kernel32.WaitForSingleObject(self._signal, 0) != 0:
            return ""
        # Reset before draining: an event logged while we read signals again instead of being missed.
        kernel32.ResetEvent(self._signal)
        events = self._api._drain(self._handle, count)
        if len(events) >= count:
            kernel32.SetEvent(self._signal)
        return "\n".join(events)

    def close(self) -> None:
        if self._handle:
            self._api._close(self._handle)
            self._api._kernel32.CloseHandle(self._signal)
            self._handle = self._signal = 0


class SecurityLogReader:
    """Reads new 4663 events from the Security log (wevtapi subscription, wevtutil as fallback)."""

    BATCH = 500
    XPATH = "*[System[(EventID=4663)]]"

    def __init__(self, run: Runner = subprocess.run, channel: str = "Security"):
        self._run = run
        self.channel = channel
        self.last_record = 0
        self._api: Optional[EventLogApi] = None
        self._subscription: Optional[EventLogSubscription] = None
        if run is subprocess.run and EventLogApi.available():
            try:
                self._api = EventLogApi()
            except Exception:
                self._api = None

    def _query(self, xpath: str, count: int, newest_first: bool = False) -> str:
        if self._api is not None:
            try:
                return self._api.query(self.channel, xpath, count, newest_first)
            except Exception:
                self._api = None
        cmd = ["wevtutil", "qe", self.channel, f"/q:{xpath}", "/f:xml", f"/c:{count}"]
        if newest_first:
            cmd.append("/rd:true")
        result = self._run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise RuntimeError(f"wevtutil failed: {(result.stderr or '').strip()}")
        return result.stdout or ""

    def start(self) -> None:
        """Skip everything already in the log."""
        if self._api is not None:
            try:
                self._subscription = self._api.subscribe(self.channel, self.XPATH)
            except Exception:
                self._subscription = None
        newest = parse_events_xml(self._query("*", 1, newest_first=True))
        self.last_record = newest[0]["record_id"] if newest else 0

    def close(self) -> None:
        if self._subscription is not None:
            self._subscription.close()
            self._subscription = None

    def _read_subscription(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        while True:
            batch = parse_events_xml(self._subscription.read(self.BATCH))
            events.extend(e for e in batch if e["record_id"] > self.last_record)
            if len(batch) < self.BATCH:
                break
        if events:
            self.last_record = max(e["record_id"] for e in events)
        return events

    def read_new(self) -> List[Dict[str, Any]]:
        if self._subscription is not None:
            try:
                return self._read_subscription()
            except Exception:
                self.close()
        events: List[Dict[str, Any]] = []
        while True:
            xpath = f"*[System[(EventID=4663) and (EventRecordID>{self.last_record})]]"
            batch = parse_events_xml(self._query(xpath, self.BATCH))
            if not batch:
                break
            events.extend(batch)
            self.last_record = max(e["record_id"] for e in batch)
            if len(batch) < self.BATCH:
                break
        return events


# ---------------------------------------------------------------------------
# File state (poll mode rows, and re-arming audit rules on replaced files)
# ---------------------------------------------------------------------------

FileState = Tuple[int, int, int]


def _stat(path: str) -> Optional[FileState]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_ino, st.st_mtime_ns, st.st_size


class FileStateTracker:
    """CREATE / MODIFY / REPLACE / DELETE from file identity, mtime and size.

    REPLACE means a new file now sits at the path (atomic save, or a stealer
    swapping the file); audit rules don't carry over and must be re-applied.
    """

    def __init__(self, targets: Iterable[Target]):
        self.targets: Dict[str, Target] = {}
        self._state: Dict[str, Optional[FileState]] = {}
        self.add(targets)

    def add(self, targets: Iterable[Target]) -> List[Target]:
        added = []
        for target in targets:
            key = os.path.normcase(target.path)
            if key not in self.targets:
                self.targets[key] = target
                self._state[key] = _stat(target.path)
                added.append(target)
        return added

    def poll(self) -> List[Tuple[Target, str]]:
        changes = []
        for key, target in self.targets.items():
            prev, cur = self._state[key], _stat(target.path)
            if prev is None and cur is not None:
                changes.append((target, "CREATE"))
            elif prev is not None and cur is None:
                changes.append((target, "DELETE"))
            elif prev is not None and cur is not None:
                if cur[0] != prev[0]:
                    changes.append((target, "REPLACE"))
                elif cur != prev:
                    changes.append((target, "MODIFY"))
            self._state[key] = cur
        return changes


def poll_rows(changes: Iterable[Tuple[Target, str]], now: float) -> List[Dict[str, Any]]:
    return [
        build_row(now, "MODIFY" if change == "REPLACE" else change, target, "poll")
        for target, change in changes
    ]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _arm(paths: List[str]) -> None:
    for path, error in set_audit_rules(paths).items():
        print(f"  [WARN] could not audit {path}: {error}")


def run(
    mode: str = "auto",
    poll_interval: float = POLL_INTERVAL,
    log_dir: str = LOG_DIR,
    duration: float = 0.0,
    dedup_window: float = DEDUP_WINDOW,
    on_rows: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> None:
    admin = is_admin()
    if mode == "auto":
        mode = "audit" if admin else "poll"
    if mode == "audit" and not admin:
        print("Audit mode needs an Administrator PowerShell (it reads the Security log and sets audit rules).")
        return

    tracker = FileStateTracker(resolve_targets())
    if not tracker.targets:
        print("No browser credential files found for this user. Targets would be:")
        for pattern in describe_watch_targets():
            print(f"  {pattern}")
        return

    reader: Optional[SecurityLogReader] = None
    if mode == "audit":
        if not set_audit_policy(True):
            print("auditpol failed to enable File System auditing.")
            return
        _arm([t.path for t in tracker.targets.values()])
        reader = SecurityLogReader()
        reader.start()
    else:
        print("Poll mode: only CREATE / MODIFY / DELETE, no reads and no process. Run as Administrator for audit mode.")

    out = DailyCsvWriter(log_dir, prefix=LOG_PREFIX, fields=FIELDS)
    dedup = Deduper(dedup_window)
    own_pids = {os.getpid()}
    logged = ticks = overruns = 0
    start = next_tick = time.monotonic()
    last_rescan = time.time()

    print(f"File sensor ({mode}) watching {len(tracker.targets)} file(s):")
    for target in tracker.targets.values():
        print(f"  [{target.browser}] {target.path}")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            now = time.time()
            if now - last_rescan >= RESCAN_EVERY:
                added = tracker.add(resolve_targets())
                if added and reader is not None:
                    _arm([t.path for t in added])
                last_rescan = now

            changes = tracker.poll()
            if reader is not None:
                rearm = [t.path for t, change in changes if change in ("CREATE", "REPLACE")]
                if rearm:
                    _arm(rearm)
                rows = []
                for event in reader.read_new():
                    row = audit_row(event, tracker.targets, own_pids)
                    if row is not None:
                        row.update(describe_process(int(row["pid"]), row["exe_path"]))
                        rows.append(row)
            else:
                rows = poll_rows(changes, now)

            rows = [r for r in rows if dedup.allow(r)]
            for r in rows:
                owner = {1: "owner", 0: "NOT OWNER"}.get(r["accessor_is_owner"], "?")
                print(f"  [{r['event_type']}] {r['process_name']} (pid {r['pid'] or '?'}, {owner}) -> {r['file_path']}")
            out.write(rows, now)
            if on_rows and rows:
                on_rows(rows)
            logged += len(rows)
            ticks += 1

            if duration and time.monotonic() - start >= duration:
                break
            if stop_event is not None and stop_event.is_set():
                break
            next_tick += poll_interval
            delay = next_tick - time.monotonic()
            if delay > 0:
                if stop_event is not None:
                    stop_event.wait(delay)
                else:
                    time.sleep(delay)
            else:
                overruns += 1
                next_tick = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        out.close()
        if reader is not None:
            reader.close()
        print(f"\nStopped after {ticks} checks ({overruns} late), {logged} event(s). Log: {out.path}")
        if mode == "audit":
            print("Audit rules are still on the files. Remove them with: python -m hids.file_monitor --remove-audit")


def remove_audit() -> None:
    if not is_admin():
        print("Run as Administrator to remove audit rules.")
        return
    paths = [t.path for t in resolve_targets()]
    failures = set_audit_rules(paths, add=False)
    print(f"Removed audit rules from {len(paths) - len(failures)} of {len(paths)} file(s).")
    for path, error in failures.items():
        print(f"  [WARN] {path}: {error}")
    if set_audit_policy(False):
        print("File System auditing disabled.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelAI HIDS browser credential file sensor")
    parser.add_argument("--mode", choices=("auto", "audit", "poll"), default="auto",
                        help="audit needs Administrator; auto picks audit when elevated")
    parser.add_argument("--poll-interval", type=float, default=POLL_INTERVAL,
                        help=f"Seconds between checks (default {POLL_INTERVAL})")
    parser.add_argument("--log-dir", default=LOG_DIR, help="Output folder (default hids/logs)")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = until Ctrl+C)")
    parser.add_argument("--dedup-window", type=float, default=DEDUP_WINDOW,
                        help=f"Seconds to suppress repeats of the same pid/file/event (default {DEDUP_WINDOW})")
    parser.add_argument("--list-targets", action="store_true", help="Print the files that would be watched and exit")
    parser.add_argument("--remove-audit", action="store_true", help="Remove audit rules and disable File System auditing")
    parser.add_argument("--soar", action="store_true",
                        help="Send a non-owner credential access to SOAR immediately (dry-run)")
    parser.add_argument("--live-response", action="store_true",
                        help="With --soar, allow SOAR to terminate a process. Default is dry-run.")
    args = parser.parse_args()

    if args.list_targets:
        for target in resolve_targets():
            print(f"[{target.browser}] {target.file_type}: {target.path}")
        return
    if args.remove_audit:
        remove_audit()
        return
    on_rows = None
    bridge = None
    if args.soar:
        from hids.live import HostBridge
        bridge = HostBridge(dry_run=not args.live_response)
        on_rows = bridge.on_file_rows
        print(f"SOAR host response: {'LIVE' if args.live_response else 'dry-run'}")
    try:
        run(mode=args.mode, poll_interval=args.poll_interval, log_dir=args.log_dir,
            duration=args.duration, dedup_window=args.dedup_window, on_rows=on_rows)
    finally:
        if bridge is not None:
            bridge.close()


if __name__ == "__main__":
    main()
