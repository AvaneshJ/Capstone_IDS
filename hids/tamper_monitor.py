"""
Tamper sensor - attempts to blind or stop SentinelAI.

  * Security log (Administrator): 1102 log cleared, 1100 event logging shut down,
    4719 audit policy changed (only removals; SentinelAI itself only adds auditing).
  * Process command lines (from hids.process_monitor START rows): kill tools aimed at
    SentinelAI processes, event-log clearing, auditpol disabling, firewall switched off,
    and destructive commands on the SentinelAI install folder.

Each finding is a dict: kind, title, mitre_id, mitre_name, details (+ pid/process when known).

Run from repo root (Administrator for the Security log part):
  python -m hids.tamper_monitor [--duration 0]
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from hids.file_monitor import Runner, is_admin, parse_events_xml

POLL_INTERVAL = 15.0
INSTALL_ROOT = os.path.normcase(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROTECTED_NAMES = ("sentinelai", "sentinel-backend", "sentinel_backend", "python.exe", "pythonw.exe",
                   "electron.exe", "soar\\main.py", "soar/main.py", "uvicorn")
KILL_TOOLS = {"taskkill.exe", "tskill.exe", "pskill.exe", "pskill64.exe", "processhacker.exe"}
DESTRUCTIVE = ("del ", "erase ", "rd ", "rmdir ", "remove-item", "icacls", "takeown", "attrib ",
               "move-item", "ren ", "rename-item", "set-content", "out-file", "copy-item")

# AuditPolicyChanges: %%8448 success removed, %%8450 failure removed
AUDIT_REMOVED = ("%%8448", "%%8450", "removed")

TAMPER_LOG_EVENTS = {
    1102: ("log_cleared", "Security event log was cleared", "T1070.001", "Indicator Removal: Clear Windows Event Logs"),
    1100: ("logging_stopped", "Windows event logging service was shut down", "T1562.002", "Impair Defenses: Disable Windows Event Logging"),
    4719: ("audit_policy_changed", "System audit policy was weakened", "T1562.002", "Impair Defenses: Disable Windows Event Logging"),
}


def _finding(kind: str, title: str, mitre_id: str, mitre_name: str, details: str, **extra: Any) -> Dict[str, Any]:
    return {"kind": kind, "title": title, "mitre_id": mitre_id, "mitre_name": mitre_name, "details": details, **extra}


# ---------------------------------------------------------------------------
# Security log
# ---------------------------------------------------------------------------

def event_finding(event: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    spec = TAMPER_LOG_EVENTS.get(event.get("event_id"))
    if spec is None:
        return None
    kind, title, mitre_id, mitre_name = spec
    data = event.get("data", {})
    if event["event_id"] == 4719:
        changes = str(data.get("AuditPolicyChanges", "")).lower()
        if not any(marker in changes for marker in AUDIT_REMOVED):
            return None
        details = f"Audit subcategory {data.get('SubcategoryGuid', '?')} changed ({data.get('AuditPolicyChanges', '')}) by {data.get('SubjectUserName', '?')}"
    elif event["event_id"] == 1102:
        details = "The Security log was cleared, erasing evidence SentinelAI relies on."
    else:
        details = "The Windows Event Log service stopped; host sensors are blind until it restarts."
    return _finding(kind, title, mitre_id, mitre_name, details, record_id=event.get("record_id"), event_id=event["event_id"])


class TamperLogReader:
    """New 1100 / 1102 / 4719 events from the Security log via wevtutil."""

    XPATH = "*[System[(EventID=1100 or EventID=1102 or EventID=4719) and (EventRecordID>{last})]]"

    def __init__(self, run: Runner = subprocess.run):
        self._run = run
        self.last_record = 0

    def _query(self, xpath: str, count: int, newest_first: bool = False) -> str:
        cmd = ["wevtutil", "qe", "Security", f"/q:{xpath}", "/f:xml", f"/c:{count}"]
        if newest_first:
            cmd.append("/rd:true")
        result = self._run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise RuntimeError(f"wevtutil failed: {(result.stderr or '').strip()}")
        return result.stdout or ""

    def start(self) -> None:
        newest = parse_events_xml(self._query("*", 1, newest_first=True))
        self.last_record = newest[0]["record_id"] if newest else 0

    def read_new(self) -> List[Dict[str, Any]]:
        events = parse_events_xml(self._query(self.XPATH.format(last=self.last_record), 200))
        if events:
            self.last_record = max(e["record_id"] for e in events)
        findings = [event_finding(e) for e in events]
        return [f for f in findings if f is not None]


# ---------------------------------------------------------------------------
# Command lines
# ---------------------------------------------------------------------------

def _targets_us(cmd: str, protected_pids: Iterable[int], names: Iterable[str]) -> Optional[str]:
    for name in names:
        if name in cmd:
            return name
    for pid in protected_pids:
        if pid and re.search(rf"(?<![\d.:]){pid}(?![\d.:])", cmd):
            return f"pid {pid}"
    return None


def classify_command(
    process_name: str,
    cmdline: str,
    protected_pids: Iterable[int] = (),
    names: Iterable[str] = PROTECTED_NAMES,
    install_root: str = INSTALL_ROOT,
) -> Optional[Dict[str, Any]]:
    name = (process_name or "").lower()
    cmd = (cmdline or "").lower()
    if not cmd:
        return None

    kill_context = (
        name in KILL_TOOLS
        or "stop-process" in cmd
        or re.search(r"\bkill\s+(-\w+\s+)*-?\d+", cmd) is not None
        or ("wmic" in cmd and "process" in cmd and ("delete" in cmd or "terminate" in cmd))
        or re.search(r"\b(sc|sc\.exe)\s+(stop|delete|config)\b", cmd) is not None
        or re.search(r"\bnet\s+stop\b", cmd) is not None
    )
    if kill_context:
        target = _targets_us(cmd, protected_pids, names)
        if target:
            return _finding("kill_attempt", "Attempt to stop SentinelAI", "T1562.001",
                            "Impair Defenses: Disable or Modify Tools",
                            f"{process_name} targeted {target}: {cmdline[:300]}")

    if ("wevtutil" in cmd and re.search(r"\b(cl|clear-log)\b", cmd)) or "clear-eventlog" in cmd or "remove-eventlog" in cmd:
        return _finding("log_clear_command", "Command to clear Windows event logs", "T1070.001",
                        "Indicator Removal: Clear Windows Event Logs", cmdline[:300])

    if "auditpol" in cmd and ("/clear" in cmd or "/remove" in cmd or ":disable" in cmd):
        return _finding("audit_disable_command", "Command to disable Windows auditing", "T1562.002",
                        "Impair Defenses: Disable Windows Event Logging", cmdline[:300])

    if ("advfirewall" in cmd and "state off" in cmd) or ("set-netfirewallprofile" in cmd and "false" in cmd):
        return _finding("firewall_disabled", "Command to switch off Windows Firewall", "T1562.004",
                        "Impair Defenses: Disable or Modify System Firewall", cmdline[:300])

    if install_root and install_root in os.path.normcase(cmd) and any(verb in cmd for verb in DESTRUCTIVE):
        return _finding("install_tamper_command", "Command modifying SentinelAI's files", "T1565.001",
                        "Data Manipulation: Stored Data Manipulation", cmdline[:300])
    return None


def protected_pids() -> set:
    pids = {os.getpid(), os.getppid()}
    extra = os.environ.get("SENTINEL_PROTECTED_PIDS", "")
    pids.update(int(p) for p in extra.split(",") if p.strip().isdigit())
    return pids


def row_finding(row: Mapping[str, Any], pids: Iterable[int], trusted_parents: Iterable[int]) -> Optional[Dict[str, Any]]:
    """process_monitor START row -> finding. Commands launched by SentinelAI itself are ignored."""
    if str(row.get("event", "")).upper() != "START":
        return None
    try:
        if int(row.get("ppid") or 0) in set(trusted_parents):
            return None
    except (TypeError, ValueError):
        pass
    finding = classify_command(str(row.get("process_name") or ""), str(row.get("cmdline") or ""), pids)
    if finding:
        finding.update(pid=row.get("pid"), process_name=row.get("process_name"),
                       exe_path=row.get("exe_path"), parent_name=row.get("parent_name"))
    return finding


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(
    on_tamper: Callable[[Dict[str, Any]], None],
    interval: float = POLL_INTERVAL,
    duration: float = 0.0,
    stop_event: Optional[threading.Event] = None,
    on_tick: Optional[Callable[[], None]] = None,
) -> None:
    if not is_admin():
        print("Tamper log sensor needs Administrator (reads the Security log).")
        return
    reader = TamperLogReader()
    reader.start()
    stop_event = stop_event or threading.Event()
    start = time.monotonic()
    while not stop_event.is_set():
        try:
            for finding in reader.read_new():
                on_tamper(finding)
        except Exception as exc:
            print(f"[tamper] Security log read failed: {exc}")
        if on_tick:
            on_tick()
        if duration and time.monotonic() - start >= duration:
            break
        stop_event.wait(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelAI tamper sensor (Security log 1100/1102/4719)")
    parser.add_argument("--duration", type=float, default=0.0, help="Stop after N seconds (0 = until Ctrl+C)")
    args = parser.parse_args()
    try:
        run(lambda f: print(f"[TAMPER] {f['title']}: {f['details']}"), duration=args.duration)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
