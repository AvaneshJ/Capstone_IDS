"""
SentinelAI - self-protection (anti-tamper) service.

Runs inside the backend and raises a CRITICAL "Tamper" host incident when:
  * models / policies / code no longer match the signed integrity manifest (T1565.001 / T1562.001)
  * sensor CSV logs shrink, vanish or are edited (T1070)
  * the SQLite evidence chain (incidents, host incidents, audit log) is broken (T1565.001)
  * a sensor or the supervisor stops sending heartbeats (T1562.001)
  * the previous engine run ended without a clean shutdown (killed)
  * the HIDS tamper sensor reports log clearing / audit changes / kill commands

One background thread; unchanged files reuse cached hashes, full rehash every FULL_EVERY.
"""
from __future__ import annotations

import json
import logging
import os
import re
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import security  # noqa: E402
from config.integrity import AppendOnlyWatch, IntegrityMonitor  # noqa: E402
from config.paths import HIDS_LOG_DIR, ROOT as INSTALL_ROOT  # noqa: E402
from core.schemas import HostActionType, HostFileEvent, HostIncident, HostProcessInfo, SeverityLevel  # noqa: E402
from core.watchdog import SensorWatchdog  # noqa: E402

logger = logging.getLogger("SentinelAI.SelfProtection")

CHECK_INTERVAL = 30.0
FULL_EVERY = 600.0
CHAIN_EVERY = 300.0
TAMPER_COOLDOWN = 600.0
RUN_MARKER = "engine_run.json"
SHUTDOWN_GRACE = CHECK_INTERVAL * 2 + 30.0

Notify = Callable[[str, Dict[str, Any]], None]


class SelfProtection:
    def __init__(
        self,
        orchestrator: Any,
        notify: Optional[Notify] = None,
        root: Path = INSTALL_ROOT,
        manifest_file: Optional[Path] = None,
        watchdog: Optional[SensorWatchdog] = None,
        log_dirs: Optional[List[Path]] = None,
    ) -> None:
        self.orch = orchestrator
        self.notify = notify
        self.integrity = IntegrityMonitor(root, manifest_file)
        self.watchdog = watchdog or SensorWatchdog()
        self.log_watches = [AppendOnlyWatch(d) for d in (log_dirs if log_dirs is not None else [HIDS_LOG_DIR])]
        self.chain: Optional[Dict[str, Any]] = None
        self.events: List[Dict[str, Any]] = []
        self._last_raised: Dict[str, float] = {}
        self._reported_integrity: set = set()
        self._reported_chain: set = set()
        self._last_full = 0.0
        self._last_chain = 0.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._planned_stop = False

    # -------------------------------------------------------------
    # Incidents
    # -------------------------------------------------------------

    def raise_tamper(
        self,
        kind: str,
        title: str,
        details: str,
        mitre_id: str = "T1562.001",
        mitre_name: str = "Impair Defenses: Disable or Modify Tools",
        process: Optional[Dict[str, Any]] = None,
        file_path: str = "",
        dedupe_key: Optional[str] = None,
    ) -> Optional[HostIncident]:
        key = dedupe_key or f"{kind}|{details}"
        now = time.time()
        with self._lock:
            if now - self._last_raised.get(key, 0.0) < TAMPER_COOLDOWN:
                return None
            self._last_raised[key] = now

        process = process or {}
        incident = HostIncident(
            hostname=os.environ.get("COMPUTERNAME", "WINDOWS-HOST"),
            process=HostProcessInfo(
                pid=int(process.get("pid") or 0),
                process_name=str(process.get("process_name") or "sentinelai"),
                parent_name=str(process.get("parent_name") or ""),
                exe_path=str(process.get("exe_path") or ""),
            ),
            file_event=HostFileEvent(file_path=file_path, file_type="SentinelAI", event_type="TAMPER", target_browser="System"),
            classification="Tamper",
            confidence=1.0,
            anomaly_score=1.0,
            risk_score=9.5,
            severity=SeverityLevel.CRITICAL,
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
            mitre_tactic="Defense Evasion",
            soar_action=HostActionType.ALERT_ONLY,
            action_status="ALERT_DISPATCHED",
            remediation_notes=f"{title}. {details}",
            raw_event={"source": "self_protection", "kind": kind, "title": title, "details": details},
        )
        logger.critical("TAMPER [%s] %s - %s", kind, title, details)
        try:
            incident.alert = self.orch.alert_agent.dispatch_host_alert(incident)
        except Exception as exc:
            logger.error("Tamper alert dispatch failed: %s", exc)
        try:
            self.orch.db_manager.save_host_incident(incident)
            self.orch.db_manager.save_audit_log("SelfProtection", f"TAMPER {kind}", f"{title}: {details}", "CRITICAL")
        except Exception as exc:
            logger.error("Could not persist tamper incident: %s", exc)
        with self._lock:
            self.events.insert(0, {"kind": kind, "title": title, "details": details, "mitre": mitre_id,
                                   "timestamp": incident.timestamp, "incident_id": incident.incident_id})
            del self.events[50:]
        if self.notify is not None:
            try:
                self.notify("NEW_HOST_INCIDENT", incident.to_dict())
            except Exception as exc:
                logger.debug("Tamper notify failed: %s", exc)
        return incident

    def on_finding(self, finding: Dict[str, Any]) -> Optional[HostIncident]:
        """Sink for hids.tamper_monitor findings."""
        return self.raise_tamper(
            kind=finding.get("kind", "tamper"),
            title=finding.get("title", "Tamper attempt"),
            details=finding.get("details", ""),
            mitre_id=finding.get("mitre_id", "T1562.001"),
            mitre_name=finding.get("mitre_name", "Impair Defenses: Disable or Modify Tools"),
            process=finding,
            dedupe_key=f"{finding.get('kind')}|{finding.get('record_id') or finding.get('pid') or finding.get('details')}",
        )

    # -------------------------------------------------------------
    # Unclean shutdown detection
    # -------------------------------------------------------------

    @staticmethod
    def _marker_path() -> Path:
        return security.data_dir() / RUN_MARKER

    def check_previous_run(self) -> None:
        path = self._marker_path()
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            previous = None
        if previous and not previous.get("planned_stop") and not _pid_alive(previous.get("pid")):
            started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(previous.get("started_at", 0)))
            if _stopped_by_os_shutdown(previous):
                self._log_info("ENGINE_STOPPED_WITH_WINDOWS", f"Engine started at {started} (PID {previous.get('pid')}) stopped when Windows shut down.")
            else:
                self.raise_tamper(
                    "engine_killed",
                    "SentinelAI engine stopped without a clean shutdown",
                    f"The engine started at {started} (PID {previous.get('pid')}) was killed or crashed; "
                    "protection was off until this restart.",
                    dedupe_key=f"engine_killed|{previous.get('pid')}|{previous.get('started_at')}",
                )
        self._write_marker(planned_stop=False)

    def _write_marker(self, planned_stop: bool) -> None:
        try:
            self._marker_path().write_text(json.dumps({
                "pid": os.getpid(), "started_at": self.orch.start_time if hasattr(self.orch, "start_time") else time.time(),
                "alive_at": time.time(),
                "planned_stop": planned_stop,
            }), encoding="utf-8")
        except OSError as exc:
            logger.debug("Could not write run marker: %s", exc)

    def mark_planned_stop(self) -> None:
        self._planned_stop = True
        self._write_marker(planned_stop=True)

    def _log_info(self, key: str, message: str) -> None:
        logger.info("%s: %s", key, message)
        try:
            self.orch.db_manager.save_audit_log("SelfProtection", key, message, "INFO")
        except Exception as exc:
            logger.debug("Could not save audit log: %s", exc)

    def check_integrity(self, full: bool = False) -> None:
        report = self.integrity.check(full=full)
        if report.state == "no_manifest":
            self.raise_tamper("manifest_forged", "Integrity manifest signature is invalid",
                              "The trusted file list was edited without the install key; every file is untrusted.",
                              "T1565.001", "Data Manipulation: Stored Data Manipulation", dedupe_key="manifest_forged")
            return
        current = {f"modified:{p}" for p in report.modified} | {f"missing:{p}" for p in report.missing} | {f"added:{p}" for p in report.added}
        new = sorted(current - self._reported_integrity)
        self._reported_integrity = current
        if not new:
            return
        models = [n for n in new if n.split(":", 1)[1].startswith("models/")]
        policies = [n for n in new if n.split(":", 1)[1].startswith("soar/rules/")]
        if models or policies:
            mitre_id, mitre_name = "T1565.001", "Data Manipulation: Stored Data Manipulation"
            title = "SentinelAI detection models or policies were tampered with"
        else:
            mitre_id, mitre_name = "T1562.001", "Impair Defenses: Disable or Modify Tools"
            title = "SentinelAI program files were modified"
        shown = ", ".join(new[:8]) + (f" (+{len(new) - 8} more)" if len(new) > 8 else "")
        self.raise_tamper("integrity_mismatch", title, shown, mitre_id, mitre_name,
                          file_path=new[0].split(":", 1)[1], dedupe_key=f"integrity|{'|'.join(new)}")

    def check_logs(self) -> None:
        for watch in self.log_watches:
            for problem in watch.check():
                self.raise_tamper("log_tampered", "SentinelAI sensor log was altered", problem,
                                  "T1070", "Indicator Removal", file_path=str(watch.folder))

    def check_chain(self) -> None:
        try:
            self.chain = self.orch.db_manager.verify_evidence_chain()
        except Exception as exc:
            logger.error("Evidence chain verification failed: %s", exc)
            return
        current = set(self.chain["problems"])
        new = sorted(current - self._reported_chain)
        self._reported_chain = current
        if new:
            self.raise_tamper("evidence_tampered", "SentinelAI incident database was tampered with",
                              "; ".join(new[:5]) + (f" (+{len(new) - 5} more)" if len(new) > 5 else ""),
                              "T1565.001", "Data Manipulation: Stored Data Manipulation",
                              file_path=str(getattr(self.orch.db_manager, "db_path", "")))

    def check_sensors(self) -> None:
        silenced, recovered = self.watchdog.check()
        for rec in silenced:
            self.raise_tamper("sensor_silenced", f"Sensor '{rec.name}' went silent", rec.reason,
                              dedupe_key=f"sensor_silenced|{rec.name}|{rec.silenced_since}")
        for rec in recovered:
            try:
                self.orch.db_manager.save_audit_log("SelfProtection", "SENSOR_RECOVERED", rec.name, "INFO")
            except Exception:
                pass

    def tick(self, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        steps = (
            lambda: self.check_integrity(full=now - self._last_full >= FULL_EVERY),
            self.check_logs,
            self.check_sensors,
        )
        for step in steps:
            try:
                step()
            except Exception as exc:
                logger.error("Self-protection check failed: %s", exc)
        if now - self._last_full >= FULL_EVERY:
            self._last_full = now
        if now - self._last_chain >= CHAIN_EVERY:
            self._last_chain = now
            self.check_chain()
        self._write_marker(planned_stop=self._planned_stop)

    # -------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------

    def start(self, interval: float = CHECK_INTERVAL) -> None:
        self.check_previous_run()
        self.tick()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(interval,), name="self-protection", daemon=True)
        self._thread.start()

    def _loop(self, interval: float) -> None:
        while not self._stop.wait(interval):
            self.tick()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        self.mark_planned_stop()

    def status(self) -> Dict[str, Any]:
        report = self.integrity.last
        with self._lock:
            events = list(self.events[:20])
        return {
            "integrity": report.to_dict() if report else None,
            "evidence_chain": self.chain,
            "watchdog": self.watchdog.status(),
            "recent_tamper_events": events,
            "auth_required": auth_enabled(),
        }


def auth_enabled() -> bool:
    return os.environ.get("SENTINEL_AUTH", "1").strip() != "0"


def _pid_alive(pid: Any) -> bool:
    try:
        import psutil

        return bool(pid) and psutil.pid_exists(int(pid))
    except Exception:
        return False


def _shutdown_events() -> List[float]:
    """Recent power-off / restart requests (User32 1074) and clean event-log stops (6006), Unix time."""
    query = "*[System[(EventID=1074 or EventID=6006)]]"
    try:
        out = subprocess.run(
            ["wevtutil", "qe", "System", f"/q:{query}", "/rd:true", "/c:20", "/f:xml"],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    times = []
    for stamp in re.findall(r"SystemTime='([^']+)'", out):
        try:
            times.append(datetime.fromisoformat(stamp[:26].rstrip("Z") + "+00:00").timestamp())
        except ValueError:
            continue
    return times


def _registry_shutdown_time() -> Optional[float]:
    # Not updated by Fast Startup's hybrid shutdown, hence only a fallback.
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Windows") as key:
            raw, _ = winreg.QueryValueEx(key, "ShutdownTime")
        return struct.unpack("<Q", bytes(raw)[:8])[0] / 10_000_000 - 11_644_473_600
    except (OSError, ValueError, struct.error):
        return None


def windows_shutdown_time(after: float = 0.0) -> Optional[float]:
    """First Windows shutdown or restart after `after` (Unix time), or None."""
    if os.name != "nt":
        return None
    candidates = [t for t in _shutdown_events() if t > after]
    reg = _registry_shutdown_time()
    if reg is not None and reg > after:
        candidates.append(reg)
    return min(candidates) if candidates else None


def _stopped_by_os_shutdown(previous: Dict[str, Any], shutdown_at: Optional[float] = None) -> bool:
    """True when the previous engine was still alive right up to a Windows shutdown that happened after it started."""
    started_at = previous.get("started_at") or 0
    shutdown_at = windows_shutdown_time(started_at) if shutdown_at is None else shutdown_at
    alive_at = previous.get("alive_at")
    if shutdown_at is None or alive_at is None:
        return False
    return started_at < shutdown_at and alive_at >= shutdown_at - SHUTDOWN_GRACE
