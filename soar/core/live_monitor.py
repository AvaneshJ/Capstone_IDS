"""
SentinelAI - Live Monitor

Runs the real-time sensors inside the SOAR backend and feeds them into the orchestrator:

  * Network: nids.live_capture.NetworkSensor (Npcap + cicflowmeter flows -> XGBoost).
      - Benign flows are counted (traffic_stats), not stored as incidents.
      - Threats are only acted on when a remote host opened the connection to this
        machine (the attacker -> victim direction the model was trained on). Flagged
        outbound flows are counted but never turned into a block of our own address.
      - One incident per (attacker, attack type) per INCIDENT_COOLDOWN seconds, so a
        flood doesn't produce thousands of identical incidents.
      - A remote host touching PORTSCAN_MIN_PORTS+ local ports within PORTSCAN_WINDOW
        seconds is reported as PortScan (the per-flow model can't see fan-out).
  * Host: hids.process_monitor (no admin needed) + hids.file_monitor audit mode (admin),
    through hids.live.HostBridge.

Environment:
  SENTINEL_LIVE=0                 disable all live sensors
  SENTINEL_CAPTURE_IFACES=a,b     capture only these interfaces (default: every adapter with IPv4)
  SENTINEL_ECO=1                  eco mode: process scans every 5 s instead of 2 s (config/runtime.py)
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("SentinelAI.LiveMonitor")

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

INCIDENT_COOLDOWN = 60.0
# Single SYN probes look benign one flow at a time; a scan is one host touching many ports.
PORTSCAN_MIN_PORTS = 15
PORTSCAN_WINDOW = 20.0
PORTSCAN_MODEL_VERSION = "live_fanout_rule"
HOST_ALERT_COOLDOWN = 600.0
# A trusted vendor reading a protected file is reported once a day per (program, file kind).
TRUSTED_VENDOR_COOLDOWN = 24 * 3600.0
MAX_INCIDENTS_PER_MINUTE = 30
FLUSH_INTERVAL = 10.0
LOCAL_IP_REFRESH = 60.0
FLOW_QUEUE_SIZE = 20_000

IncidentCallback = Callable[[str, Dict[str, Any]], None]


def _system_dirs() -> Tuple[str, ...]:
    names = ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
    dirs = {os.path.normcase(os.path.abspath(os.environ[n])) + os.sep for n in names if os.environ.get(n)}
    return tuple(dirs)


SYSTEM_DIRS = _system_dirs()


def _elevated() -> bool:
    try:
        from nids.live_capture import is_admin
    except Exception:
        return False
    return is_admin()


def _user_writable(exe_path: str) -> bool:
    """False for Windows / Program Files binaries and for processes whose path can't be read."""
    if not exe_path:
        return False
    path = os.path.normcase(os.path.abspath(exe_path))
    return not path.startswith(SYSTEM_DIRS)


class LiveMonitor:
    def __init__(self, orchestrator: Any, on_incident: Optional[IncidentCallback] = None) -> None:
        self.orch = orchestrator
        self.on_incident = on_incident
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

        # Network
        self.network_sensor = None
        self.network_state = "stopped"      # running | unavailable | error | stopped | disabled
        self.network_reason = ""
        self._flows: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=FLOW_QUEUE_SIZE)
        self._local_ips: set = set()
        self._local_ips_at = 0.0
        self._last_incident: Dict[Tuple[str, str], float] = {}
        self._fanout: Dict[str, Dict[Tuple[str, int], float]] = {}
        self._recent_incidents: list[float] = []
        self._pending_checked = 0
        self.net_stats = {
            "flows_checked": 0,
            "threats_found": 0,
            "incidents_created": 0,
            "repeats_grouped": 0,
            "outbound_flagged": 0,
            "ignored_noise": 0,
            "dropped": 0,
            "last_flow_at": None,
            "last_threat_at": None,
        }

        # Host
        self.host_bridge = None
        self.process_state = "stopped"
        self.file_state = "stopped"
        self._last_host_alert: Dict[str, float] = {}
        self._last_trusted_alert: Dict[Tuple[str, str], float] = {}
        self._trust_rules: Optional[list] = None
        self.host_stats = {"alerts": 0, "repeats_grouped": 0, "trusted_location_skipped": 0, "allowed_by_you": 0}

        # Self-protection hooks (set by the API server): SensorWatchdog and tamper finding sink
        self.watchdog: Any = None
        self.on_tamper: Optional[Callable[[Dict[str, Any]], Any]] = None
        self.tamper_state = "stopped"

    # -------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------

    def start(self) -> None:
        if os.getenv("SENTINEL_LIVE", "1").strip() == "0":
            self.network_state = self.process_state = self.file_state = "disabled"
            logger.info("Live sensors disabled (SENTINEL_LIVE=0).")
            return
        self._stop.clear()
        self._start_network()
        self._start_host()
        self._spawn(self._flush_loop, "live-stats-flush")

    def stop(self) -> None:
        self._stop.set()
        if self.network_sensor is not None:
            self.network_sensor.stop()
        for t in self._threads:
            t.join(timeout=3.0)
        self._flush_counters()
        if self.network_state == "running":
            self.network_state = "stopped"
        for attr in ("process_state", "file_state", "tamper_state"):
            if getattr(self, attr) == "running":
                setattr(self, attr, "stopped")

    def _spawn(self, target: Callable[[], None], name: str) -> threading.Thread:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        return t

    def _watch(self, sensor: str, thread: threading.Thread, state_attr: str, timeout: Optional[float] = None) -> None:
        def alive() -> bool:
            state = getattr(self, state_attr)
            if self._stop.is_set() or state in ("unavailable", "disabled", "needs_admin", "stopped"):
                return True
            return state == "running" and thread.is_alive()

        if self.watchdog is not None:
            self.watchdog.register(sensor, probe=alive, timeout=timeout)

    def _beat(self, sensor: str) -> None:
        if self.watchdog is not None:
            self.watchdog.beat(sensor)

    def _report_tamper(self, finding: Dict[str, Any]) -> None:
        logger.critical("Tamper attempt: %s - %s", finding.get("title"), finding.get("details"))
        if self.on_tamper is not None:
            self.on_tamper(finding)

    # -------------------------------------------------------------
    # Network
    # -------------------------------------------------------------

    def _start_network(self) -> None:
        try:
            from nids.live_capture import NetworkSensor, capture_available
        except Exception as exc:
            self.network_state, self.network_reason = "unavailable", f"import_failed: {exc}"
            logger.warning("Live network capture unavailable: %s", exc)
            return

        ok, reason = capture_available()
        if not ok:
            self.network_state, self.network_reason = "unavailable", reason
            logger.warning(
                "Live network capture unavailable (%s). Run SentinelAI as Administrator or install Npcap (https://npcap.com)",
                reason,
            )
            return

        ifaces_env = os.getenv("SENTINEL_CAPTURE_IFACES", "").strip()
        ifaces = [i.strip() for i in ifaces_env.split(",") if i.strip()] or None
        self.network_sensor = NetworkSensor(self._enqueue_flow, interfaces=ifaces)
        try:
            self.network_sensor.start()
        except Exception as exc:
            self.network_state, self.network_reason = "error", str(exc)
            logger.error("Live network capture failed to start: %s", exc)
            return
        self.network_state, self.network_reason = "running", ""
        self._watch("nids_capture", self._spawn(self._flow_worker, "live-flow-worker"), "network_state")

    def _enqueue_flow(self, event: Dict[str, Any]) -> None:
        try:
            self._flows.put_nowait(event)
        except queue.Full:
            self.net_stats["dropped"] += 1

    def _flow_worker(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._flows.get(timeout=1.0)
            except queue.Empty:
                self._check_sensor()
                continue
            try:
                self.handle_flow(event)
            except Exception as exc:
                logger.error("Live flow processing failed: %s", exc)

    def _check_sensor(self) -> None:
        sensor = self.network_sensor
        if sensor is not None and sensor.error and self.network_state == "running":
            self.network_state, self.network_reason = "error", sensor.error

    def _local(self) -> set:
        now = time.time()
        if now - self._local_ips_at > LOCAL_IP_REFRESH:
            from nids.live_capture import local_ipv4_addresses

            try:
                self._local_ips = local_ipv4_addresses()
            except Exception as exc:
                logger.debug("Could not refresh local addresses: %s", exc)
            self._local_ips_at = now
        return self._local_ips

    def handle_flow(self, event: Dict[str, Any]) -> Optional[Any]:
        """Classify one live flow and, for inbound threats, run the full SOAR pipeline."""
        from nids.live_capture import flow_direction, is_noise

        if is_noise(event["src_ip"], event["dst_ip"]):
            self.net_stats["ignored_noise"] += 1
            return None

        now = time.time()
        self.net_stats["flows_checked"] += 1
        self.net_stats["last_flow_at"] = now
        inbound = flow_direction(event, self._local()) == "inbound"

        flow = self.orch.packet_agent.sanitize_flow(event)
        detection = self.orch.detection_agent.predict(flow)
        is_benign = detection.attack_type.strip().lower() == "benign"

        if inbound and self._port_fanout(event, now) >= PORTSCAN_MIN_PORTS:
            detection = self._portscan_detection(detection, now)
            is_benign = False

        if is_benign:
            self._count_checked()
            return None

        if not inbound:
            self.net_stats["outbound_flagged"] += 1
            self._count_checked()
            logger.debug(
                "Ignoring %s on outbound/internal flow %s:%s -> %s:%s",
                detection.attack_type, event["src_ip"], event["src_port"], event["dst_ip"], event["dst_port"],
            )
            return None

        self.net_stats["threats_found"] += 1
        self.net_stats["last_threat_at"] = now

        key = (event["src_ip"], detection.attack_type)
        if now - self._last_incident.get(key, 0.0) < INCIDENT_COOLDOWN or not self._incident_budget(now):
            self.net_stats["repeats_grouped"] += 1
            self._count_checked()
            return None
        self._last_incident[key] = now

        override = detection if detection.model_version == PORTSCAN_MODEL_VERSION else None
        incident = self.orch.process_flow(event, detection_override=override)
        self.net_stats["incidents_created"] += 1
        logger.info(
            "Live threat: %s from %s -> %s:%s (risk %.1f, action %s)",
            incident.detection.attack_type, event["src_ip"], event["dst_ip"], event["dst_port"],
            incident.risk.score, incident.action_plan.action_type.value,
        )
        self._notify("NEW_INCIDENT", incident.to_dict())
        return incident

    def _port_fanout(self, event: Dict[str, Any], now: float) -> int:
        """Distinct local ports this remote host opened connections to in the last PORTSCAN_WINDOW seconds."""
        seen = self._fanout.setdefault(event["src_ip"], {})
        seen[(event["dst_ip"], event["dst_port"])] = now
        for key in [k for k, t in seen.items() if now - t > PORTSCAN_WINDOW]:
            del seen[key]
        if len(self._fanout) > 5000:
            self._fanout = {ip: s for ip, s in self._fanout.items() if s}
        return len(seen)

    @staticmethod
    def _portscan_detection(model_detection: Any, now: float) -> Any:
        from core.schemas import DetectionResult

        return DetectionResult(
            attack_type="PortScan",
            confidence=0.95,
            probabilities={**(model_detection.probabilities or {}), "PortScan": 0.95},
            model_version=PORTSCAN_MODEL_VERSION,
            is_anomaly=True,
            ml_attack_type=model_detection.ml_attack_type or model_detection.attack_type,
            ml_confidence=model_detection.ml_confidence or model_detection.confidence,
            policy_applied=True,
            policy_reason=f"Remote host contacted {PORTSCAN_MIN_PORTS}+ different ports within {PORTSCAN_WINDOW:.0f}s",
        )

    def _incident_budget(self, now: float) -> bool:
        self._recent_incidents = [t for t in self._recent_incidents if now - t < 60.0]
        if len(self._recent_incidents) >= MAX_INCIDENTS_PER_MINUTE:
            return False
        self._recent_incidents.append(now)
        return True

    def _count_checked(self) -> None:
        # process_flow() counts the flows it stores; everything else is counted here.
        self._pending_checked += 1
        self.orch.total_flows_processed += 1

    def _flush_counters(self) -> None:
        pending, self._pending_checked = self._pending_checked, 0
        if pending:
            try:
                self.orch.db_manager.add_checked_flows(pending)
            except Exception as exc:
                logger.debug("Could not save traffic counters: %s", exc)
                self._pending_checked += pending

    def _flush_loop(self) -> None:
        while not self._stop.wait(FLUSH_INTERVAL):
            self._flush_counters()

    # -------------------------------------------------------------
    # Host
    # -------------------------------------------------------------

    def _start_host(self) -> None:
        try:
            from hids.file_monitor import is_admin
            from hids.live import HostBridge
        except Exception as exc:
            self.process_state = self.file_state = "unavailable"
            logger.warning("HIDS sensors unavailable: %s", exc)
            return

        try:
            self.host_bridge = HostBridge(orchestrator=self.orch, dry_run=self.orch.host_agent.dry_run)
        except Exception as exc:
            self.process_state = self.file_state = "unavailable"
            logger.warning("HIDS model unavailable: %s", exc)
            return
        self.host_bridge._send = self._send_host_event  # route through dedupe + dashboard notify
        self.host_bridge.on_tamper = self._report_tamper
        self.host_bridge.score_filter = self._worth_scoring

        self.process_state = "running"
        # STATS rows arrive every 30 s while any process runs, so silence means the sensor is gone
        self._watch("hids_process", self._spawn(self._run_process_sensor, "hids-process-sensor"), "process_state", 120.0)

        if is_admin():
            self.file_state = "running"
            self._watch("hids_file", self._spawn(self._run_file_sensor, "hids-file-sensor"), "file_state")
            self.tamper_state = "running"
            self._watch("hids_tamper_log", self._spawn(self._run_tamper_sensor, "hids-tamper-sensor"), "tamper_state", 120.0)
        else:
            self.file_state = self.tamper_state = "needs_admin"
            logger.info("File sensor needs Administrator rights; credential-file reads are not watched.")

    def _run_tamper_sensor(self) -> None:
        from hids.tamper_monitor import run

        try:
            run(on_tamper=self._report_tamper, stop_event=self._stop, on_tick=lambda: self._beat("hids_tamper_log"))
        except Exception as exc:
            self.tamper_state = "error"
            logger.error("Tamper sensor stopped: %s", exc)

    def _worth_scoring(self, row: Any) -> bool:
        """Process-only alerts are dropped for system binaries (see _send_host_event), so skip the model."""
        if _user_writable(str(row.get("exe_path") or "")):
            return True
        self.host_stats["trusted_location_skipped"] += 1
        return False

    def _run_process_sensor(self) -> None:
        from config.runtime import process_scan_interval
        from hids.process_monitor import run

        def on_rows(rows: Any) -> Any:
            self._beat("hids_process")
            return self.host_bridge.on_process_rows(rows)

        try:
            run(interval=process_scan_interval(), on_rows=on_rows, stop_event=self._stop)
        except Exception as exc:
            self.process_state = "error"
            logger.error("Process sensor stopped: %s", exc)

    def _run_file_sensor(self) -> None:
        from hids.file_monitor import run

        try:
            run(mode="audit", on_rows=self.host_bridge.on_file_rows, stop_event=self._stop)
        except Exception as exc:
            self.file_state = "error"
            logger.error("File sensor stopped: %s", exc)
            return
        if not self._stop.is_set():
            # run() returns early when there are no credential files or auditpol fails.
            self.file_state = "unavailable"
            logger.warning("File sensor exited early (no credential files to watch or auditing unavailable).")

    def _send_host_event(self, event: Dict[str, Any]) -> Optional[Any]:
        """
        Credential-file evidence is always reported. A process-only anomaly is reported once per
        program per HOST_ALERT_COOLDOWN, and only for programs running from user-writable folders:
        the Isolation Forest scores origin / lifetime / parent, so short-lived Windows or installed
        binaries started from a shell (conhost.exe, ...) sit just past its threshold.
        """
        name = str(event.get("process_name") or "").lower()
        exe = str(event.get("exe_path") or "")
        now = time.time()
        touched_file = bool(event.get("file_path"))
        if not touched_file and not _user_writable(exe):
            self.host_stats["trusted_location_skipped"] += 1
            return None
        if not touched_file and now - self._last_host_alert.get(name, 0.0) < HOST_ALERT_COOLDOWN:
            self.host_stats["repeats_grouped"] += 1
            return None

        verdict = self._trust_verdict(exe)
        if verdict is not None:
            if verdict.level == "allowed":
                self.host_stats["allowed_by_you"] += 1
                return None
            event["trust"] = verdict.to_dict()
            if touched_file and verdict.level == "trusted_vendor":
                key = (os.path.normcase(exe), str(event.get("file_type") or event.get("file_path")))
                if now - self._last_trusted_alert.get(key, 0.0) < TRUSTED_VENDOR_COOLDOWN:
                    self.host_stats["repeats_grouped"] += 1
                    return None
                self._last_trusted_alert[key] = now
        self._last_host_alert[name] = now
        event.setdefault("file_path", "")
        try:
            incident = self.orch.process_host_event(event)
        except Exception as exc:
            logger.error("Host event ingest failed: %s", exc)
            return None
        self.host_stats["alerts"] += 1
        logger.info(
            "Live host event: %s pid %s -> %s (action %s)",
            event.get("process_name"), event.get("pid"), incident.classification, incident.soar_action.value,
        )
        self._notify("NEW_HOST_INCIDENT", incident.to_dict())
        return incident

    def reload_trust_rules(self) -> None:
        """Call after the user adds or removes a trusted program."""
        self._trust_rules = None

    def _trust_verdict(self, exe_path: str) -> Optional[Any]:
        if not exe_path:
            return None
        try:
            from hids.trust import evaluate

            if self._trust_rules is None:
                self._trust_rules = self.orch.db_manager.get_trusted_programs()
            return evaluate(exe_path, self._trust_rules)
        except Exception as exc:
            logger.debug("Trust check failed for %s: %s", exe_path, exc)
            return None

    # -------------------------------------------------------------
    # Status
    # -------------------------------------------------------------

    def _notify(self, event_type: str, data: Dict[str, Any]) -> None:
        if self.on_incident is None:
            return
        try:
            self.on_incident(event_type, data)
        except Exception as exc:
            logger.debug("Live incident notify failed: %s", exc)

    def status(self) -> Dict[str, Any]:
        self._check_sensor()
        sensor = self.network_sensor
        return {
            "network": {
                "state": self.network_state,
                "reason": self.network_reason,
                "backend": sensor.backend if sensor else "",
                "interfaces": list(sensor.interfaces) if sensor else [],
                "packets_seen": sensor.packets_seen if sensor else 0,
                "started_at": sensor.started_at if sensor else None,
                "queue": self._flows.qsize(),
                **self.net_stats,
            },
            "host": {
                "process_sensor": self.process_state,
                "file_sensor": self.file_state,
                "tamper_sensor": self.tamper_state,
                **self.host_stats,
            },
            "elevated": _elevated(),
            "response_mode": "test" if (self.orch.firewall_agent.dry_run or self.orch.host_agent.dry_run) else "live",
        }
