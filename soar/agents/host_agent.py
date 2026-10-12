"""
SentinelAI - Host Intrusion Detection System (HIDS) SOAR Agent
Role: Member 4 — SOAR / Risk / Response (Phase 5)

Correlates process monitoring (psutil) and sensitive file access (watchdog),
evaluates InfoStealer behaviors, calculates host risk scores, maps to MITRE ATT&CK,
and autonomously executes host mitigations (process termination, alerting, and logging).

The heuristic classifier and MITRE table below are interim placeholders: Member 2's
HIDS model (sent as `label`) and Member 3's threat-analysis module are meant to replace them.
"""

from __future__ import annotations
import os
import sys
import time
import logging
from typing import Dict, Any, Optional, List

try:
    import psutil
except ImportError:
    psutil = None

# Ensure soar root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent
from core.schemas import (
    HostIncident,
    HostProcessInfo,
    HostFileEvent,
    HostActionType,
    SeverityLevel
)
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.HostAgent")

# ML labels accepted from Member 2's HIDS model, mapped to the classification SOAR reports
ML_LABELS = {
    "normal": "Normal",
    "benign": "Normal",
    "anomalous": "Anomalous",
    "anomaly": "Anomalous",
    "stealer": "Stealer",
    "infostealer": "Stealer",
    "ransomware": "Ransomware",
    "malware": "Malware",
}


# List of sensitive files typically targeted by InfoStealers (RedLine, Vidar, Lumma, Racoon)
SENSITIVE_TARGETS = {
    "Cookies": {"type": "CookieDB", "weight": 2.5, "mitre_id": "T1539", "mitre_name": "Steal Web Session Cookie"},
    "Local State": {"type": "LocalState (Master Key)", "weight": 3.0, "mitre_id": "T1555.003", "mitre_name": "Credentials from Web Browsers"},
    "Web Data": {"type": "Autofill & Credit Cards", "weight": 2.5, "mitre_id": "T1555.003", "mitre_name": "Credentials from Web Browsers"},
    "Login Data": {"type": "Saved Passwords DB", "weight": 3.5, "mitre_id": "T1555.003", "mitre_name": "Credentials from Web Browsers"},
    "cookies.sqlite": {"type": "Firefox CookieDB", "weight": 2.5, "mitre_id": "T1539", "mitre_name": "Steal Web Session Cookie"},
    "key4.db": {"type": "Firefox Key Database", "weight": 3.5, "mitre_id": "T1555.003", "mitre_name": "Credentials from Web Browsers"},
    "logins.json": {"type": "Firefox Saved Passwords", "weight": 3.5, "mitre_id": "T1555.003", "mitre_name": "Credentials from Web Browsers"},
    "wallet.dat": {"type": "Crypto Wallet", "weight": 3.5, "mitre_id": "T1005", "mitre_name": "Data from Local System"},
}

# Known legitimate browser binary names
LEGIT_BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"}

# Suspicious parent processes commonly used to spawn stealers
SUSPICIOUS_PARENTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


class HostSOARAgent(BaseAgent):
    """
    Host SOAR Agent for SentinelAI Phase 5.
    Ingests combined host telemetry (Process + File Access), classifies maliciousness,
    calculates host-level risk, and executes automated host mitigations.
    """

    def __init__(self, event_bus: Optional[EventBus] = None, dry_run: bool = True):
        super().__init__(name="HostSOARAgent", event_bus=event_bus)
        self.dry_run = dry_run
        self.total_host_incidents = 0
        self.total_processes_killed = 0

    def _on_initialize(self) -> None:
        # Bus topics (host.event.ingested / host.model.prediction) are subscribed by
        # SentinelOrchestrator so bus events are also persisted, alerted and explained.
        logger.info("HostSOARAgent initialized (Dry-Run: %s).", self.dry_run)

    def _handle_event(self, event: Any) -> Optional[HostIncident]:
        """Handle incoming event bus Event or raw dict."""
        data = event.data if hasattr(event, "data") else event
        return self.process_host_event(data)

    def process_host_event(self, event: Any) -> HostIncident:
        """
        Process incoming host event dictionary or HostIncident.
        Correlates process name with sensitive file access to formulate a HostIncident.
        """
        start_time = time.time()

        try:
            # 1. Normalize input dictionary into structured sub-objects
            raw_data = event if isinstance(event, dict) else (event.to_dict() if hasattr(event, "to_dict") else {})
            
            process_info = self._extract_process_info(raw_data)
            file_event = self._extract_file_event(raw_data)
            label = raw_data.get("label") or raw_data.get("classification") or ""

            # 2. Correlate and classify if not pre-labeled by ML model
            classification, confidence, anomaly_score = self._classify_host_behavior(
                process_info,
                file_event,
                label,
                ml_confidence=raw_data.get("confidence"),
                ml_anomaly_score=raw_data.get("anomaly_score"),
            )

            # 3. Calculate Host Risk Score
            risk_score, severity = self._calculate_host_risk(process_info, file_event, classification, confidence, anomaly_score)

            # 4. Map to MITRE ATT&CK
            mitre_id, mitre_name, mitre_tactic = self._map_mitre_attack(file_event, classification)

            # 5. Formulate SOAR Action Plan
            soar_action, action_status, remediation = self._plan_and_execute_response(process_info, file_event, classification, risk_score)
            reasons = self._explain(process_info, file_event, classification, raw_data.get("reasons"))

            # 6. Assemble Final HostIncident
            incident = HostIncident(
                hostname=os.environ.get("COMPUTERNAME", "WINDOWS-HOST"),
                process=process_info,
                file_event=file_event,
                classification=classification,
                confidence=confidence,
                anomaly_score=anomaly_score,
                risk_score=risk_score,
                severity=severity,
                mitre_technique_id=mitre_id,
                mitre_technique_name=mitre_name,
                mitre_tactic=mitre_tactic,
                soar_action=soar_action,
                action_status=action_status,
                remediation_notes=remediation,
                reasons=reasons,
                raw_event=raw_data
            )

            # 7. Update agent telemetry
            self.total_host_incidents += 1
            if soar_action == HostActionType.TERMINATE_PROCESS and "SUCCESS" in action_status:
                self.total_processes_killed += 1

            latency = (time.time() - start_time) * 1000.0
            self.average_latency_ms = ((self.average_latency_ms * 0.9) + (latency * 0.1)) if self.total_processed > 0 else latency
            self.total_processed += 1

            # 8. Publish to EventBus (alert fan-out is done by AlertAgent via the orchestrator)
            if self.event_bus:
                self.event_bus.publish("host.incident.created", incident.to_dict(), sender=self.name)

            return incident

        except Exception as exc:
            logger.error("Error processing host event in HostSOARAgent: %s", exc, exc_info=True)
            raise

    def _on_shutdown(self) -> None:
        """Clean shutdown hook."""
        logger.info("HostSOARAgent shut down cleanly. Total incidents: %d, Terminated PIDs: %d",
                    self.total_host_incidents, self.total_processes_killed)

    # -------------------------------------------------------------
    # Internal Correlation & Heuristics Logic
    # -------------------------------------------------------------

    def _extract_process_info(self, data: Dict[str, Any]) -> HostProcessInfo:
        """Extract process metadata from input dictionary."""
        return HostProcessInfo(
            pid=int(data.get("pid", 0)),
            process_name=str(data.get("process_name", data.get("process", "unknown.exe"))).lower(),
            parent_name=str(data.get("parent_name") or data.get("parent") or "").lower(),
            cpu_percent=float(data.get("cpu_percent", data.get("cpu", 0.0))),
            memory_mb=float(data.get("memory_mb", data.get("memory", 0.0))),
            exe_path=str(data.get("exe_path") or ""),
            cmdline=data.get("cmdline") or []
        )

    def _extract_file_event(self, data: Dict[str, Any]) -> HostFileEvent:
        """Extract file access metadata from input dictionary."""
        file_path = str(data.get("file_path") or data.get("file") or "")
        file_type = data.get("file_type") or ""
        
        if not file_type:
            # Auto-detect file type from path
            for target_name, meta in SENSITIVE_TARGETS.items():
                if target_name.lower() in file_path.lower():
                    file_type = meta["type"]
                    break
            if not file_type:
                file_type = "StandardFile"

        return HostFileEvent(
            file_path=file_path,
            file_type=file_type,
            event_type=str(data.get("event_type") or data.get("event") or "READ").upper(),
            target_browser=self._detect_browser_from_path(file_path)
        )

    def _detect_browser_from_path(self, path: str) -> str:
        p_lower = path.lower()
        if "chrome" in p_lower:
            return "Google Chrome"
        if "edge" in p_lower:
            return "Microsoft Edge"
        if "firefox" in p_lower:
            return "Mozilla Firefox"
        if "brave" in p_lower:
            return "Brave Browser"
        return "System"

    def _classify_host_behavior(
        self,
        process: HostProcessInfo,
        file_event: HostFileEvent,
        preset_label: str,
        ml_confidence: Optional[float] = None,
        ml_anomaly_score: Optional[float] = None,
    ) -> tuple[str, float, float]:
        """
        Correlate process and file access to determine if action is Normal or InfoStealer.
        """
        is_sensitive_file = self._is_sensitive(file_event)
        is_legit_browser = process.process_name in LEGIT_BROWSERS

        # Pre-classified by Member 2's HIDS model: keep its label and its scores
        ml_label = ML_LABELS.get(str(preset_label).strip().lower())
        if ml_label:
            is_normal = ml_label == "Normal"
            confidence = self._unit_interval(ml_confidence, 0.98 if is_normal else 0.95)
            anomaly_score = self._unit_interval(ml_anomaly_score, 0.05 if is_normal else 0.88)
            if ml_label == "Anomalous" and is_sensitive_file and not is_legit_browser:
                ml_label = "Stealer"
            return ml_label, confidence, anomaly_score

        # Heuristic Correlation:

        # Unauthorized process accessing browser credentials = High Probability Stealer
        if is_sensitive_file and not is_legit_browser:
            confidence = 0.92
            anomaly_score = 0.85
            if process.parent_name in SUSPICIOUS_PARENTS:
                confidence = 0.98
                anomaly_score = 0.95
            return "Stealer", confidence, anomaly_score

        # Normal application behavior
        return "Normal", 0.96, 0.05

    @staticmethod
    def _is_sensitive(file_event: HostFileEvent) -> bool:
        path = file_event.file_path.lower()
        return bool(path) and any(target.lower() in path for target in SENSITIVE_TARGETS)

    @staticmethod
    def _unit_interval(value: Any, default: float) -> float:
        try:
            return min(1.0, max(0.0, float(value)))
        except (TypeError, ValueError):
            return default

    def _calculate_host_risk(
        self,
        process: HostProcessInfo,
        file_event: HostFileEvent,
        classification: str,
        confidence: float,
        anomaly_score: float
    ) -> tuple[float, SeverityLevel]:
        """
        Host Risk Formula:
        Risk = (Base_Weight * Confidence) + Sensitive_File_Bonus + Parent_Anomaly_Bonus
        """
        if classification == "Normal":
            return 0.5, SeverityLevel.LOW
        if classification == "Anomalous":
            # Behaviour alone (no protected file touched) never reaches HIGH: 4.25 - 6.5.
            score = round(2.0 + 4.5 * anomaly_score, 2)
            return score, (SeverityLevel.MEDIUM if score >= 4.0 else SeverityLevel.LOW)

        base_weight = 7.5  # Stealer baseline weight
        file_bonus = 0.0

        for target_name, meta in SENSITIVE_TARGETS.items():
            if target_name.lower() in file_event.file_path.lower():
                file_bonus += meta["weight"]
                break

        parent_bonus = 1.0 if process.parent_name in SUSPICIOUS_PARENTS else 0.0
        
        raw_score = (base_weight * confidence) + file_bonus + parent_bonus + (anomaly_score * 0.5)
        score = min(10.0, max(1.0, round(raw_score, 2)))

        if score >= 8.5:
            severity = SeverityLevel.CRITICAL
        elif score >= 7.0:
            severity = SeverityLevel.HIGH
        elif score >= 4.0:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        return score, severity

    def _map_mitre_attack(self, file_event: HostFileEvent, classification: str) -> tuple[str, str, str]:
        """Map to MITRE ATT&CK matrix."""
        if classification in ("Normal", "Anomalous"):
            return "", "", ""

        for target_name, meta in SENSITIVE_TARGETS.items():
            if target_name.lower() in file_event.file_path.lower():
                return meta["mitre_id"], meta["mitre_name"], "Credential Access"

        return "T1005", "Data from Local System", "Collection"

    def _explain(
        self,
        process: HostProcessInfo,
        file_event: HostFileEvent,
        classification: str,
        model_reasons: Any,
    ) -> List[str]:
        """Plain-language reasons this event was flagged, shown to the user with the alert."""
        if classification == "Normal":
            return []
        reasons: List[str] = []
        if file_event.file_path:
            owner = file_event.target_browser if file_event.target_browser != "System" else "its owning app"
            reasons.append(
                f"{process.process_name} opened {file_event.file_type or 'a protected file'} "
                f"({file_event.file_path}), which only {owner} should read."
            )
        if isinstance(model_reasons, (list, tuple)):
            reasons.extend(str(r) for r in model_reasons if r)
        elif process.parent_name in SUSPICIOUS_PARENTS:
            reasons.append(f"It was started by a command shell ({process.parent_name}).")
        if not file_event.file_path:
            reasons.append("It did not touch your saved passwords, cookies or any other protected file.")
        return reasons

    def _plan_and_execute_response(
        self,
        process: HostProcessInfo,
        file_event: HostFileEvent,
        classification: str,
        risk_score: float
    ) -> tuple[HostActionType, str, str]:
        """Formulate SOAR response and execute process termination."""
        if classification == "Normal":
            return HostActionType.LOG_ONLY, "LOGGED", "Normal activity logged to host database."

        # A model score alone is never grounds to kill: developer tools, scripts and installers
        # behave like this too. Termination needs a recorded file access as evidence.
        if not file_event.file_path:
            return (
                HostActionType.ALERT_ONLY,
                "ALERT_DISPATCHED",
                f"{process.process_name} was flagged for unusual behaviour only; it did not touch any protected file, "
                "so it was not stopped. If you started it yourself, no action is needed.",
            )
        if risk_score < 7.0:
            return HostActionType.ALERT_ONLY, "ALERT_DISPATCHED", "Risk below the automatic-response threshold; alert raised for review."

        # High/Critical Risk Stealer -> Trigger Process Termination
        if process.pid <= 4:
            # Safeguard: Never terminate System/Idle processes
            return HostActionType.ALERT_ONLY, "ALERT_DISPATCHED", "System process touching file; termination skipped for safety."

        # Execute Process Kill (with dry_run safety)
        if self.dry_run:
            status = f"SIMULATED (Dry-Run: PID {process.pid} [{process.process_name}] would be terminated)"
            remediation = f"Simulated process kill for malicious PID {process.pid}. File '{file_event.file_path}' preserved."
            logger.warning("[DRY RUN] Host SOAR Action: Kill PID %d (%s)", process.pid, process.process_name)
            return HostActionType.TERMINATE_PROCESS, status, remediation

        outcome, detail = self._terminate_pid(process)
        label = f"PID {process.pid} [{process.process_name}]"
        if outcome == "SUCCESS":
            status = f"SUCCESS (Terminated malicious process {label})"
            remediation = f"Process {process.process_name} (PID: {process.pid}) was terminated immediately. Host contained."
            logger.critical("🚨 [HOST SOAR] Terminated malicious PID %d (%s)", process.pid, process.process_name)
        elif outcome == "ALREADY_EXITED":
            status = f"ALREADY_EXITED ({label} was no longer running)"
            remediation = f"{process.process_name} exited before containment. Inspect '{process.exe_path or 'its executable'}' and rotate exposed credentials."
        elif outcome == "IDENTITY_MISMATCH":
            status = f"SKIPPED (PID {process.pid} now belongs to a different process: {detail})"
            remediation = "Termination refused to avoid killing an unrelated process (PID reuse). Operator review required."
            logger.warning("Host SOAR refused to kill PID %d: %s", process.pid, detail)
        else:
            status = f"FAILED (Could not terminate {label}: {detail})"
            remediation = f"Failed to terminate PID {process.pid}. Operator manual intervention required."
        return HostActionType.TERMINATE_PROCESS, status, remediation

    def _terminate_pid(self, process: HostProcessInfo) -> tuple[str, str]:
        """
        Terminate the process only if the live PID still matches the reported process.
        Returns (outcome, detail) where outcome is SUCCESS, ALREADY_EXITED, IDENTITY_MISMATCH or FAILED.
        """
        if psutil is None:
            return "FAILED", "psutil unavailable, cannot verify process identity"

        try:
            p = psutil.Process(process.pid)
            actual_name = p.name().lower()
            try:
                actual_exe = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                actual_exe = ""
        except psutil.NoSuchProcess:
            return "ALREADY_EXITED", ""
        except psutil.AccessDenied as e:
            return "FAILED", f"access denied ({e})"

        if actual_name != process.process_name:
            return "IDENTITY_MISMATCH", f"expected {process.process_name}, found {actual_name}"
        if process.exe_path:
            if not actual_exe:
                return "IDENTITY_MISMATCH", "executable path of live process could not be verified"
            if os.path.normcase(os.path.abspath(actual_exe)) != os.path.normcase(os.path.abspath(process.exe_path)):
                return "IDENTITY_MISMATCH", f"expected {process.exe_path}, found {actual_exe}"

        try:
            p.terminate()
            _, alive = psutil.wait_procs([p], timeout=2.0)
            if alive:
                p.kill()
            return "SUCCESS", ""
        except psutil.NoSuchProcess:
            return "ALREADY_EXITED", ""
        except Exception as e:
            logger.error("Failed to terminate PID %d: %s", process.pid, e)
            return "FAILED", str(e)
