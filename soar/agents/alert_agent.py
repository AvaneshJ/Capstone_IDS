"""
SentinelAI - Alert & Notification Agent
Dispatches security alerts across Desktop notifications, Member 4's Dashboard stream,
console broadcasts, and optional Telegram webhooks.
"""

from __future__ import annotations
import queue
import logging
import threading
from typing import Dict, List, Any, Optional, Callable
import httpx

from agents.base_agent import BaseAgent
from core.schemas import Incident, HostIncident, AlertMessage, SeverityLevel
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.AlertAgent")


class AlertAgent(BaseAgent):
    """
    Multi-channel Alerting Agent.
    Fans out threat notifications to Desktop Toast, Dashboard Queue (for Member 4),
    rich ANSI console, and external Webhooks.
    """

    def __init__(
        self,
        enable_desktop: bool = True,
        enable_telegram: bool = False,
        enable_console: bool = True,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        event_bus: Optional[EventBus] = None
    ):
        super().__init__(name="AlertAgent", event_bus=event_bus)
        self.enable_desktop = enable_desktop
        self.enable_telegram = enable_telegram
        self.enable_console = enable_console
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        
        # Thread-safe queue for Member 4's SOC Dashboard
        self.dashboard_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._alert_subscribers: List[Callable[[AlertMessage], None]] = []
        self._lock = threading.RLock()

    def _on_initialize(self) -> None:
        if self.event_bus:
            self.event_bus.subscribe("action.alert", self.process, priority=7, agent_name=self.name)

    def register_dashboard_callback(self, callback: Callable[[AlertMessage], None]) -> None:
        """Register a callback handler for streaming alerts directly to Member 4's frontend."""
        with self._lock:
            self._alert_subscribers.append(callback)

    def _handle_event(self, event: Event) -> Optional[AlertMessage]:
        data = event.data
        if not isinstance(data, Incident):
            logger.warning("AlertAgent received non-incident payload: %s", type(data))
            return None

        incident: Incident = data
        alert = self.dispatch_alert(incident)
        incident.alert = alert

        if self.event_bus:
            self.event_bus.publish("alert.dispatched", alert, sender=self.name)

        return alert

    def dispatch_alert(self, incident: Incident) -> AlertMessage:
        """Construct and broadcast alert across enabled channels."""
        sev = incident.risk.severity
        attack = incident.detection.attack_type
        src_ip = incident.flow.src_ip
        action = incident.action_plan.action_type.value

        title = f"🚨 [SentinelAI Alert] {sev.value} Threat: {attack}"
        msg = (
            f"Source IP: {src_ip} -> Dest Port: {incident.flow.dst_port}\n"
            f"Risk Score: {incident.risk.score}/10 | Conf: {incident.detection.confidence * 100:.1f}%\n"
            f"Autonomous Action: {action} (Rule: {incident.action_plan.rule_matched})\n"
            f"MITRE: {incident.threat.mitre_technique_id} - {incident.threat.mitre_technique_name}"
        )

        alert = AlertMessage(
            severity=sev,
            title=title,
            message=msg,
            src_ip=src_ip,
            dst_ip=incident.flow.dst_ip,
            attack_type=attack,
            risk_score=incident.risk.score,
            action_taken=action,
            channels=["CONSOLE", "DASHBOARD"],
            source="NIDS",
            incident_id=incident.incident_id,
        )
        toast = f"{attack} from {src_ip} (Risk {incident.risk.score}/10). Action: {action}"
        return self._fan_out(alert, toast)

    def dispatch_host_alert(self, incident: HostIncident) -> AlertMessage:
        """Construct and broadcast a HIDS host incident alert across enabled channels."""
        proc = incident.process
        action = incident.soar_action.value
        mitre = f"{incident.mitre_technique_id} - {incident.mitre_technique_name}" if incident.mitre_technique_id else "Unmapped"

        title = f"🚨 [SentinelAI HIDS Alert] {incident.severity.value} Threat: {incident.classification}"
        file_line = (
            f"{incident.file_event.file_path} [{incident.file_event.event_type}]"
            if incident.file_event.file_path else "none (behaviour only)"
        )
        msg = (
            f"Process: {proc.process_name} (PID {proc.pid}, parent {proc.parent_name or 'unknown'})\n"
            f"File: {file_line}\n"
            f"Risk Score: {incident.risk_score}/10 | Conf: {incident.confidence * 100:.1f}%\n"
            f"Autonomous Action: {action} ({incident.action_status})\n"
            f"MITRE: {mitre}"
        )
        if incident.reasons:
            msg += "\nWhy: " + " ".join(incident.reasons)

        alert = AlertMessage(
            severity=incident.severity,
            title=title,
            message=msg,
            attack_type=incident.classification,
            risk_score=incident.risk_score,
            action_taken=action,
            channels=["CONSOLE", "DASHBOARD"],
            source="HIDS",
            incident_id=incident.incident_id,
        )
        if incident.file_event.file_path:
            toast = f"{proc.process_name} touched {incident.file_event.file_type} (Risk {incident.risk_score}/10). Action: {action}"
        else:
            toast = f"{proc.process_name} behaved unusually (Risk {incident.risk_score}/10). Action: {action}"
        return self._fan_out(alert, toast)

    def _fan_out(self, alert: AlertMessage, toast_message: str) -> AlertMessage:
        """Broadcast an alert to dashboard queue, callbacks, desktop, Telegram and console."""
        channels_used = alert.channels

        # 1. Dashboard Queue Broadcast (For Member 4)
        try:
            self.dashboard_queue.put_nowait(alert.to_dict())
        except queue.Full:
            try:
                self.dashboard_queue.get_nowait()
                self.dashboard_queue.put_nowait(alert.to_dict())
            except Exception:
                pass

        with self._lock:
            for cb in self._alert_subscribers:
                try:
                    cb(alert)
                except Exception as exc:
                    logger.error("Error in dashboard alert callback: %s", exc)

        # 2. Desktop Toast Notification
        if self.enable_desktop and alert.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            self._send_desktop_notification(alert.title, toast_message)
            channels_used.append("DESKTOP")

        # 3. Optional Telegram Webhook
        if self.enable_telegram and self.telegram_token and self.telegram_chat_id:
            self._send_telegram_notification(f"{alert.title}\n\n{alert.message}")
            channels_used.append("TELEGRAM")

        # 4. Rich Console Log (disable for batch scorecards)
        if self.enable_console:
            self._print_console_alert(alert)

        return alert

    def _send_desktop_notification(self, title: str, message: str) -> None:
        """Send native desktop notification using plyer with non-blocking error handling."""
        try:
            from plyer import notification
            # Run plyer notification in a non-blocking safe try-block
            try:
                notification.notify(
                    title=title[:60],
                    message=message[:120],
                    app_name="SentinelAI",
                    timeout=3
                )
            except Exception:
                pass
        except Exception as exc:
            logger.debug("Desktop notification skipped/unavailable: %s", exc)

    def _send_telegram_notification(self, text: str) -> None:
        """Dispatch async HTTP request to Telegram bot webhook."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {"chat_id": self.telegram_chat_id, "text": text}
        try:
            # Short timeout to avoid blocking pipeline
            httpx.post(url, json=payload, timeout=3.0)
        except Exception as exc:
            logger.warning("Telegram notification failed: %s", exc)

    def _print_console_alert(self, alert: AlertMessage) -> None:
        """Formatted terminal alert."""
        color = "\033[91m" if alert.severity == SeverityLevel.CRITICAL else "\033[93m"
        reset = "\033[0m"
        logger.warning(
            "\n%s%s%s\n%s",
            color, alert.title, reset, alert.message
        )
