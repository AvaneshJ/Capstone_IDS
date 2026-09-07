"""
SentinelAI - Logging & Persistence Agent
Subscribes to pipeline events and persists incidents, telemetry, and audit trails to SQLite.
"""

from __future__ import annotations
import logging
from typing import Dict, Any, Optional

from agents.base_agent import BaseAgent
from core.schemas import Incident, SystemMetrics
from core.event_bus import EventBus, Event
from database.db_manager import DatabaseManager

logger = logging.getLogger("SentinelAI.LoggingAgent")


class LoggingAgent(BaseAgent):
    """
    Persistence Agent storing incident records, telemetry snapshots, and audit trails in SQLite.
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None, event_bus: Optional[EventBus] = None):
        super().__init__(name="LoggingAgent", event_bus=event_bus)
        self.db_manager = db_manager or DatabaseManager()

    def _on_initialize(self) -> None:
        if self.event_bus:
            # Subscribe to logging topics
            self.event_bus.subscribe("action.log", self.process, priority=10, agent_name=self.name)
            self.event_bus.subscribe("system.metrics.record", self._handle_metrics_event, priority=10, agent_name=self.name)

    def _handle_event(self, event: Event) -> Optional[bool]:
        data = event.data
        if isinstance(data, Incident):
            success = self.db_manager.save_incident(data)
            if success:
                logger.debug("Persisted incident %s to database.", data.incident_id)
            return success
        elif isinstance(data, dict) and "incident" in data:
            inc = data["incident"]
            if isinstance(inc, Incident):
                return self.db_manager.save_incident(inc)
        return False

    def _handle_metrics_event(self, event: Event) -> None:
        """Persist system metrics snapshot."""
        data = event.data
        if isinstance(data, SystemMetrics):
            self.db_manager.save_system_metrics(data)
        elif isinstance(data, dict):
            try:
                metrics = SystemMetrics(**data)
                self.db_manager.save_system_metrics(metrics)
            except Exception as exc:
                logger.error("Failed to parse system metrics dict: %s", exc)

    def log_audit(self, agent_name: str, action: str, details: str = "", level: str = "INFO") -> bool:
        """Manual audit log entry helper."""
        return self.db_manager.save_audit_log(agent_name, action, details, level)
