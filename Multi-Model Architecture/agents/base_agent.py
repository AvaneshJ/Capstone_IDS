"""
SentinelAI - Base Agent
Abstract base class defining standard lifecycle hooks, status telemetry, and error resilience.
"""

from __future__ import annotations
import abc
import time
import logging
from typing import Dict, Any, Optional

from core.schemas import AgentStatus
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.Agents")


class BaseAgent(abc.ABC):
    """
    Standardized Abstract Base Class for all SentinelAI Specialist Agents.
    Enforces unified lifecycle: initialize(), process(event), shutdown().
    """

    def __init__(self, name: str, event_bus: Optional[EventBus] = None):
        self.name = name
        self.event_bus = event_bus
        self.status = AgentStatus.UNINITIALIZED
        self.total_processed: int = 0
        self.total_errors: int = 0
        self.last_active_timestamp: float = time.time()
        self.average_latency_ms: float = 0.0

    def initialize(self) -> None:
        """Initialize resources, models, connections, and event subscriptions."""
        try:
            self._on_initialize()
            self.status = AgentStatus.IDLE
            logger.info("Agent [%s] initialized successfully.", self.name)
        except Exception as exc:
            self.status = AgentStatus.ERROR
            self.total_errors += 1
            logger.error("Agent [%s] failed initialization: %s", self.name, exc, exc_info=True)
            raise

    @abc.abstractmethod
    def _on_initialize(self) -> None:
        """Agent-specific initialization logic implemented by subclasses."""
        pass

    def process(self, event: Event) -> Optional[Any]:
        """
        Public execution wrapper with timing, status management, and error isolation.
        """
        start_time = time.perf_counter()
        self.status = AgentStatus.PROCESSING
        self.last_active_timestamp = time.time()

        try:
            result = self._handle_event(event)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            
            # Exponential moving average for processing latency
            self.average_latency_ms = (
                (self.average_latency_ms * 0.9) + (elapsed_ms * 0.1)
                if self.total_processed > 0 else elapsed_ms
            )
            self.total_processed += 1
            self.status = AgentStatus.IDLE
            return result
        except Exception as exc:
            self.total_errors += 1
            self.status = AgentStatus.ERROR
            logger.error("Agent [%s] error processing event on topic '%s': %s", self.name, event.topic, exc, exc_info=True)
            return None

    @abc.abstractmethod
    def _handle_event(self, event: Event) -> Optional[Any]:
        """Agent-specific processing logic implemented by subclasses."""
        pass

    def shutdown(self) -> None:
        """Gracefully release resources, stop background workers, and close handlers."""
        try:
            self._on_shutdown()
            self.status = AgentStatus.OFFLINE
            logger.info("Agent [%s] shut down cleanly.", self.name)
        except Exception as exc:
            self.status = AgentStatus.ERROR
            logger.error("Agent [%s] error during shutdown: %s", self.name, exc)

    def _on_shutdown(self) -> None:
        """Agent-specific shutdown hook (optional)."""
        pass

    def get_health(self) -> Dict[str, Any]:
        """Return operational health and telemetry dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "total_processed": self.total_processed,
            "total_errors": self.total_errors,
            "average_latency_ms": round(self.average_latency_ms, 3),
            "last_active": self.last_active_timestamp,
        }
