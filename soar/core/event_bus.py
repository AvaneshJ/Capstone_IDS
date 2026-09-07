"""
SentinelAI - Core Event Bus
Provides a thread-safe, resilient in-memory publish/subscribe event dispatcher for multi-agent coordination.
"""

from __future__ import annotations
import logging
import threading
import time
from typing import Callable, Dict, List, Any, Optional
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("SentinelAI.EventBus")


@dataclass
class Event:
    """Standardized event envelope passed across the bus."""
    topic: str
    data: Any
    timestamp: float = field(default_factory=time.time)
    sender: str = "system"
    event_id: str = field(default_factory=lambda: str(time.time_ns()))


@dataclass
class Subscription:
    """Handler subscription with priority and error handling metadata."""
    handler: Callable[[Event], Any]
    priority: int = 10  # Lower number = higher priority (e.g., 0 runs before 10)
    agent_name: str = "anonymous"


class EventBus:
    """
    Central in-memory publish-subscribe broker for all SentinelAI agents.
    Thread-safe and equipped with event history, error isolation, and metrics.
    """

    def __init__(self, history_size: int = 1000):
        self._subscriptions: Dict[str, List[Subscription]] = {}
        self._lock = threading.RLock()
        self._history: deque[Event] = deque(maxlen=history_size)
        self._dead_letter_queue: deque[Dict[str, Any]] = deque(maxlen=500)
        self._event_count: int = 0
        self._error_count: int = 0

    def subscribe(self, topic: str, handler: Callable[[Event], Any], priority: int = 10, agent_name: str = "anonymous") -> None:
        """Register a handler callback for a specific topic."""
        with self._lock:
            if topic not in self._subscriptions:
                self._subscriptions[topic] = []
            
            sub = Subscription(handler=handler, priority=priority, agent_name=agent_name)
            self._subscriptions[topic].append(sub)
            # Keep sorted by priority ascending
            self._subscriptions[topic].sort(key=lambda s: s.priority)
            logger.debug("Agent '%s' subscribed to topic '%s' (priority %d)", agent_name, topic, priority)

    def unsubscribe(self, topic: str, handler: Callable[[Event], Any]) -> bool:
        """Remove a previously registered handler."""
        with self._lock:
            if topic in self._subscriptions:
                initial_len = len(self._subscriptions[topic])
                self._subscriptions[topic] = [s for s in self._subscriptions[topic] if s.handler != handler]
                return len(self._subscriptions[topic]) < initial_len
            return False

    def publish(self, topic: str, data: Any, sender: str = "system") -> Event:
        """
        Publish an event to all subscribers of topic (and wildcard subscribers).
        Handlers execute synchronously under error isolation.
        """
        event = Event(topic=topic, data=data, sender=sender)
        
        with self._lock:
            self._history.append(event)
            self._event_count += 1
            
            # Find matching subscriptions
            matched_subs: List[Subscription] = []
            if topic in self._subscriptions:
                matched_subs.extend(self._subscriptions[topic])
            if "*" in self._subscriptions:
                matched_subs.extend(self._subscriptions["*"])

        # Execute handlers outside lock to avoid deadlocks
        for sub in matched_subs:
            try:
                sub.handler(event)
            except Exception as exc:
                self._error_count += 1
                logger.error(
                    "Error in agent '%s' handling event on topic '%s': %s",
                    sub.agent_name, topic, exc, exc_info=True
                )
                with self._lock:
                    self._dead_letter_queue.append({
                        "event": event,
                        "agent_name": sub.agent_name,
                        "error": str(exc),
                        "timestamp": time.time()
                    })

        return event

    def get_history(self, limit: int = 50, topic_filter: Optional[str] = None) -> List[Event]:
        """Retrieve recent events from the in-memory history buffer."""
        with self._lock:
            events = list(self._history)
            if topic_filter:
                events = [e for e in events if e.topic == topic_filter or topic_filter == "*"]
            return events[-limit:]

    def get_dead_letters(self) -> List[Dict[str, Any]]:
        """Retrieve failed handler executions from the dead letter queue."""
        with self._lock:
            return list(self._dead_letter_queue)

    def clear(self) -> None:
        """Reset bus subscriptions and history."""
        with self._lock:
            self._subscriptions.clear()
            self._history.clear()
            self._dead_letter_queue.clear()
            self._event_count = 0
            self._error_count = 0

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return bus throughput and error metrics."""
        with self._lock:
            return {
                "total_events_published": self._event_count,
                "total_handler_errors": self._error_count,
                "active_topics": list(self._subscriptions.keys()),
                "total_subscribers": sum(len(v) for v in self._subscriptions.values()),
                "history_length": len(self._history),
                "dead_letter_count": len(self._dead_letter_queue),
            }
