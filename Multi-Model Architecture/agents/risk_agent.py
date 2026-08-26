"""
SentinelAI - Risk Assessment Agent
Computes dynamic multi-factor risk scores (1.0 to 10.0) using attack severity, confidence,
frequency velocity across sliding time windows, and target asset criticality.
"""

from __future__ import annotations
import time
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple

from agents.base_agent import BaseAgent
from core.schemas import FlowEvent, DetectionResult, RiskScoreResult, SeverityLevel
from core.event_bus import EventBus, Event
from rules.policy_engine import PolicyEngine

logger = logging.getLogger("SentinelAI.RiskAgent")


class RiskAssessmentAgent(BaseAgent):
    """
    Evaluates dynamic, multi-dimensional risk scores based on:
    Risk Score = (Base Attack Weight * Confidence) + Velocity Multiplier + Target Sensitivity
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        sliding_window_seconds: float = 60.0,
        event_bus: Optional[EventBus] = None
    ):
        super().__init__(name="RiskAssessmentAgent", event_bus=event_bus)
        self.policy_engine = policy_engine or PolicyEngine()
        self.sliding_window_seconds = sliding_window_seconds
        
        # Thread-safe sliding window frequency tracker: src_ip -> deque of timestamps
        self._ip_history: Dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _on_initialize(self) -> None:
        if self.event_bus:
            self.event_bus.subscribe("threat.analyzed", self.process, priority=4, agent_name=self.name)

    def _handle_event(self, event: Event) -> Optional[RiskScoreResult]:
        data = event.data
        if not isinstance(data, dict) or "flow" not in data or "detection" not in data:
            logger.warning("RiskAssessmentAgent received invalid payload format: %s", type(data))
            return None

        flow: FlowEvent = data["flow"]
        detection: DetectionResult = data["detection"]
        threat = data.get("threat")

        risk_result = self.calculate_risk(flow, detection)
        if self.event_bus:
            # Forward enriched payload
            forward_data = {
                "flow": flow,
                "detection": detection,
                "threat": threat,
                "risk": risk_result
            }
            self.event_bus.publish("risk.evaluated", forward_data, sender=self.name)
        return risk_result

    def _record_and_get_velocity(self, src_ip: str, current_time: float) -> Tuple[int, float]:
        """Record IP event in sliding window and return (event_count, velocity_multiplier)."""
        with self._lock:
            q = self._ip_history[src_ip]
            # Prune events older than window
            cutoff = current_time - self.sliding_window_seconds
            while q and q[0] < cutoff:
                q.popleft()
            
            # Record current event
            q.append(current_time)
            count = len(q)

        multiplier = self.policy_engine.get_velocity_multiplier(count)
        return count, multiplier

    def calculate_risk(self, flow: FlowEvent, detection: DetectionResult) -> RiskScoreResult:
        """
        Compute multi-factor risk score:
        Risk = (Base_Weight * Confidence) + Velocity_Multiplier + Target_Sensitivity
        """
        now = time.time()
        
        # 1. Base Weight & Confidence
        base_weight = self.policy_engine.get_base_weight(detection.attack_type)
        confidence = float(detection.confidence)
        base_confidence_product = base_weight * confidence

        # 2. Velocity Tracking
        count_60s, velocity_multiplier = self._record_and_get_velocity(flow.src_ip, now)

        # 3. Target Sensitivity
        target_sensitivity = self.policy_engine.get_target_sensitivity(flow.dst_ip, flow.dst_port)

        # 4. Total Score Calculation
        if detection.attack_type.upper() == "BENIGN":
            raw_score = 0.2 + (0.1 if count_60s > 20 else 0.0)
        else:
            raw_score = base_confidence_product + velocity_multiplier + target_sensitivity

        # Clamp between 0.1 and 10.0
        final_score = round(max(0.1, min(10.0, raw_score)), 2)

        # 5. Categorize Severity Level
        if final_score >= 8.5:
            severity = SeverityLevel.CRITICAL
        elif final_score >= 7.0:
            severity = SeverityLevel.HIGH
        elif final_score >= 4.0:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        rationale = (
            f"Base weight ({base_weight}) * conf ({confidence:.2f}) = {base_confidence_product:.2f}. "
            f"Velocity factor: +{velocity_multiplier:.1f} ({count_60s} events/60s). "
            f"Target sensitivity on port {flow.dst_port}: +{target_sensitivity:.1f}."
        )

        return RiskScoreResult(
            score=final_score,
            severity=severity,
            base_attack_weight=base_weight,
            confidence_factor=round(confidence, 3),
            velocity_multiplier=round(velocity_multiplier, 2),
            target_sensitivity=round(target_sensitivity, 2),
            frequency_count_60s=count_60s,
            rationale=rationale
        )

    def reset_history(self) -> None:
        """Clear velocity tracker state."""
        with self._lock:
            self._ip_history.clear()
