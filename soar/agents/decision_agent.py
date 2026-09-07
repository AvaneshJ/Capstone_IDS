"""
SentinelAI - Decision & Response Planning Agent
Evaluates security policies and threat risk scores to formulate autonomous SOAR action plans.
"""

from __future__ import annotations
import logging
import time
from typing import Dict, Any, Optional

from agents.base_agent import BaseAgent
from core.schemas import FlowEvent, DetectionResult, ThreatEvidence, RiskScoreResult, ActionPlan, Incident, ActionType
from core.event_bus import EventBus, Event
from rules.policy_engine import PolicyEngine

logger = logging.getLogger("SentinelAI.DecisionAgent")


class DecisionAgent(BaseAgent):
    """
    SOAR Response Planning Agent.
    Evaluates policy engine thresholds against risk scores, checks whitelists,
    and orchestrates downstream action dispatches (Firewall, Alerts, Logging).
    """

    def __init__(self, policy_engine: Optional[PolicyEngine] = None, event_bus: Optional[EventBus] = None):
        super().__init__(name="DecisionAgent", event_bus=event_bus)
        self.policy_engine = policy_engine or PolicyEngine()

    def _on_initialize(self) -> None:
        if self.event_bus:
            self.event_bus.subscribe("risk.evaluated", self.process, priority=5, agent_name=self.name)

    def _handle_event(self, event: Event) -> Optional[Incident]:
        data = event.data
        if not isinstance(data, dict):
            logger.warning("DecisionAgent received invalid payload format: %s", type(data))
            return None

        flow: FlowEvent = data["flow"]
        detection: DetectionResult = data["detection"]
        threat: ThreatEvidence = data.get("threat") or ThreatEvidence()
        risk: RiskScoreResult = data["risk"]

        incident = self.decide_and_plan(flow, detection, threat, risk)
        return incident

    def decide_and_plan(
        self,
        flow: FlowEvent,
        detection: DetectionResult,
        threat: ThreatEvidence,
        risk: RiskScoreResult
    ) -> Incident:
        """
        Evaluate policy rules, produce ActionPlan, and construct the master Incident envelope.
        """
        action_plan = self.policy_engine.evaluate_response_action(
            src_ip=flow.src_ip,
            risk_score=risk.score,
            attack_type=detection.attack_type
        )

        incident = Incident(
            timestamp=time.time(),
            flow=flow,
            detection=detection,
            threat=threat,
            risk=risk,
            action_plan=action_plan,
            status="NEW"
        )

        logger.info(
            "Decision formulated for IP [%s] (Attack: %s, Risk: %.1f/10): Action=%s (Rule: %s)",
            flow.src_ip, detection.attack_type, risk.score, action_plan.action_type.value, action_plan.rule_matched
        )

        if self.event_bus:
            # 1. Publish full incident created
            self.event_bus.publish("incident.created", incident, sender=self.name)

            # 2. Trigger Firewall Enforcement if action requires blocking
            if action_plan.action_type in (ActionType.BLOCK_IP, ActionType.TEMP_BAN_IP):
                self.event_bus.publish("action.firewall", incident, sender=self.name)

            # 3. Trigger Alert Dispatch
            if action_plan.action_type != ActionType.IGNORE and detection.attack_type.upper() != "BENIGN":
                self.event_bus.publish("action.alert", incident, sender=self.name)

            # 4. Trigger Persistence Log
            self.event_bus.publish("action.log", incident, sender=self.name)

        return incident
