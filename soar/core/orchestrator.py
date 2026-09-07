"""
SentinelAI - Master Orchestrator
Coordinates and manages the complete lifecycle, communication pipeline, and execution
of all 11 specialist agents in the SentinelAI SOAR system.
"""

from __future__ import annotations
import os
import time
import queue
import logging
import threading
import psutil
from typing import Dict, List, Any, Optional, Union

from core.event_bus import EventBus, Event
from core.schemas import Incident, FlowEvent, SystemMetrics, AgentStatus
from database.db_manager import DatabaseManager
from rules.policy_engine import PolicyEngine

from agents.packet_agent import PacketAgent
from agents.detection_agent import DetectionAgent
from agents.threat_agent import ThreatAnalysisAgent
from agents.risk_agent import RiskAssessmentAgent
from agents.decision_agent import DecisionAgent
from agents.firewall_agent import FirewallAgent
from agents.alert_agent import AlertAgent
from agents.logging_agent import LoggingAgent
from agents.report_agent import ReportAgent
from agents.llm_agent import LLMExplanationAgent

logger = logging.getLogger("SentinelAI.Orchestrator")


class SentinelOrchestrator:
    """
    Master Multi-Agent Coordinator for SentinelAI.
    Manages the lifecycle of all 11 agents, binds event topics, and exposes
    clean contract interfaces for Member 1 (ML), Member 2 (Sniffer), and Member 4 (Dashboard).
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        policy_path: Optional[str] = None,
        model_path: Optional[str] = None,
        dry_run_firewall: bool = True,
        enable_desktop_alerts: bool = True,
        gemini_api_key: Optional[str] = None
    ):
        self.start_time = time.time()
        self.event_bus = EventBus()
        self.db_manager = DatabaseManager(db_path=db_path) if db_path else DatabaseManager()
        self.policy_engine = PolicyEngine(policy_path=policy_path) if policy_path else PolicyEngine()

        # Telemetry counters
        self.total_flows_processed: int = 0
        self.total_threats_detected: int = 0
        self.total_blocks_executed: int = 0

        # Background metrics thread
        self._stop_event = threading.Event()
        self._metrics_thread: Optional[threading.Thread] = None

        # Instantiate all 11 specialist agents
        self.packet_agent = PacketAgent(event_bus=self.event_bus)
        self.detection_agent = DetectionAgent(model_path=model_path, event_bus=self.event_bus)
        self.threat_agent = ThreatAnalysisAgent(policy_engine=self.policy_engine, event_bus=self.event_bus)
        self.risk_agent = RiskAssessmentAgent(policy_engine=self.policy_engine, event_bus=self.event_bus)
        self.decision_agent = DecisionAgent(policy_engine=self.policy_engine, event_bus=self.event_bus)
        self.firewall_agent = FirewallAgent(db_manager=self.db_manager, dry_run=dry_run_firewall, event_bus=self.event_bus)
        self.alert_agent = AlertAgent(enable_desktop=enable_desktop_alerts, event_bus=self.event_bus)
        self.logging_agent = LoggingAgent(db_manager=self.db_manager, event_bus=self.event_bus)
        self.report_agent = ReportAgent(db_manager=self.db_manager, event_bus=self.event_bus)
        self.llm_agent = LLMExplanationAgent(gemini_api_key=gemini_api_key, event_bus=self.event_bus)

        self.agents = [
            self.packet_agent,
            self.detection_agent,
            self.threat_agent,
            self.risk_agent,
            self.decision_agent,
            self.firewall_agent,
            self.alert_agent,
            self.logging_agent,
            self.report_agent,
            self.llm_agent,
        ]

    def initialize(self) -> None:
        """Initialize all 11 specialist agents and bind pub/sub event subscriptions."""
        logger.info("Initializing SentinelAI Multi-Agent System...")
        
        for agent in self.agents:
            agent.initialize()

        # Start periodic telemetry collector thread
        self._stop_event.clear()
        self._metrics_thread = threading.Thread(
            target=self._metrics_collector_loop,
            name="SentinelAI-MetricsCollector",
            daemon=True
        )
        self._metrics_thread.start()
        logger.info("All 11 SentinelAI Agents initialized and operational.")

    def process_flow(self, raw_flow: Dict[str, Any]) -> Incident:
        """
        End-to-End synchronous pipeline execution for a single network flow.
        Flow -> PacketAgent -> DetectionAgent -> ThreatAgent -> RiskAgent -> DecisionAgent
             -> [FirewallAgent, AlertAgent, LoggingAgent, LLMAgent]
        """
        self.total_flows_processed += 1

        # 1. Ingest & Validate
        flow = self.packet_agent.sanitize_flow(raw_flow)

        # 2. ML Inference / Anomaly Detection
        detection = self.detection_agent.predict(flow)
        if detection.attack_type.upper() != "BENIGN":
            self.total_threats_detected += 1

        # 3. Deep Forensic Threat Analysis
        threat = self.threat_agent.analyze_threat(flow, detection)

        # 4. Multi-Factor Risk Assessment
        risk = self.risk_agent.calculate_risk(flow, detection)

        # 5. SOAR Response Planning & Incident Generation
        incident = self.decision_agent.decide_and_plan(flow, detection, threat, risk)

        # 6. Autonomous Enforcement & Mitigation
        if incident.action_plan.action_type.value in ("BLOCK_IP", "TEMP_BAN_IP"):
            self.total_blocks_executed += 1
            rule = self.firewall_agent.block_ip(
                target_ip=flow.src_ip,
                duration_seconds=incident.action_plan.ban_duration_seconds,
                reason=f"Auto-mitigating {detection.attack_type} (Risk {risk.score}/10)"
            )
            incident.firewall_rule = rule

        # 7. Notifications & Alerts
        if detection.attack_type.upper() != "BENIGN" and incident.action_plan.action_type.value != "IGNORE":
            alert = self.alert_agent.dispatch_alert(incident)
            incident.alert = alert

        # 8. GenAI SOC Analyst Briefing (for elevated threats)
        if detection.attack_type.upper() != "BENIGN" or risk.score >= 4.0:
            explanation = self.llm_agent.generate_briefing(incident)
            incident.llm_explanation = explanation

        # 9. Persistence & Audit Logging
        self.logging_agent.process(Event(topic="action.log", data=incident))

        return incident

    def process_batch(self, raw_flows: List[Dict[str, Any]]) -> List[Incident]:
        """Process a collection of network flow dictionaries."""
        return [self.process_flow(f) for f in raw_flows]

    def run_queue_listener(self, flow_queue: Any, stop_event: Optional[threading.Event] = None) -> None:
        """
        Continuously drain incoming flows from Member 2's packet sniffer queue.
        Supports standard Python queue.Queue, multiprocessing.Queue, or iterable.
        """
        logger.info("Listening for live network flow stream from Member 2...")
        while stop_event is None or not stop_event.is_set():
            try:
                flow_dict = flow_queue.get(timeout=1.0)
                if flow_dict is None:  # Sentinel stop token
                    break
                self.process_flow(flow_dict)
            except (queue.Empty, TimeoutError):
                continue
            except Exception as exc:
                logger.error("Error processing queue flow: %s", exc)

    def get_system_metrics(self) -> SystemMetrics:
        """Collect current system telemetry snapshot."""
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        active_bans = len(self.db_manager.get_active_blocks())
        
        agent_statuses = {agent.name: agent.status.value for agent in self.agents}

        return SystemMetrics(
            timestamp=time.time(),
            total_flows=self.total_flows_processed,
            total_threats=self.total_threats_detected,
            total_blocked_ips=self.total_blocks_executed,
            total_alerts=self.alert_agent.total_processed,
            active_firewall_rules=active_bans,
            cpu_percent=cpu,
            memory_percent=mem,
            uptime_seconds=round(time.time() - self.start_time, 1),
            agent_statuses=agent_statuses
        )

    def _metrics_collector_loop(self) -> None:
        """Background thread recording periodic metrics into SQLite."""
        while not self._stop_event.is_set():
            try:
                metrics = self.get_system_metrics()
                self.db_manager.save_system_metrics(metrics)
            except Exception as exc:
                logger.debug("Metrics collection exception: %s", exc)

            self._stop_event.wait(10.0)

    def shutdown(self) -> None:
        """Gracefully shut down all agents and background threads."""
        logger.info("Shutting down SentinelAI Multi-Agent System...")
        self._stop_event.set()
        
        if self._metrics_thread and self._metrics_thread.is_alive():
            self._metrics_thread.join(timeout=2.0)

        for agent in self.agents:
            agent.shutdown()

        logger.info("All SentinelAI agents shut down successfully.")
