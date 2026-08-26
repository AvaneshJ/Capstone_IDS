"""
SentinelAI - Multi-Agent & SOAR Unit and Integration Test Suite
Validates each individual specialist agent, policy engine, database operations,
forensic evidence extraction, risk formulas, firewall dry-run, and end-to-end pipeline.
"""

import os
import time
import math
import shutil
import tempfile
import unittest

from core.event_bus import EventBus, Event
from core.schemas import (
    FlowEvent,
    DetectionResult,
    ThreatEvidence,
    RiskScoreResult,
    ActionPlan,
    Incident,
    SeverityLevel,
    ActionType
)
from core.orchestrator import SentinelOrchestrator
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

from tests.mock_traffic import (
    generate_benign_flow,
    generate_port_scan_flow,
    generate_ddos_flow,
    generate_brute_force_flow,
    generate_botnet_flow
)


class TestSentinelAIPipeline(unittest.TestCase):
    """Comprehensive test cases for SentinelAI Multi-Agent SOAR system."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.test_dir, "test_sentinel.db")
        self.test_reports_dir = os.path.join(self.test_dir, "reports")
        self.db_manager = DatabaseManager(db_path=self.test_db_path)
        self.policy_engine = PolicyEngine()
        self.event_bus = EventBus()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------
    # 1. Event Bus Tests
    # -------------------------------------------------------------
    def test_event_bus_pub_sub(self):
        received = []

        def handler(event: Event):
            received.append(event.data)

        self.event_bus.subscribe("test.topic", handler, priority=1, agent_name="test_agent")
        self.event_bus.publish("test.topic", {"msg": "hello_world"}, sender="tester")

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["msg"], "hello_world")
        self.assertEqual(self.event_bus.metrics["total_events_published"], 1)

    def test_event_bus_error_isolation(self):
        def buggy_handler(event: Event):
            raise ValueError("Intentional handler bug")

        received = []
        def good_handler(event: Event):
            received.append(event.data)

        self.event_bus.subscribe("test.bug", buggy_handler, priority=1, agent_name="buggy")
        self.event_bus.subscribe("test.bug", good_handler, priority=2, agent_name="good")

        self.event_bus.publish("test.bug", "payload")
        self.assertEqual(len(received), 1)
        self.assertEqual(self.event_bus.metrics["total_handler_errors"], 1)
        self.assertEqual(len(self.event_bus.get_dead_letters()), 1)

    # -------------------------------------------------------------
    # 2. Packet Ingest Agent Tests
    # -------------------------------------------------------------
    def test_packet_agent_sanitization(self):
        agent = PacketAgent(event_bus=self.event_bus)
        agent.initialize()

        raw_dirty = {
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.10",
            "src_port": "45000",
            "dst_port": "80",
            "flow_duration": "0.15",
            "flow_bytes_s": float("nan"),      # Test NaN handling
            "flow_pkts_s": float("inf"),       # Test Inf handling
            "syn_flag_count": "5",
            "ack_flag_count": None             # Test None handling
        }

        flow = agent.sanitize_flow(raw_dirty)
        self.assertEqual(flow.src_ip, "192.168.1.50")
        self.assertEqual(flow.dst_port, 80)
        self.assertEqual(flow.flow_bytes_s, 0.0)  # Replaced NaN
        self.assertEqual(flow.flow_pkts_s, 0.0)   # Replaced Inf
        self.assertEqual(flow.syn_flag_count, 5)
        self.assertEqual(flow.ack_flag_count, 0)

    # -------------------------------------------------------------
    # 3. Detection Agent Tests
    # -------------------------------------------------------------
    def test_detection_agent_heuristic_and_ml(self):
        agent = DetectionAgent(event_bus=self.event_bus)
        agent.initialize()

        # Port Scan Flow
        scan_raw = generate_port_scan_flow(src_ip="192.168.1.50", target_port=80)
        flow_scan = FlowEvent(**scan_raw)
        det_scan = agent.predict(flow_scan)
        self.assertEqual(det_scan.attack_type, "PortScan")
        self.assertTrue(det_scan.confidence > 0.70)
        self.assertTrue(det_scan.is_anomaly)

        # Benign Flow
        benign_raw = generate_benign_flow()
        flow_benign = FlowEvent(**benign_raw)
        det_benign = agent.predict(flow_benign)
        self.assertEqual(det_benign.attack_type, "BENIGN")
        self.assertFalse(det_benign.is_anomaly)

        # Volumetric DDoS Flow
        ddos_raw = generate_ddos_flow()
        flow_ddos = FlowEvent(**ddos_raw)
        det_ddos = agent.predict(flow_ddos)
        self.assertEqual(det_ddos.attack_type, "DDoS")
        self.assertTrue(det_ddos.confidence > 0.80)

    # -------------------------------------------------------------
    # 4. Threat Analysis Agent Tests
    # -------------------------------------------------------------
    def test_threat_agent_evidence_and_mitre(self):
        agent = ThreatAnalysisAgent(policy_engine=self.policy_engine, event_bus=self.event_bus)
        agent.initialize()

        flow = FlowEvent(src_ip="192.168.1.50", dst_port=80, syn_flag_count=5, flow_pkts_s=150.0)
        detection = DetectionResult(attack_type="PortScan", confidence=0.95, is_anomaly=True)

        evidence = agent.analyze_threat(flow, detection)
        self.assertEqual(evidence.mitre_technique_id, "T1046")
        self.assertEqual(evidence.mitre_technique_name, "Network Service Discovery")
        self.assertEqual(evidence.mitre_tactic, "Discovery")
        self.assertTrue(len(evidence.indicators) >= 2)
        self.assertIn("SYN", evidence.anomaly_explanation)

    # -------------------------------------------------------------
    # 5. Risk Assessment Agent Tests
    # -------------------------------------------------------------
    def test_risk_agent_multi_factor_calculation(self):
        agent = RiskAssessmentAgent(policy_engine=self.policy_engine, sliding_window_seconds=60.0, event_bus=self.event_bus)
        agent.initialize()

        flow = FlowEvent(src_ip="192.168.1.50", dst_ip="192.168.1.10", dst_port=3306) # MySQL sensitive port
        detection = DetectionResult(attack_type="DDoS", confidence=0.90, is_anomaly=True)

        # First event
        risk1 = agent.calculate_risk(flow, detection)
        # Base: 9.0 * 0.9 = 8.1. Target sensitivity (MySQL 3306 + critical subnet): 1.5 + 1.0 = 2.5. Total clamped to 10.0
        self.assertEqual(risk1.severity, SeverityLevel.CRITICAL)
        self.assertTrue(risk1.score >= 8.5)

        # Benign test
        flow_b = FlowEvent(src_ip="192.168.1.105", dst_ip="8.8.8.8", dst_port=53)
        det_b = DetectionResult(attack_type="BENIGN", confidence=0.98, is_anomaly=False)
        risk_b = agent.calculate_risk(flow_b, det_b)
        self.assertEqual(risk_b.severity, SeverityLevel.LOW)
        self.assertTrue(risk_b.score < 2.0)

    # -------------------------------------------------------------
    # 6. Decision & Response Planning Agent Tests
    # -------------------------------------------------------------
    def test_decision_agent_thresholds_and_whitelist(self):
        agent = DecisionAgent(policy_engine=self.policy_engine, event_bus=self.event_bus)
        agent.initialize()

        # 1. Whitelist Test (127.0.0.1 should NEVER be blocked)
        flow_white = FlowEvent(src_ip="127.0.0.1", dst_port=80)
        det_white = DetectionResult(attack_type="DDoS", confidence=0.99)
        threat_white = ThreatEvidence()
        risk_white = RiskScoreResult(score=9.5, severity=SeverityLevel.CRITICAL)

        incident_white = agent.decide_and_plan(flow_white, det_white, threat_white, risk_white)
        self.assertEqual(incident_white.action_plan.action_type, ActionType.IGNORE)
        self.assertIn("whitelist", incident_white.action_plan.rationale.lower())

        # 2. Critical Threat -> BLOCK_IP
        flow_crit = FlowEvent(src_ip="198.51.100.99", dst_port=80)
        det_crit = DetectionResult(attack_type="DDoS", confidence=0.95)
        threat_crit = ThreatEvidence()
        risk_crit = RiskScoreResult(score=9.0, severity=SeverityLevel.CRITICAL)

        incident_crit = agent.decide_and_plan(flow_crit, det_crit, threat_crit, risk_crit)
        self.assertEqual(incident_crit.action_plan.action_type, ActionType.BLOCK_IP)
        self.assertEqual(incident_crit.action_plan.priority, 5)

        # 3. Medium Threat -> TEMP_BAN_IP
        risk_med = RiskScoreResult(score=5.5, severity=SeverityLevel.MEDIUM)
        incident_med = agent.decide_and_plan(flow_crit, det_crit, threat_crit, risk_med)
        self.assertEqual(incident_med.action_plan.action_type, ActionType.TEMP_BAN_IP)

    # -------------------------------------------------------------
    # 7. Firewall Agent Tests (Dry-Run Mode)
    # -------------------------------------------------------------
    def test_firewall_agent_dry_run_and_unblock(self):
        agent = FirewallAgent(db_manager=self.db_manager, dry_run=True, event_bus=self.event_bus)
        agent.initialize()

        rule = agent.block_ip(target_ip="192.168.1.50", duration_seconds=10, reason="Test PortScan Block")
        self.assertEqual(rule.target_ip, "192.168.1.50")
        self.assertEqual(rule.status, "SIMULATED")
        self.assertIn("192.168.1.50", rule.command_executed)

        # Verify recorded in DB
        active_blocks = self.db_manager.get_active_blocks()
        self.assertEqual(len(active_blocks), 1)
        self.assertEqual(active_blocks[0]["ip_address"], "192.168.1.50")

        # Unblock test
        unblocked = agent.unblock_ip(rule.rule_id)
        self.assertTrue(unblocked)
        
        # Verify status updated
        active_after = self.db_manager.get_active_blocks()
        self.assertEqual(len(active_after), 0)
        agent.shutdown()

    # -------------------------------------------------------------
    # 8. Database Persistence Tests
    # -------------------------------------------------------------
    def test_database_manager_operations(self):
        flow = FlowEvent(src_ip="10.0.0.50", dst_ip="192.168.1.10", dst_port=22)
        det = DetectionResult(attack_type="BruteForce", confidence=0.92)
        threat = ThreatEvidence(mitre_technique_id="T1110", mitre_technique_name="Brute Force")
        risk = RiskScoreResult(score=7.8, severity=SeverityLevel.HIGH)
        plan = ActionPlan(action_type=ActionType.TEMP_BAN_IP, rule_matched="threshold_high")

        incident = Incident(flow=flow, detection=det, threat=threat, risk=risk, action_plan=plan)
        saved = self.db_manager.save_incident(incident)
        self.assertTrue(saved)

        # Query back
        recent = self.db_manager.get_recent_incidents(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["src_ip"], "10.0.0.50")
        self.assertEqual(recent[0]["attack_type"], "BruteForce")

        # Top offenders query
        offenders = self.db_manager.get_top_offending_ips(limit=5)
        self.assertEqual(len(offenders), 1)
        self.assertEqual(offenders[0]["src_ip"], "10.0.0.50")

    # -------------------------------------------------------------
    # 9. Report Agent Tests (PDF Generation)
    # -------------------------------------------------------------
    def test_report_agent_pdf_generation(self):
        report_agent = ReportAgent(db_manager=self.db_manager, reports_dir=self.test_reports_dir, event_bus=self.event_bus)
        report_agent.initialize()

        flow = FlowEvent(src_ip="192.168.1.50", dst_port=80, syn_flag_count=6, flow_pkts_s=200.0)
        det = DetectionResult(attack_type="PortScan", confidence=0.98)
        threat = ThreatEvidence(
            indicators=["Rapid SYN sweep", "Zero ACK responses"],
            anomaly_explanation="Rapid SYN port scan observed",
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery",
            mitre_tactic="Discovery"
        )
        risk = RiskScoreResult(score=8.8, severity=SeverityLevel.CRITICAL)
        plan = ActionPlan(action_type=ActionType.BLOCK_IP, rule_matched="threshold_critical")
        incident = Incident(flow=flow, detection=det, threat=threat, risk=risk, action_plan=plan)

        self.db_manager.save_incident(incident)

        # 1. Incident PDF
        pdf_path = report_agent.generate_incident_pdf(incident, "test_incident.pdf")
        self.assertTrue(os.path.exists(pdf_path))
        self.assertTrue(os.path.getsize(pdf_path) > 500)

        # 2. SOC Summary PDF
        summary_pdf = report_agent.generate_soc_summary_pdf("test_summary.pdf")
        self.assertTrue(os.path.exists(summary_pdf))
        self.assertTrue(os.path.getsize(summary_pdf) > 500)

    # -------------------------------------------------------------
    # 10. LLM Explanation Agent Tests
    # -------------------------------------------------------------
    def test_llm_explanation_expert_fallback(self):
        llm_agent = LLMExplanationAgent(event_bus=self.event_bus)
        llm_agent.initialize()

        incident = Incident(
            flow=FlowEvent(src_ip="192.168.1.50", dst_port=80, syn_flag_count=5),
            detection=DetectionResult(attack_type="PortScan", confidence=0.98),
            threat=ThreatEvidence(mitre_technique_id="T1046", mitre_technique_name="Network Service Discovery"),
            risk=RiskScoreResult(score=8.8, severity=SeverityLevel.CRITICAL),
            action_plan=ActionPlan(action_type=ActionType.BLOCK_IP)
        )

        briefing = llm_agent.generate_briefing(incident)
        self.assertIsNotNone(briefing)
        self.assertIn("192.168.1.50", briefing.summary)
        self.assertIn("T1046", briefing.mitre_context)
        self.assertTrue(len(briefing.soc_recommendations) >= 2)

    # -------------------------------------------------------------
    # 11. End-to-End Orchestrator Pipeline Test
    # -------------------------------------------------------------
    def test_end_to_end_orchestrator_flow(self):
        orchestrator = SentinelOrchestrator(
            db_path=self.test_db_path,
            dry_run_firewall=True,
            enable_desktop_alerts=False
        )
        orchestrator.initialize()

        # Ingest PortScan Flow
        scan_flow_dict = generate_port_scan_flow(src_ip="192.168.1.50", target_port=80)
        incident = orchestrator.process_flow(scan_flow_dict)

        # Assert full choreography
        self.assertEqual(incident.detection.attack_type, "PortScan")
        self.assertTrue(incident.risk.score >= 5.0)
        self.assertIn(incident.action_plan.action_type, (ActionType.BLOCK_IP, ActionType.TEMP_BAN_IP))
        self.assertIsNotNone(incident.firewall_rule)
        self.assertIsNotNone(incident.alert)
        self.assertIsNotNone(incident.llm_explanation)

        # Check DB
        db_incidents = orchestrator.db_manager.get_recent_incidents(limit=5)
        self.assertEqual(len(db_incidents), 1)
        self.assertEqual(db_incidents[0]["src_ip"], "192.168.1.50")

        # Check telemetry
        metrics = orchestrator.get_system_metrics()
        self.assertEqual(metrics.total_flows, 1)
        self.assertEqual(metrics.total_threats, 1)
        self.assertEqual(metrics.total_blocked_ips, 1)

        orchestrator.shutdown()


if __name__ == "__main__":
    unittest.main()
