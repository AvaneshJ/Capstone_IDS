"""
SentinelAI - Unit & Integration Tests for HostSOARAgent (Capstone_IDS/soar)
"""

import os
import sys
import shutil
import logging
import tempfile
import subprocess
import unittest

import psutil
from pydantic import ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.host_agent import HostSOARAgent
from agents.alert_agent import AlertAgent
from agents.llm_agent import LLMExplanationAgent
from core.event_bus import Event
from core.orchestrator import SentinelOrchestrator
from core.schemas import HostActionType, SeverityLevel

CHROME_COOKIES = "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"


def stealer_event(**overrides):
    event = {
        "pid": 5892,
        "process_name": "python.exe",
        "parent_name": "cmd.exe",
        "cpu_percent": 8.1,
        "memory_mb": 72.0,
        "file_path": CHROME_COOKIES,
        "event_type": "READ",
    }
    event.update(overrides)
    return event


def offline_llm(orchestrator):
    """Force the expert-system fallback so tests never call Gemini/Ollama."""
    orchestrator.llm_agent.gemini_api_key = None
    orchestrator.llm_agent.ollama_endpoint = "http://127.0.0.1:9"


class TestHostSOARAgent(unittest.TestCase):
    """Test suite for Phase 5 HIDS Host SOAR Agent in Capstone_IDS/soar."""

    def setUp(self):
        self.agent = HostSOARAgent(dry_run=True)
        self.agent.initialize()

    def tearDown(self):
        self.agent.shutdown()

    def test_normal_browser_activity_logged_only(self):
        """Verify legitimate Chrome reading Cookies is classified Normal and LOG_ONLY."""
        event = {
            "pid": 11240,
            "process_name": "chrome.exe",
            "parent_name": "explorer.exe",
            "cpu_percent": 2.5,
            "memory_mb": 250.0,
            "file_path": CHROME_COOKIES,
            "file_type": "CookieDB",
            "event_type": "READ",
            "label": "Normal"
        }
        incident = self.agent.process_host_event(event)
        self.assertEqual(incident.classification, "Normal")
        self.assertEqual(incident.soar_action, HostActionType.LOG_ONLY)
        self.assertEqual(incident.severity, SeverityLevel.LOW)
        self.assertTrue(incident.risk_score < 4.0)

    def test_infostealer_detection_and_process_termination(self):
        """Verify unauthorized python.exe reading Chrome Cookies triggers Stealer and TERMINATE_PROCESS."""
        incident = self.agent.process_host_event(stealer_event(file_type="CookieDB", label="Stealer"))
        self.assertEqual(incident.classification, "Stealer")
        self.assertEqual(incident.soar_action, HostActionType.TERMINATE_PROCESS)
        self.assertIn("SIMULATED", incident.action_status)
        self.assertIn("5892", incident.action_status)
        self.assertEqual(incident.mitre_technique_id, "T1539")
        self.assertEqual(incident.mitre_technique_name, "Steal Web Session Cookie")
        self.assertEqual(incident.severity, SeverityLevel.CRITICAL)
        self.assertTrue(incident.risk_score >= 8.5)

    def test_local_state_master_key_theft(self):
        """Verify PowerShell accessing Local State triggers Credentials from Web Browsers (T1555.003)."""
        event = {
            "pid": 9410,
            "process_name": "powershell.exe",
            "parent_name": "cmd.exe",
            "cpu_percent": 12.0,
            "memory_mb": 85.0,
            "file_path": "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
            "file_type": "LocalState (Master Key)",
            "event_type": "READ"
        }
        incident = self.agent.process_host_event(event)
        self.assertEqual(incident.classification, "Stealer")
        self.assertEqual(incident.mitre_technique_id, "T1555.003")
        self.assertEqual(incident.soar_action, HostActionType.TERMINATE_PROCESS)

    def test_event_bus_envelope_is_unwrapped(self):
        """An Event delivered via process() must be classified on its payload, not as unknown.exe."""
        incident = self.agent.process(Event(topic="host.event.ingested", data=stealer_event()))
        self.assertEqual(incident.process.process_name, "python.exe")
        self.assertEqual(incident.classification, "Stealer")

    def test_ml_labels_are_preserved(self):
        """Ransomware / Malware labels from the HIDS model must not be collapsed into Stealer."""
        for label, expected in (("ransomware", "Ransomware"), ("Malware", "Malware"), ("InfoStealer", "Stealer")):
            incident = self.agent.process_host_event(stealer_event(label=label))
            self.assertEqual(incident.classification, expected)

    def test_ml_scores_are_used_when_provided(self):
        incident = self.agent.process_host_event(stealer_event(label="Stealer", confidence=0.61, anomaly_score=0.4))
        self.assertAlmostEqual(incident.confidence, 0.61)
        self.assertAlmostEqual(incident.anomaly_score, 0.4)

    def test_model_anomaly_without_file_is_never_terminated(self):
        event = stealer_event(label="Anomalous", anomaly_score=0.99, confidence=0.99, file_path="",
                              reasons=["It ran from a user folder."])
        incident = self.agent.process_host_event(event)
        self.assertEqual(incident.classification, "Anomalous")
        self.assertEqual(incident.soar_action, HostActionType.ALERT_ONLY)
        self.assertEqual(incident.severity, SeverityLevel.MEDIUM)
        self.assertLess(incident.risk_score, 7.0)
        self.assertIn("It ran from a user folder.", incident.reasons)

    def test_stealer_label_without_file_is_alert_only(self):
        incident = self.agent.process_host_event(stealer_event(label="Stealer", file_path=""))
        self.assertEqual(incident.soar_action, HostActionType.ALERT_ONLY)

    def test_model_anomaly_with_credential_file_is_stealer(self):
        incident = self.agent.process_host_event(stealer_event(label="Anomalous"))
        self.assertEqual(incident.classification, "Stealer")
        self.assertEqual(incident.soar_action, HostActionType.TERMINATE_PROCESS)
        self.assertTrue(any("Cookies" in r for r in incident.reasons))

    def test_unknown_label_falls_back_to_heuristics(self):
        incident = self.agent.process_host_event(stealer_event(process_name="chrome.exe", label="Suspicious"))
        self.assertEqual(incident.classification, "Normal")

    def test_missing_parent_is_unknown_not_explorer(self):
        event = stealer_event()
        del event["parent_name"]
        incident = self.agent.process_host_event(event)
        self.assertEqual(incident.process.parent_name, "")


class TestLiveTerminationSafety(unittest.TestCase):
    """Live (non dry-run) termination must verify the PID still belongs to the reported process."""

    def setUp(self):
        self.agent = HostSOARAgent(dry_run=False)
        self.agent.initialize()
        self.proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        live = psutil.Process(self.proc.pid)
        self.real_name = live.name().lower()
        self.real_exe = live.exe()

    def tearDown(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=5)
        self.agent.shutdown()

    def test_identity_mismatch_refuses_to_kill(self):
        incident = self.agent.process_host_event(stealer_event(pid=self.proc.pid, process_name="notepad.exe"))
        self.assertIn("SKIPPED", incident.action_status)
        self.assertIsNone(self.proc.poll(), "unrelated process must still be running")

    def test_exe_path_mismatch_refuses_to_kill(self):
        incident = self.agent.process_host_event(stealer_event(
            pid=self.proc.pid,
            process_name=self.real_name,
            exe_path="C:\\Users\\Public\\Downloads\\" + self.real_name,
        ))
        self.assertIn("SKIPPED", incident.action_status)
        self.assertIsNone(self.proc.poll())

    def test_matching_identity_is_terminated(self):
        incident = self.agent.process_host_event(stealer_event(
            pid=self.proc.pid,
            process_name=self.real_name,
            exe_path=self.real_exe,
        ))
        self.assertIn("SUCCESS", incident.action_status)
        self.assertIsNotNone(self.proc.wait(timeout=5))
        self.assertEqual(self.agent.total_processes_killed, 1)

    def test_exited_process_is_not_reported_as_killed(self):
        self.proc.kill()
        self.proc.wait(timeout=5)
        incident = self.agent.process_host_event(stealer_event(pid=self.proc.pid, process_name=self.real_name))
        self.assertIn("ALREADY_EXITED", incident.action_status)
        self.assertEqual(self.agent.total_processes_killed, 0)


class TestHostResponseChannels(unittest.TestCase):
    """Host incidents reach the alert channels and get a plain-language briefing."""

    def setUp(self):
        self.agent = HostSOARAgent(dry_run=True)
        self.agent.initialize()
        self.incident = self.agent.process_host_event(stealer_event())

    def tearDown(self):
        self.agent.shutdown()

    def test_host_alert_is_tagged_and_queued_for_dashboard(self):
        alerts = AlertAgent(enable_desktop=False, enable_console=False)
        alert = alerts.dispatch_host_alert(self.incident)
        self.assertEqual(alert.source, "HIDS")
        self.assertEqual(alert.attack_type, "Stealer")
        self.assertIn("python.exe", alert.message)
        self.assertEqual(alerts.dashboard_queue.get_nowait()["source"], "HIDS")

    def test_host_expert_briefing(self):
        llm = LLMExplanationAgent()
        briefing = llm._generate_host_expert_briefing(self.incident)
        self.assertIn("python.exe", briefing.summary)
        self.assertIn("T1539", briefing.mitre_context)
        self.assertTrue(briefing.soc_recommendations)


class TestOrchestratorHostPipeline(unittest.TestCase):
    """End-to-end host pipeline through SentinelOrchestrator."""

    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)
        cls.tmp = tempfile.mkdtemp()
        cls.orch = SentinelOrchestrator(
            db_path=os.path.join(cls.tmp, "test.db"),
            enable_desktop_alerts=False,
            enable_console_alerts=False,
        )
        offline_llm(cls.orch)
        cls.orch.report_agent.reports_dir = cls.tmp
        cls.orch.initialize()

    @classmethod
    def tearDownClass(cls):
        cls.orch.shutdown()
        logging.disable(logging.NOTSET)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_host_dry_run_is_independent_of_firewall(self):
        orch = SentinelOrchestrator(db_path=os.path.join(self.tmp, "flags.db"), dry_run_firewall=False)
        self.assertTrue(orch.host_agent.dry_run)
        self.assertFalse(orch.firewall_agent.dry_run)

    def test_threat_is_alerted_explained_and_persisted(self):
        incident = self.orch.process_host_event(stealer_event(pid=7001))
        self.assertIsNotNone(incident.alert)
        self.assertIsNotNone(incident.llm_explanation)
        stored = [r for r in self.orch.db_manager.get_recent_host_incidents() if r["pid"] == 7001]
        self.assertEqual(len(stored), 1)

    def test_normal_event_is_not_alerted(self):
        incident = self.orch.process_host_event(stealer_event(pid=7002, process_name="chrome.exe"))
        self.assertIsNone(incident.alert)
        self.assertIsNone(incident.llm_explanation)

    def test_event_bus_publish_runs_full_pipeline(self):
        self.orch.event_bus.publish("host.event.ingested", stealer_event(pid=7003), sender="test")
        stored = [r for r in self.orch.db_manager.get_recent_host_incidents() if r["pid"] == 7003]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["process_name"], "python.exe")
        self.assertEqual(stored[0]["classification"], "Stealer")

    def test_summary_report_includes_host_section(self):
        self.orch.process_host_event(stealer_event(pid=7004))
        path = self.orch.report_agent.generate_soc_summary_pdf()
        self.assertTrue(path.endswith(".pdf"), "PDF generation fell back to markdown")
        self.assertTrue(os.path.exists(path))


class TestHostIngestApiModel(unittest.TestCase):
    """The ingest API must not invent a PID, process, file or ML verdict."""

    def test_empty_payload_is_rejected(self):
        from api.server import HostEventIngestRequest
        with self.assertRaises(ValidationError):
            HostEventIngestRequest()

    def test_minimal_payload_has_no_preset_label(self):
        from api.server import HostEventIngestRequest
        req = HostEventIngestRequest(pid=1234, process_name="python.exe", file_path=CHROME_COOKIES)
        payload = req.model_dump(exclude_none=True)
        self.assertNotIn("label", payload)
        self.assertNotIn("parent_name", payload)


if __name__ == "__main__":
    unittest.main()
