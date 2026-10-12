"""
Tests for host false-positive handling: program trust (hids/trust.py), how the live monitor and
host agent apply it, and the trust / terminate API.
Run from repo root:  python -m pytest soar/tests/test_trust.py -q

Signature checks are patched, so no PowerShell call is made.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import security  # noqa: E402
from core.live_monitor import LiveMonitor  # noqa: E402
from core.schemas import HostIncident, HostProcessInfo, SeverityLevel  # noqa: E402
from agents.host_agent import HostSOARAgent  # noqa: E402
from database.db_manager import DatabaseManager  # noqa: E402
from hids import trust  # noqa: E402

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
PROTECTED_EXE = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Vendor", "helper.exe")
LOGIN_DATA = r"C:\Users\Lab\AppData\Local\Google\Chrome\User Data\Default\Login Data"
SIGNED = trust.Signature("valid", "Vendor Inc.", "AB12")
UNSIGNED = trust.Signature("unsigned")


class _TempDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.exe = os.path.join(self.tmp, "tool.exe")
        with open(self.exe, "wb") as f:
            f.write(b"MZ fake binary")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestEvaluate(_TempDir):

    def test_signed_in_protected_folder_is_trusted_vendor(self):
        with mock.patch.object(trust, "signature", return_value=SIGNED):
            verdict = trust.evaluate(PROTECTED_EXE)
        self.assertEqual(verdict.level, trust.TRUSTED_VENDOR)
        self.assertEqual(verdict.publisher, "Vendor Inc.")

    def test_signed_in_user_folder_stays_unverified(self):
        with mock.patch.object(trust, "signature", return_value=SIGNED):
            self.assertEqual(trust.evaluate(self.exe).level, trust.UNVERIFIED)

    def test_unsigned_in_protected_folder_stays_unverified(self):
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            verdict = trust.evaluate(PROTECTED_EXE)
        self.assertEqual(verdict.level, trust.UNVERIFIED)
        self.assertIn("Not digitally signed", verdict.reason)

    def test_hash_rule_matches_only_the_exact_file(self):
        rules = [{"id": 1, "kind": "hash", "value": trust.file_sha256(self.exe)}]
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            self.assertEqual(trust.evaluate(self.exe, rules).level, trust.ALLOWED)
            with open(self.exe, "ab") as f:
                f.write(b"tampered")
            os.utime(self.exe, ns=(1, 2))
            self.assertEqual(trust.evaluate(self.exe, rules).level, trust.UNVERIFIED)

    def test_code_runners_never_earn_trust(self):
        ps = os.path.join(WINDIR, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        rules = [{"id": 3, "kind": "publisher", "value": "Microsoft Windows"}]
        with mock.patch.object(trust, "signature", return_value=trust.Signature("valid", "Microsoft Windows")):
            self.assertEqual(trust.evaluate(ps, rules).level, trust.UNVERIFIED)
            rule, why = trust.rule_for(ps)
        self.assertIsNone(rule)
        self.assertIn("runs scripts", why)

    def test_platform_publisher_falls_back_to_file_hash(self):
        with mock.patch.object(trust, "signature", return_value=trust.Signature("valid", "Microsoft Windows")):
            rule, _ = trust.rule_for(self.exe, "auto")
            self.assertEqual(rule["kind"], "hash")
            self.assertIsNone(trust.rule_for(self.exe, "publisher")[0])
            rules = [{"id": 4, "kind": "publisher", "value": "Microsoft Windows"}]
            self.assertEqual(trust.evaluate(self.exe, rules).level, trust.UNVERIFIED)

    def test_publisher_rule_needs_a_valid_signature(self):
        rules = [{"id": 2, "kind": "publisher", "value": "vendor inc."}]
        with mock.patch.object(trust, "signature", return_value=SIGNED):
            self.assertEqual(trust.evaluate(self.exe, rules).level, trust.ALLOWED)
        with mock.patch.object(trust, "signature", return_value=trust.Signature("invalid", "Vendor Inc.")):
            self.assertEqual(trust.evaluate(self.exe, rules).level, trust.UNVERIFIED)


class TestHostAgentTrust(unittest.TestCase):

    def setUp(self):
        self.agent = HostSOARAgent(dry_run=True)

    def _event(self, level):
        return {"pid": 4242, "process_name": "helper.exe", "exe_path": PROTECTED_EXE, "file_path": LOGIN_DATA,
                "trust": {"level": level, "publisher": "Vendor Inc.", "reason": "Signed by Vendor Inc."}}

    def test_trusted_vendor_is_downgraded_and_not_stopped(self):
        inc = self.agent.process_host_event(self._event(trust.TRUSTED_VENDOR))
        self.assertEqual(inc.classification, "TrustedAccess")
        self.assertEqual(inc.severity, SeverityLevel.LOW)
        self.assertLessEqual(inc.risk_score, 3.5)
        self.assertEqual(inc.soar_action.value, "ALERT_ONLY")
        self.assertTrue(any("Vendor Inc." in r for r in inc.reasons))

    def test_unverified_keeps_full_severity(self):
        inc = self.agent.process_host_event(self._event(trust.UNVERIFIED))
        self.assertEqual(inc.classification, "Stealer")
        self.assertIn(inc.severity, (SeverityLevel.HIGH, SeverityLevel.CRITICAL))
        self.assertEqual(inc.soar_action.value, "TERMINATE_PROCESS")

    def test_user_terminate_refuses_system_and_checks_identity(self):
        self.assertEqual(self.agent.terminate_process(HostProcessInfo(pid=4, process_name="system"))[0], "REFUSED")
        outcome, _ = self.agent.terminate_process(HostProcessInfo(pid=os.getppid(), process_name="definitely-not-this.exe"))
        self.assertIn(outcome, ("IDENTITY_MISMATCH", "REFUSED", "FAILED"))


class TestLiveMonitorTrust(_TempDir):

    def setUp(self):
        super().setUp()
        self.rules = []
        self.sent = []
        orch = SimpleNamespace(
            db_manager=SimpleNamespace(get_trusted_programs=lambda: list(self.rules)),
            firewall_agent=SimpleNamespace(dry_run=True), host_agent=SimpleNamespace(dry_run=True),
            process_host_event=self._host,
        )
        self.mon = LiveMonitor(orch)

    def _host(self, event):
        self.sent.append(event)
        return SimpleNamespace(classification="Stealer", soar_action=SimpleNamespace(value="ALERT_ONLY"), to_dict=lambda: {})

    def test_allowed_program_is_suppressed(self):
        self.rules.append({"id": 1, "kind": "hash", "value": trust.file_sha256(self.exe)})
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            self.mon._send_host_event({"process_name": "tool.exe", "exe_path": self.exe, "file_path": LOGIN_DATA})
            self.mon._send_host_event({"process_name": "tool.exe", "exe_path": self.exe})
        self.assertEqual(self.sent, [])
        self.assertEqual(self.mon.host_stats["allowed_by_you"], 2)

    def test_rules_reload_after_change(self):
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            self.mon._send_host_event({"process_name": "tool.exe", "exe_path": self.exe, "file_path": LOGIN_DATA})
            self.rules.append({"id": 1, "kind": "hash", "value": trust.file_sha256(self.exe)})
            self.mon.reload_trust_rules()
            self.mon._send_host_event({"process_name": "tool.exe", "exe_path": self.exe, "file_path": LOGIN_DATA})
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["trust"]["level"], trust.UNVERIFIED)

    def test_trusted_vendor_reported_once_per_day_per_file_kind(self):
        event = {"process_name": "helper.exe", "exe_path": PROTECTED_EXE, "file_path": LOGIN_DATA, "file_type": "Saved Passwords DB"}
        with mock.patch.object(trust, "signature", return_value=SIGNED):
            self.mon._send_host_event(dict(event))
            self.mon._send_host_event(dict(event))
            self.mon._send_host_event({**event, "file_type": "CookieDB"})
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[0]["trust"]["level"], trust.TRUSTED_VENDOR)

    def test_unverified_credential_access_always_reported(self):
        event = {"process_name": "tool.exe", "exe_path": self.exe, "file_path": LOGIN_DATA}
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            self.mon._send_host_event(dict(event))
            self.mon._send_host_event(dict(event))
        self.assertEqual(len(self.sent), 2)


class TestTrustApi(_TempDir):

    def setUp(self):
        super().setUp()
        self._old = os.environ.get("SENTINEL_DATA_DIR")
        os.environ["SENTINEL_DATA_DIR"] = os.path.join(self.tmp, "data")
        from fastapi.testclient import TestClient
        import api.server as server

        self.server = server
        self.db = DatabaseManager(db_path=os.path.join(self.tmp, "trust.db"))
        self.terminated = []
        server.orchestrator = SimpleNamespace(
            db_manager=self.db,
            host_agent=SimpleNamespace(terminate_process=self._terminate),
        )
        server.live_monitor = None
        self.client = TestClient(server.app)
        self.headers = {security.TOKEN_HEADER: security.api_token()}
        self.incident = HostIncident(process=HostProcessInfo(pid=4242, process_name="tool.exe", exe_path=self.exe),
                                     classification="Stealer", risk_score=9.0)
        self.db.save_host_incident(self.incident)

    def tearDown(self):
        self.server.orchestrator = None
        if self._old is None:
            os.environ.pop("SENTINEL_DATA_DIR", None)
        else:
            os.environ["SENTINEL_DATA_DIR"] = self._old
        super().tearDown()

    def _terminate(self, process):
        self.terminated.append(process)
        return "SUCCESS", ""

    def _url(self, action):
        return f"/api/host/incidents/{self.incident.incident_id}/{action}"

    def test_trust_unsigned_program_by_file_hash(self):
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            res = self.client.post(self._url("trust"), json={"scope": "auto"}, headers=self.headers)
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["rule"]["kind"], "hash")
        rules = self.client.get("/api/trust", headers=self.headers).json()["rules"]
        self.assertEqual(rules[0]["value"], trust.file_sha256(self.exe))

        rows = self.client.get("/api/host/incidents", headers=self.headers).json()["host_incidents"]
        self.assertEqual(rows[0]["followups"][0]["action"], "MARKED_SAFE")

        self.assertEqual(self.client.delete(f"/api/trust/{rules[0]['id']}", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/trust", headers=self.headers).json()["count"], 0)

    def test_trust_signed_program_by_publisher(self):
        with mock.patch.object(trust, "signature", return_value=SIGNED):
            res = self.client.post(self._url("trust"), json={"scope": "auto"}, headers=self.headers)
        self.assertEqual(res.json()["rule"], {**res.json()["rule"], "kind": "publisher", "value": "Vendor Inc."})

    def test_publisher_scope_rejected_for_unsigned(self):
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            res = self.client.post(self._url("trust"), json={"scope": "publisher"}, headers=self.headers)
        self.assertEqual(res.status_code, 400)

    def test_terminate_uses_alert_identity_and_records_followup(self):
        res = self.client.post(self._url("terminate"), headers=self.headers)
        self.assertEqual(res.json()["status"], "SUCCESS")
        self.assertEqual((self.terminated[0].pid, self.terminated[0].exe_path), (4242, self.exe))
        rows = self.db.get_host_followups([self.incident.incident_id])[self.incident.incident_id]
        self.assertEqual(rows[0]["action"], "TERMINATED")
        conn = self.db._get_connection()
        actions = [r["action"] for r in conn.execute("SELECT action FROM audit_logs")]
        conn.close()
        self.assertTrue(any("TERMINATE_PROCESS" in a for a in actions))

    def test_code_runner_cannot_be_trusted(self):
        runner = os.path.join(self.tmp, "python.exe")
        shutil.copy(self.exe, runner)
        inc = HostIncident(process=HostProcessInfo(pid=4243, process_name="python.exe", exe_path=runner),
                           classification="Stealer", risk_score=9.0)
        self.db.save_host_incident(inc)
        res = self.client.post(f"/api/host/incidents/{inc.incident_id}/trust", json={"scope": "file"}, headers=self.headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("runs scripts", res.json()["detail"])

    def test_unknown_incident_is_404(self):
        self.assertEqual(self.client.post("/api/host/incidents/NOPE/terminate", headers=self.headers).status_code, 404)

    def test_evidence_chain_still_verifies(self):
        with mock.patch.object(trust, "signature", return_value=UNSIGNED):
            self.client.post(self._url("trust"), json={"scope": "file"}, headers=self.headers)
        self.client.post(self._url("terminate"), headers=self.headers)
        self.assertTrue(self.db.verify_evidence_chain()["ok"])


if __name__ == "__main__":
    unittest.main()
