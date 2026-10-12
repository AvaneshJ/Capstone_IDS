"""
Tests for SentinelAI anti-tamper: integrity manifest, API token auth, sensor heartbeat
watchdog, evidence hash chain, and tamper command / event classification.
Run from repo root:  python -m pytest soar/tests/test_self_protection.py -q
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import joblib  # noqa: E402

from config import integrity, security  # noqa: E402
from core.schemas import HostIncident, HostProcessInfo  # noqa: E402
from core.self_protection import SelfProtection  # noqa: E402
from core.watchdog import SensorWatchdog  # noqa: E402
from database.db_manager import DatabaseManager  # noqa: E402
from hids.tamper_monitor import classify_command, event_finding, row_finding  # noqa: E402


class _TempDataDir(unittest.TestCase):
    """Each test gets its own data folder (token, HMAC key, manifest, anchors)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._old = os.environ.get("SENTINEL_DATA_DIR")
        os.environ["SENTINEL_DATA_DIR"] = os.path.join(self.tmp, "data")
        integrity._cache.clear()

    def tearDown(self):
        if self._old is None:
            os.environ.pop("SENTINEL_DATA_DIR", None)
        else:
            os.environ["SENTINEL_DATA_DIR"] = self._old
        integrity._cache.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)


def _fake_install(root: Path) -> None:
    (root / "models").mkdir(parents=True)
    (root / "soar" / "rules").mkdir(parents=True)
    (root / "soar" / "core").mkdir(parents=True)
    (root / "soar" / "tests").mkdir(parents=True)
    joblib.dump({"threshold": 0.1}, root / "models" / "model.joblib")
    (root / "soar" / "rules" / "policies.yaml").write_text("whitelist: []\n", encoding="utf-8")
    (root / "soar" / "core" / "engine.py").write_text("X = 1\n", encoding="utf-8")
    (root / "soar" / "tests" / "test_x.py").write_text("pass\n", encoding="utf-8")


class TestSecrets(_TempDataDir):

    def test_token_is_created_once_and_stable(self):
        token = security.api_token()
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(security.api_token(), token)
        self.assertTrue(security.token_path().exists())

    def test_env_token_override(self):
        os.environ["SENTINEL_API_TOKEN"] = "fixed-token"
        try:
            self.assertEqual(security.api_token(), "fixed-token")
        finally:
            del os.environ["SENTINEL_API_TOKEN"]

    def test_tokens_equal(self):
        self.assertTrue(security.tokens_equal("abc", "abc"))
        self.assertFalse(security.tokens_equal("abd", "abc"))
        self.assertFalse(security.tokens_equal(None, "abc"))
        self.assertFalse(security.tokens_equal("", "abc"))


class TestIntegrityManifest(_TempDataDir):

    def setUp(self):
        super().setUp()
        self.root = Path(self.tmp) / "install"
        _fake_install(self.root)
        self.manifest = Path(self.tmp) / "manifest.json"
        self.manifest.write_text(json.dumps(integrity.build_manifest(self.root)), encoding="utf-8")

    def test_manifest_covers_models_policies_code_but_not_tests(self):
        files = json.loads(self.manifest.read_text())["files"]
        self.assertIn("models/model.joblib", files)
        self.assertIn("soar/rules/policies.yaml", files)
        self.assertIn("soar/core/engine.py", files)
        self.assertNotIn("soar/tests/test_x.py", files)

    def test_clean_install_verifies(self):
        report = integrity.verify(self.root, self.manifest)
        self.assertEqual(report.state, "ok")
        self.assertEqual(report.problems, [])

    def test_modified_missing_and_added_files_detected(self):
        (self.root / "soar" / "rules" / "policies.yaml").write_text("whitelist: ['0.0.0.0/0']\n", encoding="utf-8")
        (self.root / "soar" / "core" / "engine.py").unlink()
        (self.root / "soar" / "core" / "backdoor.py").write_text("import os\n", encoding="utf-8")
        report = integrity.verify(self.root, self.manifest)
        self.assertEqual(report.state, "tampered")
        self.assertEqual(report.modified, ["soar/rules/policies.yaml"])
        self.assertEqual(report.missing, ["soar/core/engine.py"])
        self.assertEqual(report.added, ["soar/core/backdoor.py"])

    def test_forged_manifest_fails_signature(self):
        data = json.loads(self.manifest.read_text())
        data["files"]["soar/rules/policies.yaml"] = "0" * 64
        self.manifest.write_text(json.dumps(data), encoding="utf-8")
        self.assertEqual(integrity.verify(self.root, self.manifest).state, "bad_signature")

    def test_quick_check_reuses_hash_until_file_changes(self):
        mon = integrity.IntegrityMonitor(self.root, self.manifest)
        self.assertEqual(mon.check().state, "ok")
        path = self.root / "soar" / "core" / "engine.py"
        path.write_text("X = 2\n", encoding="utf-8")
        os.utime(path, ns=(time.time_ns(), time.time_ns() + 10_000_000))
        self.assertEqual(mon.check().modified, ["soar/core/engine.py"])

    def test_trusted_model_loads(self):
        model = integrity.load_verified(self.root / "models" / "model.joblib", self.manifest, self.root)
        self.assertEqual(model, {"threshold": 0.1})

    def test_swapped_model_is_refused_before_unpickling(self):
        joblib.dump({"threshold": 999}, self.root / "models" / "model.joblib")
        with self.assertRaises(integrity.IntegrityError):
            integrity.load_verified(self.root / "models" / "model.joblib", self.manifest, self.root)

    def test_unlisted_model_in_models_dir_is_refused(self):
        joblib.dump([1], self.root / "models" / "dropped.pkl")
        with self.assertRaises(integrity.IntegrityError):
            integrity.load_verified(self.root / "models" / "dropped.pkl", self.manifest, self.root)

    def test_forged_manifest_blocks_model_loading(self):
        data = json.loads(self.manifest.read_text())
        data["signature"] = "f" * 64
        self.manifest.write_text(json.dumps(data), encoding="utf-8")
        integrity._cache.clear()
        with self.assertRaises(integrity.IntegrityError):
            integrity.load_verified(self.root / "models" / "model.joblib", self.manifest, self.root)

    def test_no_manifest_loads_unless_required(self):
        missing = Path(self.tmp) / "nope.json"
        self.assertEqual(integrity.load_verified(self.root / "models" / "model.joblib", missing, self.root),
                         {"threshold": 0.1})
        os.environ["SENTINEL_INTEGRITY_REQUIRED"] = "1"
        try:
            with self.assertRaises(integrity.IntegrityError):
                integrity.load_verified(self.root / "models" / "model.joblib", missing, self.root)
        finally:
            del os.environ["SENTINEL_INTEGRITY_REQUIRED"]


class TestAppendOnlyLogs(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "process_events_2026-10-12.csv"
        self.log.write_text("a,b\n1,2\n", encoding="utf-8")
        self.watch = integrity.AppendOnlyWatch(self.tmp)
        self.assertEqual(self.watch.check(), [])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_append_is_fine(self):
        with open(self.log, "a", encoding="utf-8") as f:
            f.write("3,4\n")
        self.assertEqual(self.watch.check(), [])

    def test_truncate_edit_delete_detected(self):
        self.log.write_text("a,b\n", encoding="utf-8")
        self.assertIn("truncated", self.watch.check()[0])
        self.log.write_text("x,y\n", encoding="utf-8")
        self.assertIn("edited", self.watch.check()[0])
        self.log.unlink()
        self.assertIn("deleted", self.watch.check()[0])


class TestEvidenceChain(_TempDataDir):

    def setUp(self):
        super().setUp()
        self.db = DatabaseManager(db_path=os.path.join(self.tmp, "chain.db"))

    def _host_incident(self, name="evil.exe"):
        return HostIncident(process=HostProcessInfo(pid=1234, process_name=name), classification="Stealer", risk_score=9.0)

    def _populate(self):
        inc = self._host_incident()
        self.db.save_host_incident(inc)
        self.db.save_audit_log("HostSOARAgent", "TERMINATE_PROCESS", "pid 1234")
        self.db.save_host_incident(self._host_incident("other.exe"))
        return inc

    def _sql(self, query, params=()):
        conn = sqlite3.connect(self.db.db_path)
        conn.execute(query, params)
        conn.commit()
        conn.close()

    def test_untouched_chain_verifies(self):
        self._populate()
        result = self.db.verify_evidence_chain()
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["entries"], 3)

    def test_edited_incident_detected(self):
        inc = self._populate()
        self._sql("UPDATE host_incidents SET classification = 'Normal' WHERE incident_id = ?", (inc.incident_id,))
        result = self.db.verify_evidence_chain()
        self.assertFalse(result["ok"])
        self.assertTrue(any("modified" in p for p in result["problems"]))

    def test_deleted_incident_detected(self):
        inc = self._populate()
        self._sql("DELETE FROM host_incidents WHERE incident_id = ?", (inc.incident_id,))
        self.assertTrue(any("deleted" in p for p in self.db.verify_evidence_chain()["problems"]))

    def test_deleted_audit_row_and_chain_entry_detected(self):
        self._populate()
        self._sql("DELETE FROM audit_logs")
        self._sql("DELETE FROM evidence_chain WHERE table_name = 'audit_logs'")
        problems = self.db.verify_evidence_chain()["problems"]
        self.assertTrue(any("chain entries 2..2 were deleted" in p for p in problems), problems)

    def test_truncated_tail_detected_by_anchor(self):
        self._populate()
        last = self.db.verify_evidence_chain()["entries"]
        self._sql("DELETE FROM evidence_chain WHERE seq = ?", (last,))
        self._sql("DELETE FROM host_incidents WHERE id = (SELECT MAX(id) FROM host_incidents)")
        problems = self.db.verify_evidence_chain()["problems"]
        self.assertTrue(any("truncated or replaced" in p for p in problems), problems)

    def test_forged_chain_entry_detected(self):
        self._populate()
        self._sql("UPDATE evidence_chain SET record_hash = ? WHERE seq = 1", ("a" * 64,))
        problems = self.db.verify_evidence_chain()["problems"]
        self.assertTrue(any("forged or edited" in p for p in problems), problems)

    def test_row_injected_outside_chain_detected(self):
        self._populate()
        self._sql("INSERT INTO audit_logs (timestamp, agent_name, action) VALUES (?, 'x', 'fake')", (time.time() + 1,))
        problems = self.db.verify_evidence_chain()["problems"]
        self.assertTrue(any("inserted outside the chain" in p for p in problems), problems)

    def test_replaced_database_recorded_as_break(self):
        self._populate()
        self._sql("DELETE FROM evidence_chain WHERE seq = 3")
        self._sql("DELETE FROM host_incidents WHERE id = (SELECT MAX(id) FROM host_incidents)")
        self.db.save_audit_log("x", "y")
        problems = self.db.verify_evidence_chain()["problems"]
        self.assertTrue(any("chain head mismatch" in p for p in problems), problems)


class TestWatchdog(unittest.TestCase):

    def test_heartbeat_timeout_reported_once_then_recovers(self):
        wd = SensorWatchdog(default_timeout=30)
        wd.beat("hids_live", now=1000)
        self.assertEqual(wd.check(now=1020), ([], []))
        silenced, _ = wd.check(now=1031)
        self.assertEqual([r.name for r in silenced], ["hids_live"])
        self.assertEqual(wd.check(now=1040), ([], []), "reported once per silence")
        self.assertEqual(wd.status(now=1040)["silenced"], ["hids_live"])
        wd.beat("hids_live", now=1041)
        _, recovered = wd.check(now=1042)
        self.assertEqual([r.name for r in recovered], ["hids_live"])

    def test_probe_only_sensor(self):
        alive = {"v": True}
        wd = SensorWatchdog()
        wd.register("hids_file", probe=lambda: alive["v"], timeout=None)
        self.assertEqual(wd.check(now=time.time() + 10_000), ([], []), "no timeout for quiet sensors")
        alive["v"] = False
        silenced, _ = wd.check()
        self.assertEqual(silenced[0].reason, "stopped running")


class _StubOrch:
    def __init__(self, db):
        self.db_manager = db
        self.alerts = []
        self.alert_agent = SimpleNamespace(dispatch_host_alert=lambda inc: self.alerts.append(inc))
        self.start_time = time.time()


class TestSelfProtectionService(_TempDataDir):

    def setUp(self):
        super().setUp()
        self.db = DatabaseManager(db_path=os.path.join(self.tmp, "sp.db"))
        self.orch = _StubOrch(self.db)
        self.root = Path(self.tmp) / "install"
        _fake_install(self.root)
        self.manifest = Path(self.tmp) / "manifest.json"
        self.manifest.write_text(json.dumps(integrity.build_manifest(self.root)), encoding="utf-8")
        self.notified = []
        self.sp = SelfProtection(self.orch, notify=lambda t, d: self.notified.append((t, d)),
                                 root=self.root, manifest_file=self.manifest, log_dirs=[])

    def _tamper_incidents(self):
        return [r for r in self.db.get_recent_host_incidents(classification="Tamper")]

    def test_policy_tamper_raises_one_critical_incident(self):
        self.sp.check_integrity(full=True)
        self.assertEqual(self._tamper_incidents(), [])
        (self.root / "soar" / "rules" / "policies.yaml").write_text("whitelist: ['0.0.0.0/0']\n", encoding="utf-8")
        self.sp.check_integrity(full=True)
        self.sp.check_integrity(full=True)
        rows = self._tamper_incidents()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "CRITICAL")
        self.assertEqual(rows[0]["mitre_technique_id"], "T1565.001")
        self.assertEqual(self.notified[0][0], "NEW_HOST_INCIDENT")
        self.assertEqual(len(self.orch.alerts), 1)

    def test_silenced_sensor_raises_incident(self):
        self.sp.watchdog.register("hids_process", timeout=0.01)
        time.sleep(0.05)
        self.sp.check_sensors()
        rows = self._tamper_incidents()
        self.assertEqual(len(rows), 1)
        self.assertIn("hids_process", rows[0]["remediation_notes"])

    def test_killed_previous_run_detected(self):
        marker = security.data_dir() / "engine_run.json"
        marker.write_text(json.dumps({"pid": 999_999_9, "started_at": 1.0, "planned_stop": False}))
        self.sp.check_previous_run()
        self.assertEqual(len(self._tamper_incidents()), 1)
        self.sp.mark_planned_stop()
        self.sp._last_raised.clear()
        self.sp.check_previous_run()
        self.assertEqual(len(self._tamper_incidents()), 1, "a planned stop is not a kill")

    def test_windows_shutdown_is_not_a_kill(self):
        from core import self_protection as sp_mod

        now = time.time()
        marker = security.data_dir() / "engine_run.json"
        marker.write_text(json.dumps({"pid": 999_999_9, "started_at": now - 3600, "alive_at": now - 20, "planned_stop": False}))
        with mock.patch.object(sp_mod, "windows_shutdown_time", return_value=now):
            self.sp.check_previous_run()
        self.assertEqual(len(self._tamper_incidents()), 0, "engine alive until Windows shut down")

    def test_kill_long_before_shutdown_still_detected(self):
        from core import self_protection as sp_mod

        now = time.time()
        marker = security.data_dir() / "engine_run.json"
        marker.write_text(json.dumps({"pid": 999_999_9, "started_at": now - 7200, "alive_at": now - 3600, "planned_stop": False}))
        with mock.patch.object(sp_mod, "windows_shutdown_time", return_value=now):
            self.sp.check_previous_run()
        self.assertEqual(len(self._tamper_incidents()), 1, "killed an hour before the shutdown")

    def test_heartbeat_keeps_planned_stop(self):
        self.sp.mark_planned_stop()
        self.sp.tick()
        marker = json.loads((security.data_dir() / "engine_run.json").read_text())
        self.assertTrue(marker["planned_stop"])

    def test_chain_tamper_raises_incident(self):
        self.db.save_audit_log("a", "b")
        conn = sqlite3.connect(self.db.db_path)
        conn.execute("UPDATE audit_logs SET action = 'nothing to see'")
        conn.commit()
        conn.close()
        self.sp.check_chain()
        self.assertFalse(self.sp.chain["ok"])
        self.assertTrue(any(r["file_type"] == "SentinelAI" for r in self._tamper_incidents()))

    def test_finding_sink(self):
        inc = self.sp.on_finding({"kind": "log_cleared", "title": "Security event log was cleared",
                                  "details": "x", "mitre_id": "T1070.001", "record_id": 7})
        self.assertEqual(inc.mitre_technique_id, "T1070.001")
        self.assertIsNone(self.sp.on_finding({"kind": "log_cleared", "record_id": 7}), "deduplicated")


class TestTamperClassification(unittest.TestCase):

    def test_kill_commands_targeting_sentinel(self):
        for name, cmd in [
            ("taskkill.exe", "taskkill /F /IM python.exe"),
            ("taskkill.exe", "taskkill /pid 4242 /f"),
            ("powershell.exe", "powershell -c Stop-Process -Name electron -Force; Stop-Process -Id 4242"),
            ("wmic.exe", "wmic process where name='SentinelAI.exe' delete"),
            ("sc.exe", "sc stop SentinelAI"),
        ]:
            finding = classify_command(name, cmd, protected_pids={4242})
            self.assertIsNotNone(finding, cmd)
            self.assertEqual(finding["kind"], "kill_attempt")

    def test_unrelated_kills_ignored(self):
        self.assertIsNone(classify_command("taskkill.exe", "taskkill /IM notepad.exe", protected_pids={4242}))
        self.assertIsNone(classify_command("taskkill.exe", "taskkill /pid 42420", protected_pids={4242}))
        self.assertIsNone(classify_command("chrome.exe", "chrome.exe --type=renderer python.exe"))

    def test_defense_evasion_commands(self):
        cases = {
            "wevtutil cl Security": "log_clear_command",
            "powershell Clear-EventLog -LogName Security": "log_clear_command",
            "auditpol /set /subcategory:{0CCE921D} /success:disable": "audit_disable_command",
            "auditpol /clear /y": "audit_disable_command",
            "netsh advfirewall set allprofiles state off": "firewall_disabled",
        }
        for cmd, kind in cases.items():
            self.assertEqual(classify_command("x.exe", cmd)["kind"], kind, cmd)

    def test_install_folder_tamper(self):
        finding = classify_command("cmd.exe", r"cmd /c del C:\SentinelAI\models\sentinel_xgb_v3.pkl",
                                   install_root=os.path.normcase(r"C:\SentinelAI"))
        self.assertEqual(finding["kind"], "install_tamper_command")

    def test_electron_processes_with_install_path_not_flagged(self):
        electron = rf"{_ROOT}\dashboard\node_modules\electron\dist\electron.exe"
        common = (rf"--user-data-dir=C:\Users\me\AppData\Roaming\SentinelAI --app-user-model-id=com.sentinelai.desktop "
                  rf"--app-path={_ROOT}\dashboard --enable-sandbox --video-capture-use-gpu-memory-buffer --lang=en-US "
                  "--device-scale-factor=1 --num-raster-threads=4 --enable-main-frame-before-activation "
                  "--renderer-client-id=5 --time-ticks-at-unix-epoch=-1760000000000000 --launch-time-ticks=123456789 "
                  "--field-trial-handle=1888,i,2735582036112380419,9873455646233420102,262144 "
                  "--disable-features=SpareRendererForSitePerProcess,WinRetrieveSuggestionsOnlyOnDemand "
                  "--variations-seed-version --mojo-platform-channel-handle=3084 /prefetch:1")
        for kind in ("--type=renderer", "--type=gpu-process --gpu-preferences=UAAAAAAAAADgAAAEAAAAAAAAAAAAAAAAAAABgAAAAAAA",
                     "--type=utility --utility-sub-type=network.mojom.NetworkService --service-sandbox-type=none"):
            cmd = f'"{electron}" {kind} {common}'
            self.assertIsNone(classify_command("electron.exe", cmd, protected_pids={4242}), kind)
            row = {"event": "START", "pid": 13920, "ppid": 555, "process_name": "electron.exe", "cmdline": cmd}
            self.assertIsNone(row_finding(row, pids={4242}), kind)
        backend = rf'"{_ROOT}\.venv\Scripts\python.exe" -m soar.main --host 127.0.0.1 --port 8000'
        self.assertIsNone(classify_command("python.exe", backend, protected_pids={4242}))

    def test_real_destructive_commands_on_install_folder_still_flagged(self):
        for cmd in (rf"cmd /c del /q {_ROOT}\models\sentinel_xgb_v3.pkl",
                    rf"cmd.exe /c echo x & rd /s /q {_ROOT}\soar",
                    rf'powershell -Command "Remove-Item -Recurse -Force \"{_ROOT}\hids\""',
                    rf"icacls {_ROOT} /deny Everyone:F",
                    rf"powershell -c Set-Content -Path {_ROOT}\soar\rules\host.yaml -Value x"):
            finding = classify_command("cmd.exe", cmd)
            self.assertEqual(finding and finding["kind"], "install_tamper_command", cmd)
        self.assertIsNone(classify_command("notepad.exe", rf"notepad.exe {_ROOT}\README.md"))
        self.assertIsNone(classify_command("code.exe", rf'"C:\VS Code\code.exe" --reuse-window {_ROOT}\hids\remove_old.py'))

    def test_own_process_tree_is_trusted(self):
        from unittest import mock
        from config import own_processes

        parents = own_processes.ParentMap()
        for pid, ppid in ((200, 100), (300, 200)):
            parents.observe({"pid": pid, "ppid": ppid})
        row = {"event": "START", "pid": 300, "ppid": 200, "process_name": "taskkill.exe", "cmdline": "taskkill /pid 4242 /T /F"}
        with mock.patch.object(own_processes, "root_pids", return_value=frozenset({100})):
            self.assertTrue(parents.is_own(300))
            self.assertIsNone(row_finding(row, pids={4242}, parents=parents))
            parents.observe({"pid": 301, "ppid": 555})
            self.assertFalse(parents.is_own(301))
            self.assertIsNotNone(row_finding({**row, "pid": 301, "ppid": 555}, pids={4242}, parents=parents))

    def test_security_log_reader_queries_tamper_events(self):
        from hids.tamper_monitor import TamperLogReader

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1102</EventID>"
                   "<EventRecordID>9</EventRecordID></System><UserData/></Event>") if len(calls) == 2 else ""
            return SimpleNamespace(returncode=0, stdout=xml, stderr="")

        reader = TamperLogReader(run=fake_run)
        reader.start()
        self.assertEqual([f["kind"] for f in reader.read_new()], ["log_cleared"])
        self.assertIn("EventID=1100 or EventID=1102 or EventID=4719", calls[1][3])
        reader.close()

    def test_security_log_events(self):
        self.assertEqual(event_finding({"event_id": 1102, "record_id": 5, "data": {}})["kind"], "log_cleared")
        added = {"event_id": 4719, "record_id": 6, "data": {"AuditPolicyChanges": "%%8449"}}
        removed = {"event_id": 4719, "record_id": 7, "data": {"AuditPolicyChanges": "%%8448"}}
        self.assertIsNone(event_finding(added), "SentinelAI itself only adds auditing")
        self.assertEqual(event_finding(removed)["mitre_id"], "T1562.002")
        self.assertIsNone(event_finding({"event_id": 4663, "data": {}}))


class TestSensorHooks(unittest.TestCase):

    def test_live_monitor_dead_thread_is_silenced(self):
        import threading
        from core.live_monitor import LiveMonitor

        orch = SimpleNamespace(firewall_agent=SimpleNamespace(dry_run=True), host_agent=SimpleNamespace(dry_run=True))
        mon = LiveMonitor(orch)
        mon.watchdog = SensorWatchdog()
        t = threading.Thread(target=lambda: None)
        t.start()
        t.join()
        mon.process_state = "running"
        mon._watch("hids_process", t, "process_state", timeout=None)
        silenced, _ = mon.watchdog.check()
        self.assertEqual([r.name for r in silenced], ["hids_process"])

        mon.file_state = "unavailable"
        mon._watch("hids_file", t, "file_state")
        self.assertEqual(mon.watchdog.check(), ([], []), "a sensor that legitimately exited isn't tamper")

    def test_host_bridge_reports_kill_command(self):
        from hids.live import HostBridge

        bridge = HostBridge(predictor=SimpleNamespace())
        found = []
        bridge.on_tamper = found.append
        bridge._protected_pids = {4242}
        bridge.on_process_rows([{"event": "START", "pid": 77, "ppid": 1, "process_name": "taskkill.exe",
                                 "cmdline": "taskkill /F /PID 4242", "exe_path": r"C:\Windows\System32\taskkill.exe"}])
        self.assertEqual([f["kind"] for f in found], ["kill_attempt"])
        self.assertEqual(found[0]["pid"], 77)

    def test_host_bridge_skips_own_processes(self):
        from hids.live import HostBridge

        scored = []
        bridge = HostBridge(predictor=SimpleNamespace(predict_many=lambda rows: scored.extend(rows) or []))
        found = []
        bridge.on_tamper = found.append
        cmd = (rf'"{_ROOT}\dashboard\node_modules\electron\dist\electron.exe" --type=renderer '
               rf"--app-path={_ROOT}\dashboard --enable-sandbox")
        rows = [{"event": "START", "pid": os.getpid() + 100000, "ppid": os.getpid(), "process_name": "electron.exe",
                 "cmdline": cmd, "exe_path": ""},
                {"event": "EXIT", "pid": os.getpid() + 100000, "ppid": os.getpid(), "process_name": "electron.exe"},
                {"event": "EXIT", "pid": 999999, "ppid": 1, "process_name": "python.exe",
                 "exe_path": rf"{_ROOT}\.venv\Scripts\python.exe"}]
        bridge.on_process_rows(rows)
        self.assertEqual(found, [])
        self.assertEqual(scored, [])

    def test_host_agent_never_terminates_sentinel(self):
        from agents.host_agent import HostSOARAgent
        from core.schemas import HostActionType, HostFileEvent

        agent = HostSOARAgent(dry_run=False)
        proc = HostProcessInfo(pid=os.getpid(), process_name="python.exe", exe_path=sys.executable)
        fevent = HostFileEvent(file_path=r"C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\Login Data")
        action, status, _ = agent._plan_and_execute_response(proc, fevent, "Stealer", 9.5)
        self.assertEqual(action, HostActionType.ALERT_ONLY)
        self.assertEqual(agent._terminate_pid(proc)[0], "IDENTITY_MISMATCH")


class TestApiAuth(_TempDataDir):

    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        import api.server as server

        self.server = server
        self.client = TestClient(server.app)
        self.token = security.api_token()

    def tearDown(self):
        self.server.self_protection = None
        super().tearDown()

    def test_root_is_open(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_mutating_and_read_endpoints_need_token(self):
        for method, path in [("post", "/api/blocks/unblock/abc"), ("post", "/api/reports/generate"),
                             ("post", "/api/flows/ingest"), ("post", "/api/host/events/ingest"),
                             ("get", "/api/incidents"), ("get", "/api/status")]:
            self.assertEqual(getattr(self.client, method)(path).status_code, 401, path)
            bad = getattr(self.client, method)(path, headers={security.TOKEN_HEADER: "wrong"})
            self.assertEqual(bad.status_code, 401, path)

    def test_valid_token_passes_auth(self):
        res = self.client.post("/api/blocks/unblock/abc", headers={security.TOKEN_HEADER: self.token})
        self.assertEqual(res.status_code, 503, "past auth; orchestrator isn't running in this test")
        res = self.client.get(f"/api/incidents?token={self.token}")
        self.assertEqual(res.status_code, 503)

    def test_websocket_requires_token(self):
        from starlette.websockets import WebSocketDisconnect

        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/live-stream") as ws:
                ws.receive_text()
        with self.client.websocket_connect(f"/ws/live-stream?token={self.token}") as ws:
            ws.send_text(json.dumps({"action": "PING"}))
            self.assertEqual(ws.receive_json()["event_type"], "PONG")

    def test_cors_only_for_dashboard_origins(self):
        ok = self.client.options("/api/status", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
                                                         "Access-Control-Request-Headers": security.TOKEN_HEADER})
        self.assertEqual(ok.headers.get("access-control-allow-origin"), "http://localhost:5173")
        evil = self.client.options("/api/status", headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"})
        self.assertNotIn("access-control-allow-origin", evil.headers)

    def test_heartbeat_endpoint_feeds_watchdog(self):
        self.server.self_protection = SimpleNamespace(watchdog=SensorWatchdog(), on_finding=lambda f: None)
        res = self.client.post("/api/sensors/heartbeat", json={"sensor": "hids_live", "pid": 1},
                               headers={security.TOKEN_HEADER: self.token})
        self.assertEqual(res.status_code, 200)
        self.assertIn("hids_live", self.server.self_protection.watchdog.status()["sensors"])
        unauth = self.client.post("/api/sensors/heartbeat", json={"sensor": "hids_live"})
        self.assertEqual(unauth.status_code, 401)

    def test_auth_can_be_disabled_for_demos(self):
        os.environ["SENTINEL_AUTH"] = "0"
        try:
            self.assertEqual(self.client.get("/api/incidents").status_code, 503)
        finally:
            del os.environ["SENTINEL_AUTH"]


if __name__ == "__main__":
    unittest.main()
