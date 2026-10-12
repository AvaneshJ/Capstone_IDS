"""
Tests for the HIDS file sensor (hids/file_monitor.py).
Run from repo root:  python -m unittest hids.tests.test_file_monitor -v

No Administrator rights, real browser files or real Security log needed:
event XML and the auditpol / wevtutil / PowerShell calls are faked.
"""

import csv
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from hids.file_monitor import (
    FIELDS,
    LOG_PREFIX,
    Deduper,
    FileStateTracker,
    SecurityLogReader,
    Target,
    access_event_type,
    accessor_is_owner,
    audit_row,
    build_row,
    describe_process,
    describe_watch_targets,
    file_type_for,
    parse_events_xml,
    parse_system_time,
    path_looks_sensitive,
    poll_rows,
    resolve_targets,
    set_audit_policy,
    set_audit_rules,
    to_host_event,
)
from hids.process_monitor import DailyCsvWriter

CHROME_EXE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
STEALER_EXE = r"C:\Users\Lab\AppData\Local\Temp\svc_update.exe"
LOGIN_DATA = r"C:\Users\Lab\AppData\Local\Google\Chrome\User Data\Default\Login Data"


def event_xml(record_id, object_name, process_name, pid_hex="0x1a2c", mask="0x1", event_id=4663,
              system_time="2026-10-01T11:47:00.1234567Z"):
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime='{system_time}'/>"
        f"<EventRecordID>{record_id}</EventRecordID></System><EventData>"
        "<Data Name='SubjectUserName'>Lab</Data><Data Name='ObjectType'>File</Data>"
        f"<Data Name='ObjectName'>{object_name}</Data><Data Name='AccessList'>%%4416</Data>"
        f"<Data Name='AccessMask'>{mask}</Data><Data Name='ProcessId'>{pid_hex}</Data>"
        f"<Data Name='ProcessName'>{process_name}</Data></EventData></Event>"
    )


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def touch(path, content="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# ---------------------------------------------------------------
# Targets
# ---------------------------------------------------------------

class TestResolveTargets(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.local = os.path.join(self.dir, "Local")
        self.roaming = os.path.join(self.dir, "Roaming")
        self.env = {"LOCALAPPDATA": self.local, "APPDATA": self.roaming}
        chrome = os.path.join(self.local, "Google", "Chrome", "User Data")
        self.files = {
            os.path.join(chrome, "Local State"): ("Chrome", "LocalState (Master Key)"),
            os.path.join(chrome, "Default", "Login Data"): ("Chrome", "Saved Passwords DB"),
            os.path.join(chrome, "Default", "Network", "Cookies"): ("Chrome", "CookieDB"),
            os.path.join(chrome, "Profile 1", "Web Data"): ("Chrome", "Autofill & Credit Cards"),
            os.path.join(self.local, "Microsoft", "Edge", "User Data", "Local State"): ("Edge", "LocalState (Master Key)"),
            os.path.join(self.local, "Microsoft", "Edge", "User Data", "Default", "Login Data For Account"): ("Edge", "Saved Passwords DB"),
            os.path.join(self.local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cookies"): ("Brave", "CookieDB"),
            os.path.join(self.roaming, "Opera Software", "Opera Stable", "Login Data"): ("Opera", "Saved Passwords DB"),
            os.path.join(self.roaming, "Mozilla", "Firefox", "Profiles", "ab12.default-release", "logins.json"): ("Firefox", "Firefox Saved Passwords"),
            os.path.join(self.roaming, "Mozilla", "Firefox", "Profiles", "ab12.default-release", "key4.db"): ("Firefox", "Firefox Key Database"),
            os.path.join(self.roaming, "Bitcoin", "wallet.dat"): ("Bitcoin Core", "Crypto Wallet"),
        }
        for path in self.files:
            touch(path)
        touch(os.path.join(chrome, "Default", "History"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_finds_every_existing_target_with_browser_and_type(self):
        found = {t.path: (t.browser, t.file_type) for t in resolve_targets(self.env)}
        self.assertEqual(found, self.files)

    def test_missing_files_and_non_targets_are_skipped(self):
        paths = [t.path for t in resolve_targets(self.env)]
        self.assertFalse(any(p.endswith("History") for p in paths))
        self.assertFalse(any("Firefox" in p and p.endswith("cookies.sqlite") for p in paths))

    def test_empty_environment(self):
        self.assertEqual(resolve_targets({}), [])


class TestFileTypes(unittest.TestCase):

    def test_file_type_for(self):
        self.assertEqual(file_type_for(LOGIN_DATA), "Saved Passwords DB")
        self.assertEqual(file_type_for(r"C:\x\Network\Cookies"), "CookieDB")
        self.assertEqual(file_type_for(r"C:\x\cookies.sqlite"), "Firefox CookieDB")
        self.assertEqual(file_type_for(r"C:\x\History"), "")

    def test_path_looks_sensitive(self):
        self.assertTrue(path_looks_sensitive(LOGIN_DATA))
        self.assertTrue(path_looks_sensitive(r"C:\Users\Lab\AppData\Roaming\Mozilla\Firefox\Profiles\a\key4.db"))
        self.assertFalse(path_looks_sensitive(r"C:\Windows\System32\notepad.exe"))

    def test_describe_watch_targets_lists_password_stores(self):
        text = " ".join(describe_watch_targets())
        for name in ("Login Data", "Local State", "logins.json", "key4.db"):
            self.assertIn(name, text)


# ---------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------

class TestAccessorIsOwner(unittest.TestCase):

    def test_real_chrome_is_owner(self):
        self.assertTrue(accessor_is_owner(CHROME_EXE, "Chrome"))

    def test_fake_chrome_outside_install_folder_is_not_owner(self):
        self.assertFalse(accessor_is_owner(r"C:\Users\Lab\AppData\Local\Temp\chrome.exe", "Chrome"))

    def test_other_process_is_not_owner(self):
        self.assertFalse(accessor_is_owner(STEALER_EXE, "Chrome"))
        self.assertFalse(accessor_is_owner(CHROME_EXE, "Edge"))

    def test_unknown_exe_is_none(self):
        self.assertIsNone(accessor_is_owner("", "Chrome"))


class TestDescribeProcess(unittest.TestCase):

    def test_own_process(self):
        me = __import__("psutil").Process()
        # Not sys.executable: in a Windows venv that is a launcher stub, not this process's image.
        info = describe_process(os.getpid(), me.exe())
        self.assertAlmostEqual(info["create_time"], me.create_time(), places=2)

    def test_reused_pid_with_different_exe_is_rejected(self):
        self.assertEqual(describe_process(os.getpid(), r"C:\not\the\same.exe"), {})

    def test_dead_pid(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        self.assertEqual(describe_process(proc.pid, sys.executable), {})

    def test_is_fast(self):
        start = time.perf_counter()
        describe_process(os.getpid(), sys.executable)
        self.assertLess(time.perf_counter() - start, 0.5)


# ---------------------------------------------------------------
# Event 4663 parsing
# ---------------------------------------------------------------

class TestEventParsing(unittest.TestCase):

    def setUp(self):
        self.target = Target(LOGIN_DATA, "Chrome", "Saved Passwords DB")
        self.targets = {os.path.normcase(LOGIN_DATA): self.target}

    def test_parse_system_time_with_7_digit_fraction(self):
        self.assertAlmostEqual(parse_system_time("2026-10-01T11:47:00.1234567Z"), 1790855220.123456, places=5)

    def test_access_event_type(self):
        self.assertEqual(access_event_type(0x1), "READ")
        self.assertEqual(access_event_type(0x2), "MODIFY")
        self.assertEqual(access_event_type(0x6), "MODIFY")
        self.assertEqual(access_event_type(0x10000), "DELETE")
        self.assertIsNone(access_event_type(0x80))

    def test_parse_events_xml(self):
        text = event_xml(10, LOGIN_DATA, STEALER_EXE) + "\n" + event_xml(11, LOGIN_DATA, CHROME_EXE, mask="0x2")
        events = parse_events_xml(text)
        self.assertEqual([e["record_id"] for e in events], [10, 11])
        self.assertEqual(events[0]["event_id"], 4663)
        self.assertEqual(events[0]["data"]["ProcessName"], STEALER_EXE)

    def test_parse_empty_output(self):
        self.assertEqual(parse_events_xml(""), [])

    def test_stealer_read_becomes_row_with_pid_and_exe(self):
        event = parse_events_xml(event_xml(10, LOGIN_DATA, STEALER_EXE))[0]
        row = audit_row(event, self.targets)
        self.assertEqual(row["event_type"], "READ")
        self.assertEqual(row["pid"], 0x1A2C)
        self.assertEqual(row["process_name"], "svc_update.exe")
        self.assertEqual(row["exe_path"], STEALER_EXE)
        self.assertEqual(row["file_type"], "Saved Passwords DB")
        self.assertEqual(row["browser"], "Chrome")
        self.assertEqual(row["accessor_is_owner"], 0)
        self.assertEqual(row["access_mask"], "0x1")
        self.assertEqual(row["source"], "audit")
        self.assertEqual(set(row), set(FIELDS))

    def test_chrome_reading_its_own_file_is_owner(self):
        event = parse_events_xml(event_xml(10, LOGIN_DATA, CHROME_EXE))[0]
        self.assertEqual(audit_row(event, self.targets)["accessor_is_owner"], 1)

    def test_object_name_case_is_ignored(self):
        event = parse_events_xml(event_xml(10, LOGIN_DATA.upper(), STEALER_EXE))[0]
        self.assertIsNotNone(audit_row(event, self.targets))

    def test_irrelevant_events_are_dropped(self):
        other_file = parse_events_xml(event_xml(10, r"C:\Windows\win.ini", STEALER_EXE))[0]
        other_id = parse_events_xml(event_xml(11, LOGIN_DATA, STEALER_EXE, event_id=4656))[0]
        own_pid = parse_events_xml(event_xml(12, LOGIN_DATA, STEALER_EXE, pid_hex="0x10"))[0]
        attrs_only = parse_events_xml(event_xml(13, LOGIN_DATA, STEALER_EXE, mask="0x80"))[0]
        self.assertIsNone(audit_row(other_file, self.targets))
        self.assertIsNone(audit_row(other_id, self.targets))
        self.assertIsNone(audit_row(own_pid, self.targets, exclude_pids={0x10}))
        self.assertIsNone(audit_row(attrs_only, self.targets))


class TestSecurityLogReader(unittest.TestCase):

    def test_start_then_read_only_new_events(self):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            query = cmd[3]
            if query == "/q:*":
                return completed(event_xml(500, "x", "y", event_id=4624))
            if "EventRecordID>500" in query:
                return completed(event_xml(501, LOGIN_DATA, STEALER_EXE) + event_xml(502, LOGIN_DATA, CHROME_EXE))
            return completed("")

        reader = SecurityLogReader(run=fake_run)
        reader.start()
        self.assertEqual(reader.last_record, 500)
        self.assertEqual([e["record_id"] for e in reader.read_new()], [501, 502])
        self.assertEqual(reader.last_record, 502)
        self.assertEqual(reader.read_new(), [])
        self.assertIn("EventRecordID>502", calls[-1][3])
        self.assertIn("/rd:true", calls[0])

    def test_wevtutil_failure_raises(self):
        reader = SecurityLogReader(run=lambda cmd, **kw: completed(returncode=5, stderr="Access is denied."))
        with self.assertRaises(RuntimeError):
            reader.read_new()


class TestAuditSetup(unittest.TestCase):

    def test_audit_policy_uses_subcategory_guid(self):
        calls = []
        ok = set_audit_policy(True, run=lambda cmd, **kw: calls.append(cmd) or completed())
        self.assertTrue(ok)
        self.assertEqual(calls[0][0], "auditpol")
        self.assertIn("/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}", calls[0])
        self.assertIn("/success:enable", calls[0])

    def test_set_audit_rules_reports_failures(self):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["paths"] = kwargs["env"]["SENTINEL_AUDIT_PATHS"].split("|")
            seen["script"] = cmd[-1]
            return completed(f"OK\t{seen['paths'][0]}\nFAIL\t{seen['paths'][1]}\tAccess denied\n")

        failures = set_audit_rules([r"C:\a\Login Data", r"C:\b\Cookies", r"C:\c\Web Data"], run=fake_run)
        self.assertEqual(seen["paths"], [r"C:\a\Login Data", r"C:\b\Cookies", r"C:\c\Web Data"])
        self.assertIn("AddAuditRule", seen["script"])
        self.assertIn("S-1-1-0", seen["script"])
        self.assertEqual(failures[r"C:\b\Cookies"], "Access denied")
        self.assertIn(r"C:\c\Web Data", failures)
        self.assertNotIn(r"C:\a\Login Data", failures)

    def test_remove_uses_remove_rule(self):
        seen = {}
        set_audit_rules([r"C:\a"], add=False, run=lambda cmd, **kw: seen.setdefault("s", cmd[-1]) and completed("OK\tC:\\a"))
        self.assertIn("RemoveAuditRuleAll", seen["s"])


# ---------------------------------------------------------------
# Rows, dedup, SOAR shape
# ---------------------------------------------------------------

class TestRowsAndDedup(unittest.TestCase):

    def setUp(self):
        self.target = Target(LOGIN_DATA, "Chrome", "Saved Passwords DB")

    def test_dedup_window(self):
        dedup = Deduper(window=2.0)
        row = build_row(100.0, "READ", self.target, "audit", pid=7, exe_path=STEALER_EXE)
        self.assertTrue(dedup.allow(row))
        self.assertFalse(dedup.allow(dict(row, timestamp=101.0)))
        self.assertTrue(dedup.allow(dict(row, timestamp=102.5)))
        self.assertTrue(dedup.allow(dict(row, timestamp=101.0, pid=8)))

    def test_poll_rows_have_no_process(self):
        rows = poll_rows([(self.target, "REPLACE"), (self.target, "DELETE")], 100.0)
        self.assertEqual([r["event_type"] for r in rows], ["MODIFY", "DELETE"])
        self.assertEqual(rows[0]["process_name"], "unknown")
        self.assertEqual(rows[0]["pid"], "")
        self.assertEqual(rows[0]["source"], "poll")

    def test_to_host_event_matches_soar_api(self):
        soar_dir = str(Path(__file__).resolve().parents[2] / "soar")
        if soar_dir not in sys.path:
            sys.path.insert(0, soar_dir)
        from api.server import HostEventIngestRequest

        row = build_row(100.0, "READ", self.target, "audit", pid=6700, exe_path=STEALER_EXE, parent_name="powershell.exe")
        event = to_host_event(row)
        request = HostEventIngestRequest(**event)
        self.assertEqual(request.pid, 6700)
        self.assertEqual(request.process_name, "svc_update.exe")
        self.assertEqual(request.exe_path, STEALER_EXE)
        self.assertEqual(request.file_path, LOGIN_DATA)
        self.assertEqual(request.file_type, "Saved Passwords DB")

    def test_rows_without_pid_are_not_sent_to_soar(self):
        self.assertIsNone(to_host_event(poll_rows([(self.target, "MODIFY")], 1.0)[0]))

    def test_daily_csv_header(self):
        tmp = tempfile.mkdtemp()
        try:
            out = DailyCsvWriter(tmp, prefix=LOG_PREFIX, fields=FIELDS)
            out.write([build_row(time.time(), "READ", self.target, "audit", pid=7, exe_path=STEALER_EXE)], time.time())
            out.close()
            self.assertTrue(os.path.basename(out.path).startswith("file_events_"))
            with open(out.path, newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))
            self.assertEqual(rows[0], FIELDS)
            self.assertEqual(len(rows), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------
# File state tracking
# ---------------------------------------------------------------

class TestFileStateTracker(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "Cookies")
        touch(self.path, "initial")
        self.target = Target(self.path, "Chrome", "CookieDB")
        self.tracker = FileStateTracker([self.target])

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_no_change(self):
        self.assertEqual(self.tracker.poll(), [])

    def test_modify(self):
        with open(self.path, "a") as f:
            f.write("more")
        self.assertEqual(self.tracker.poll(), [(self.target, "MODIFY")])

    def test_replace_is_detected_as_new_file(self):
        tmp = self.path + ".tmp"
        touch(tmp, "initial")
        os.replace(tmp, self.path)
        self.assertEqual(self.tracker.poll(), [(self.target, "REPLACE")])

    def test_delete_then_create(self):
        os.remove(self.path)
        self.assertEqual(self.tracker.poll(), [(self.target, "DELETE")])
        touch(self.path)
        self.assertEqual(self.tracker.poll(), [(self.target, "CREATE")])

    def test_add_only_new_targets(self):
        other = Target(os.path.join(self.dir, "Login Data"), "Chrome", "Saved Passwords DB")
        self.assertEqual(self.tracker.add([self.target, other]), [other])


if __name__ == "__main__":
    unittest.main()
