"""
Tests for the live monitor routing rules (soar/core/live_monitor.py).
Run from repo root:  python -m pytest soar/tests -q

The orchestrator is a stub, so no model, database or capture driver is needed.
"""
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.live_monitor import INCIDENT_COOLDOWN, PORTSCAN_MIN_PORTS, LiveMonitor  # noqa: E402

LOCAL, ATTACKER = "192.168.56.1", "192.168.56.101"


class StubOrchestrator:
    def __init__(self, label="Benign"):
        self.label = label
        self.total_flows_processed = 0
        self.processed = []
        self.checked_saved = 0
        self.packet_agent = SimpleNamespace(sanitize_flow=lambda e: e)
        self.detection_agent = SimpleNamespace(predict=lambda f: SimpleNamespace(
            attack_type=self.label, confidence=0.9, probabilities={self.label: 0.9},
            model_version="CIC_XGB", ml_attack_type=self.label, ml_confidence=0.9,
        ))
        self.db_manager = SimpleNamespace(add_checked_flows=self._save)
        self.firewall_agent = SimpleNamespace(dry_run=True)
        self.host_agent = SimpleNamespace(dry_run=True)

    def _save(self, n):
        self.checked_saved += n

    def process_flow(self, event, detection_override=None):
        label = detection_override.attack_type if detection_override else self.label
        self.processed.append((event, label))
        self.total_flows_processed += 1
        return SimpleNamespace(
            detection=SimpleNamespace(attack_type=label),
            risk=SimpleNamespace(score=8.0),
            action_plan=SimpleNamespace(action_type=SimpleNamespace(value="TEMP_BAN_IP")),
            to_dict=lambda: {"src_ip": event["src_ip"]},
        )


def _flow(src=ATTACKER, dst=LOCAL, sport=50000, dport=22):
    return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport}


class TestLiveMonitorRouting(unittest.TestCase):

    def _monitor(self, label):
        orch = StubOrchestrator(label)
        events = []
        mon = LiveMonitor(orch, on_incident=lambda t, d: events.append(t))
        mon._local_ips = {LOCAL}
        mon._local_ips_at = float("inf")
        return mon, orch, events

    def test_benign_is_counted_not_stored(self):
        mon, orch, events = self._monitor("Benign")
        mon.handle_flow(_flow())
        self.assertEqual(orch.processed, [])
        self.assertEqual(orch.total_flows_processed, 1)
        mon._flush_counters()
        self.assertEqual(orch.checked_saved, 1)
        self.assertEqual(events, [])

    def test_inbound_threat_runs_pipeline_and_notifies(self):
        mon, orch, events = self._monitor("SSH-Bruteforce")
        mon.handle_flow(_flow())
        self.assertEqual(len(orch.processed), 1)
        self.assertEqual(events, ["NEW_INCIDENT"])
        self.assertEqual(mon.net_stats["threats_found"], 1)

    def test_outbound_threat_never_responds(self):
        mon, orch, _ = self._monitor("DoS")
        mon.handle_flow(_flow(src=LOCAL, dst="93.184.216.34", sport=51000, dport=443))
        self.assertEqual(orch.processed, [])
        self.assertEqual(mon.net_stats["outbound_flagged"], 1)

    def test_repeats_grouped_within_cooldown(self):
        mon, orch, _ = self._monitor("DDoS")
        for port in range(50000, 50010):
            mon.handle_flow(_flow(sport=port, dport=80))
        self.assertEqual(len(orch.processed), 1)
        self.assertEqual(mon.net_stats["repeats_grouped"], 9)

        key = (ATTACKER, "DDoS")
        mon._last_incident[key] -= INCIDENT_COOLDOWN + 1
        mon.handle_flow(_flow(sport=50011, dport=80))
        self.assertEqual(len(orch.processed), 2)

    def test_port_scan_fanout_rule(self):
        mon, orch, events = self._monitor("Benign")
        for port in range(1, PORTSCAN_MIN_PORTS):
            mon.handle_flow(_flow(sport=40000, dport=port))
        self.assertEqual(orch.processed, [], "below the threshold every probe is just benign")
        mon.handle_flow(_flow(sport=40000, dport=PORTSCAN_MIN_PORTS))
        self.assertEqual([label for _, label in orch.processed], ["PortScan"])
        for port in range(100, 140):
            mon.handle_flow(_flow(sport=40000, dport=port))
        self.assertEqual(len(orch.processed), 1, "the rest of the scan is grouped")
        self.assertEqual(events, ["NEW_INCIDENT"])

    def test_many_connections_to_one_port_is_not_a_scan(self):
        mon, orch, _ = self._monitor("Benign")
        for sport in range(50000, 50100):
            mon.handle_flow(_flow(sport=sport, dport=443))
        self.assertEqual(orch.processed, [])

    def test_noise_ignored(self):
        mon, orch, _ = self._monitor("DoS")
        mon.handle_flow(_flow(dst="239.255.255.250"))
        self.assertEqual(orch.processed, [])
        self.assertEqual(mon.net_stats["ignored_noise"], 1)
        self.assertEqual(mon.net_stats["flows_checked"], 0)

    def test_disabled_by_env(self):
        mon, _, _ = self._monitor("Benign")
        os.environ["SENTINEL_LIVE"] = "0"
        try:
            mon.start()
        finally:
            del os.environ["SENTINEL_LIVE"]
        self.assertEqual(mon.status()["network"]["state"], "disabled")


class TestLiveMonitorHostRules(unittest.TestCase):

    def setUp(self):
        self.orch = StubOrchestrator()
        self.orch.process_host_event = self._host
        self.sent = []
        self.mon = LiveMonitor(self.orch)

    def _host(self, event):
        self.sent.append(event)
        return SimpleNamespace(classification="Stealer", soar_action=SimpleNamespace(value="TERMINATE_PROCESS"),
                               to_dict=lambda: {})

    def test_system_binary_without_file_evidence_is_skipped(self):
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        self.mon._send_host_event({"process_name": "conhost.exe", "exe_path": os.path.join(windir, "System32", "conhost.exe")})
        self.mon._send_host_event({"process_name": "unknown.exe", "exe_path": ""})
        self.assertEqual(self.sent, [])
        self.assertEqual(self.mon.host_stats["trusted_location_skipped"], 2)

    def test_user_folder_binary_reported_once_per_cooldown(self):
        event = {"process_name": "upd.exe", "exe_path": r"C:\Users\Lab\AppData\Local\Temp\upd.exe"}
        self.mon._send_host_event(dict(event))
        self.mon._send_host_event(dict(event))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.mon.host_stats["repeats_grouped"], 1)

    def test_credential_file_access_always_reported(self):
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        event = {"process_name": "rundll32.exe", "exe_path": os.path.join(windir, "System32", "rundll32.exe"),
                 "file_path": r"C:\Users\Lab\AppData\Local\Google\Chrome\User Data\Default\Login Data"}
        self.mon._send_host_event(dict(event))
        self.mon._send_host_event(dict(event))
        self.assertEqual(len(self.sent), 2)


if __name__ == "__main__":
    unittest.main()
