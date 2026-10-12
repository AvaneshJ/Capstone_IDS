"""
Tests for the live network sensor helpers (nids/live_capture.py).
Run from repo root:  python -m pytest nids/tests -q

No Npcap needed: packets are built with scapy and fed straight into the flow session.
"""
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP

from nids.live_capture import (
    CICFLOWMETER_TO_CIC,
    IDLE_TIMEOUT,
    _make_session,
    flow_direction,
    flow_to_cic,
    flow_to_event,
    is_noise,
)

MODEL_FEATURES = Path(__file__).resolve().parents[2] / "models" / "feature_columns_v3.pkl"

ATTACKER, VICTIM = "192.168.56.101", "192.168.56.1"


def _pkt(src, dst, sport, dport, flags, t, payload=b""):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, window=64240) / payload
    p = IP(bytes(p))
    p.time = t
    return p


def _handshake(t0, sport=50000, dport=22):
    """A short TCP session: handshake, a little data, then FIN from both sides."""
    return [
        _pkt(ATTACKER, VICTIM, sport, dport, "S", t0),
        _pkt(VICTIM, ATTACKER, dport, sport, "SA", t0 + 0.001),
        _pkt(ATTACKER, VICTIM, sport, dport, "A", t0 + 0.002),
        _pkt(ATTACKER, VICTIM, sport, dport, "PA", t0 + 0.010, b"x" * 40),
        _pkt(VICTIM, ATTACKER, dport, sport, "PA", t0 + 0.020, b"y" * 60),
        _pkt(ATTACKER, VICTIM, sport, dport, "FA", t0 + 0.030),
        _pkt(VICTIM, ATTACKER, dport, sport, "FA", t0 + 0.031),
    ]


class TestFeatureMapping(unittest.TestCase):

    @unittest.skipUnless(MODEL_FEATURES.exists(), "model feature list not present")
    def test_covers_every_model_feature(self):
        import joblib

        names = list(joblib.load(MODEL_FEATURES))
        self.assertEqual(sorted(names), sorted(CICFLOWMETER_TO_CIC.values()))

    def test_time_fields_scaled_to_microseconds(self):
        raw = flow_to_cic({"flow_duration": 1.5, "flow_iat_mean": 0.25, "idle_max": 2, "tot_fwd_pkts": 3})
        self.assertAlmostEqual(raw["Flow Duration"], 1_500_000.0)
        self.assertAlmostEqual(raw["Flow IAT Mean"], 250_000.0)
        self.assertAlmostEqual(raw["Idle Max"], 2_000_000.0)
        self.assertEqual(raw["Tot Fwd Pkts"], 3.0)

    def test_bad_values_become_zero(self):
        raw = flow_to_cic({"flow_byts_s": float("inf"), "flow_pkts_s": "nan?"})
        self.assertEqual(raw["Flow Byts/s"], 0.0)
        self.assertEqual(raw["Flow Pkts/s"], 0.0)

    def test_event_keeps_endpoints_and_seconds(self):
        event = flow_to_event({"src_ip": ATTACKER, "dst_ip": VICTIM, "src_port": 50000, "dst_port": 22,
                               "protocol": 6, "flow_duration": 0.5})
        self.assertEqual(event["dst_port"], 22)
        self.assertEqual(event["flow_duration"], 0.5)
        self.assertEqual(event["raw_features"]["Flow Duration"], 500_000.0)


class TestDirectionAndNoise(unittest.TestCase):

    def _event(self, src, dst, sport, dport):
        return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport}

    def test_inbound_to_service_port(self):
        self.assertEqual(flow_direction(self._event(ATTACKER, VICTIM, 50000, 22), {VICTIM}), "inbound")

    def test_outbound_from_this_machine(self):
        self.assertEqual(flow_direction(self._event(VICTIM, "93.184.216.34", 51000, 443), {VICTIM}), "outbound")

    def test_reply_half_of_our_connection_is_outbound(self):
        self.assertEqual(flow_direction(self._event("93.184.216.34", VICTIM, 443, 51000), {VICTIM}), "outbound")

    def test_neither_end_local_is_internal(self):
        self.assertEqual(flow_direction(self._event("10.0.0.5", "10.0.0.6", 50000, 80), {VICTIM}), "internal")

    def test_noise(self):
        self.assertTrue(is_noise("127.0.0.1", VICTIM))
        self.assertTrue(is_noise(VICTIM, "239.255.255.250"))
        self.assertTrue(is_noise(VICTIM, "192.168.56.255"))
        self.assertTrue(is_noise("169.254.1.2", VICTIM))
        self.assertFalse(is_noise(ATTACKER, VICTIM))


class TestLiveFlowSession(unittest.TestCase):

    def test_closed_flow_emitted_after_grace(self):
        flows = []
        session = _make_session(flows.append)
        packets = _handshake(1000.0)
        for p in packets:
            session.process(p)
        session.garbage_collect(1000.5)
        self.assertEqual(flows, [], "should wait for the FIN grace period")
        session.garbage_collect(1002.0)
        self.assertEqual(len(flows), 1)

        event = flow_to_event(flows[0])
        self.assertEqual((event["src_ip"], event["dst_ip"], event["dst_port"]), (ATTACKER, VICTIM, 22))
        raw = event["raw_features"]
        self.assertEqual(raw["Tot Fwd Pkts"], 4)
        self.assertEqual(raw["Tot Bwd Pkts"], 3)
        self.assertEqual(raw["TotLen Fwd Pkts"], 40)
        self.assertEqual(raw["TotLen Bwd Pkts"], 60)
        self.assertAlmostEqual(raw["Flow Duration"], 31_000.0, delta=1.0)
        self.assertEqual(raw["Init Fwd Win Byts"], 64240)

    def test_java_cicflowmeter_semantics(self):
        """Payload lengths, TCP header lengths and sample std, like the training CSVs."""
        flows = []
        session = _make_session(flows.append)
        for p in _handshake(1000.0):
            session.process(p)
        session.garbage_collect(None)
        raw = flow_to_event(flows[0])["raw_features"]

        self.assertEqual(raw["Fwd Pkt Len Min"], 0)
        self.assertEqual(raw["Fwd Pkt Len Max"], 40)
        self.assertEqual(raw["Fwd Pkt Len Mean"], 10)
        self.assertAlmostEqual(raw["Fwd Pkt Len Std"], 20.0)  # sample std of [0, 0, 40, 0]
        self.assertEqual(raw["Fwd Header Len"], 4 * 20)
        self.assertEqual(raw["Bwd Header Len"], 3 * 20)
        self.assertEqual(raw["Fwd Seg Size Min"], 20)
        self.assertAlmostEqual(raw["Pkt Size Avg"], 100 / 7)
        self.assertAlmostEqual(raw["Flow Byts/s"], 100 / 0.031, delta=1.0)
        self.assertEqual(raw["Fwd Act Data Pkts"], 1)
        self.assertEqual(raw["Down/Up Ratio"], 0)
        self.assertAlmostEqual(raw["Flow IAT Max"], 10_000.0, delta=1.0)

    def test_open_flow_emitted_after_idle_timeout(self):
        flows = []
        session = _make_session(flows.append)
        session.process(_pkt(ATTACKER, VICTIM, 50001, 80, "S", 2000.0))
        session.garbage_collect(2000.0 + IDLE_TIMEOUT - 1)
        self.assertEqual(flows, [])
        session.garbage_collect(2000.0 + IDLE_TIMEOUT + 1)
        self.assertEqual(len(flows), 1)

    def test_flush_emits_everything(self):
        flows = []
        session = _make_session(flows.append)
        session.process(_pkt(ATTACKER, VICTIM, 50002, 21, "S", 3000.0))
        session.process(_pkt(ATTACKER, VICTIM, 50003, 23, "S", 3000.1))
        session.garbage_collect(None)
        self.assertEqual(len(flows), 2)


if __name__ == "__main__":
    unittest.main()


class BackendSelectionTests(unittest.TestCase):
    def _select(self, npcap, windivert, admin, forced=""):
        from unittest import mock

        import nids.live_capture as lc

        with mock.patch.object(lc, "npcap_available", return_value=npcap), \
             mock.patch.object(lc, "windivert_installed", return_value=windivert), \
             mock.patch.object(lc, "is_admin", return_value=admin), \
             mock.patch.dict("os.environ", {"SENTINEL_CAPTURE_BACKEND": forced}):
            return lc.select_backend()

    def test_npcap_preferred(self):
        self.assertEqual(self._select(True, True, True), ("npcap", ""))

    def test_windivert_fallback_when_admin(self):
        self.assertEqual(self._select(False, True, True), ("windivert", ""))

    def test_windivert_needs_admin(self):
        self.assertEqual(self._select(False, True, False), (None, "needs_admin"))

    def test_nothing_available(self):
        self.assertEqual(self._select(False, False, True), (None, "npcap_missing"))

    def test_forced_windivert(self):
        self.assertEqual(self._select(True, True, True, forced="windivert"), ("windivert", ""))
