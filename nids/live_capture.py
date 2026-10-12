"""
Live network sensor: sniff packets -> CIC-style flows -> callback.

Flows are built with the Python `cicflowmeter` flow engine and converted to the 77 CIC
column names the XGBoost model was trained on. The training data (CIC-IDS2018 and the lab
*.pcap_Flow.csv files) came from Java CICFlowMeter, so the fields where the two differ
(payload vs IP length, TCP/UDP vs IP header, sample vs population std, a double-counted
first packet) are recomputed with the Java definitions, and times are scaled from seconds
to microseconds.

A flow is handed to the callback when it:
  * sees FIN or RST and then goes quiet for FIN_GRACE seconds,
  * is idle for IDLE_TIMEOUT seconds, or
  * reaches MAX_FLOW_DURATION seconds (Java CICFlowMeter's default flow timeout), or
  * holds MAX_FLOW_PACKETS packets. Every packet is kept until the flow is emitted (~6 KB
    each as a scapy object), so a long bulk download would otherwise grow to gigabytes.

Capture backends (IPv4 TCP/UDP only), picked in this order:
  * npcap     - scapy + Npcap (https://npcap.com), works without admin on a default install.
  * windivert - WinDivert driver shipped inside pydivert (LGPL, redistributable), sniff-only
                mode so packets are never delayed or dropped. Needs Administrator.
SENTINEL_CAPTURE_BACKEND=npcap|windivert forces one.

Quick check from repo root:
  python -m nids.live_capture            # print flows for 60 s
  python -m nids.live_capture --list     # show interfaces
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("SentinelAI.LiveCapture")

IDLE_TIMEOUT = 30.0
MAX_FLOW_DURATION = 120.0
MAX_FLOW_PACKETS = 5000
FIN_GRACE = 1.0
GC_INTERVAL = 1.0
CAPTURE_FILTER = "ip and (tcp or udp)"
WINDIVERT_FILTER = "ip and (tcp or udp) and not loopback"
BACKENDS = ("npcap", "windivert")

# Windows hands out ephemeral client ports from this range.
EPHEMERAL_PORT_MIN = 49152

# cicflowmeter (Python) field -> CIC-IDS2018 column used by the model
CICFLOWMETER_TO_CIC: Dict[str, str] = {
    "protocol": "Protocol",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Tot Fwd Pkts",
    "tot_bwd_pkts": "Tot Bwd Pkts",
    "totlen_fwd_pkts": "TotLen Fwd Pkts",
    "totlen_bwd_pkts": "TotLen Bwd Pkts",
    "fwd_pkt_len_max": "Fwd Pkt Len Max",
    "fwd_pkt_len_min": "Fwd Pkt Len Min",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean",
    "fwd_pkt_len_std": "Fwd Pkt Len Std",
    "bwd_pkt_len_max": "Bwd Pkt Len Max",
    "bwd_pkt_len_min": "Bwd Pkt Len Min",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean",
    "bwd_pkt_len_std": "Bwd Pkt Len Std",
    "flow_byts_s": "Flow Byts/s",
    "flow_pkts_s": "Flow Pkts/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Tot",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Tot",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Len",
    "bwd_header_len": "Bwd Header Len",
    "fwd_pkts_s": "Fwd Pkts/s",
    "bwd_pkts_s": "Bwd Pkts/s",
    "pkt_len_min": "Pkt Len Min",
    "pkt_len_max": "Pkt Len Max",
    "pkt_len_mean": "Pkt Len Mean",
    "pkt_len_std": "Pkt Len Std",
    "pkt_len_var": "Pkt Len Var",
    "fin_flag_cnt": "FIN Flag Cnt",
    "syn_flag_cnt": "SYN Flag Cnt",
    "rst_flag_cnt": "RST Flag Cnt",
    "psh_flag_cnt": "PSH Flag Cnt",
    "ack_flag_cnt": "ACK Flag Cnt",
    "urg_flag_cnt": "URG Flag Cnt",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Cnt",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Pkt Size Avg",
    "fwd_seg_size_avg": "Fwd Seg Size Avg",
    "bwd_seg_size_avg": "Bwd Seg Size Avg",
    "fwd_byts_b_avg": "Fwd Byts/b Avg",
    "fwd_pkts_b_avg": "Fwd Pkts/b Avg",
    "fwd_blk_rate_avg": "Fwd Blk Rate Avg",
    "bwd_byts_b_avg": "Bwd Byts/b Avg",
    "bwd_pkts_b_avg": "Bwd Pkts/b Avg",
    "bwd_blk_rate_avg": "Bwd Blk Rate Avg",
    "subflow_fwd_pkts": "Subflow Fwd Pkts",
    "subflow_fwd_byts": "Subflow Fwd Byts",
    "subflow_bwd_pkts": "Subflow Bwd Pkts",
    "subflow_bwd_byts": "Subflow Bwd Byts",
    "init_fwd_win_byts": "Init Fwd Win Byts",
    "init_bwd_win_byts": "Init Bwd Win Byts",
    "fwd_act_data_pkts": "Fwd Act Data Pkts",
    "fwd_seg_size_min": "Fwd Seg Size Min",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

# Seconds in cicflowmeter, microseconds in CIC-IDS2018
TIME_FIELDS = frozenset(
    {"flow_duration"}
    | {f"{p}_{s}" for p in ("flow_iat", "fwd_iat", "bwd_iat") for s in ("mean", "std", "max", "min")}
    | {"fwd_iat_tot", "bwd_iat_tot"}
    | {f"{p}_{s}" for p in ("active", "idle") for s in ("mean", "std", "max", "min")}
)


def _num(value: Any) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f != f or f in (float("inf"), float("-inf")):
        return 0.0
    return f


def flow_to_cic(data: Dict[str, Any]) -> Dict[str, float]:
    """cicflowmeter Flow.get_data() -> 77 CIC features (training units)."""
    raw: Dict[str, float] = {}
    for src, cic in CICFLOWMETER_TO_CIC.items():
        value = _num(data.get(src, 0.0))
        if src in TIME_FIELDS:
            value *= 1_000_000.0
        raw[cic] = value
    return raw


def flow_to_event(data: Dict[str, Any]) -> Dict[str, Any]:
    """cicflowmeter Flow.get_data() -> the flow dict SentinelOrchestrator.process_flow() accepts."""
    raw = flow_to_cic(data)
    return {
        "src_ip": str(data.get("src_ip", "")),
        "dst_ip": str(data.get("dst_ip", "")),
        "src_port": int(_num(data.get("src_port"))),
        "dst_port": int(_num(data.get("dst_port"))),
        "protocol": int(_num(data.get("protocol"))) or 6,
        "flow_duration": _num(data.get("flow_duration")),
        "tot_fwd_pkts": int(raw["Tot Fwd Pkts"]),
        "tot_bwd_pkts": int(raw["Tot Bwd Pkts"]),
        "fwd_pkt_len_mean": raw["Fwd Pkt Len Mean"],
        "bwd_pkt_len_mean": raw["Bwd Pkt Len Mean"],
        "flow_bytes_s": raw["Flow Byts/s"],
        "flow_pkts_s": raw["Flow Pkts/s"],
        "syn_flag_count": int(raw["SYN Flag Cnt"]),
        "ack_flag_count": int(raw["ACK Flag Cnt"]),
        "rst_flag_count": int(raw["RST Flag Cnt"]),
        "psh_flag_count": int(raw["PSH Flag Cnt"]),
        "fin_flag_count": int(raw["FIN Flag Cnt"]),
        "raw_features": raw,
        "source": "live_capture",
    }


# -------------------------------------------------------------
# Addresses and direction
# -------------------------------------------------------------

def local_ipv4_addresses() -> Set[str]:
    """IPv4 addresses assigned to this machine (all adapters)."""
    import socket

    import psutil

    addrs: Set[str] = set()
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            if entry.family == socket.AF_INET and entry.address:
                addrs.add(entry.address)
    return addrs


def is_noise(src_ip: str, dst_ip: str) -> bool:
    """Loopback, multicast, broadcast and link-local traffic is never scored."""
    for ip in (src_ip, dst_ip):
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return True
        if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified:
            return True
        if ip == "255.255.255.255" or ip.endswith(".255"):
            return True
    return False


def flow_direction(event: Dict[str, Any], local_ips: Set[str]) -> str:
    """
    'inbound'  : a remote host opened a connection to this machine (what the model was trained on)
    'outbound' : this machine opened the connection, or the flow is the reply side of one
    'internal' : both ends are this machine / neither end is this machine
    """
    src_local = event["src_ip"] in local_ips
    dst_local = event["dst_ip"] in local_ips
    if src_local == dst_local:
        return "internal"
    if src_local:
        return "outbound"
    # A remote "initiator" talking to one of our ephemeral ports is the reply half of a connection
    # we opened (the flow was split by a timeout or started before capture).
    if event["dst_port"] >= EPHEMERAL_PORT_MIN and event["src_port"] < EPHEMERAL_PORT_MIN:
        return "outbound"
    return "inbound"


# -------------------------------------------------------------
# Capture availability / interfaces
# -------------------------------------------------------------

def is_admin() -> bool:
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def npcap_available() -> bool:
    if os.name != "nt":
        return True
    import scapy.all  # noqa: F401  (conf.use_pcap / conf.ifaces are only set once the arch layer loads)
    from scapy.config import conf

    return bool(conf.use_pcap)


def windivert_installed() -> bool:
    if os.name != "nt":
        return False
    try:
        import pydivert  # noqa: F401
    except Exception:
        return False
    return True


def select_backend() -> Tuple[Optional[str], str]:
    """(backend, reason). backend is None when capture can't run; reason says why.

    Reasons: scapy_missing, cicflowmeter_missing, npcap_missing (no Npcap and no WinDivert),
    needs_admin (WinDivert available but the engine isn't elevated).
    """
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return None, "scapy_missing"
    try:
        import cicflowmeter  # noqa: F401
    except ImportError:
        return None, "cicflowmeter_missing"

    forced = os.getenv("SENTINEL_CAPTURE_BACKEND", "").strip().lower()
    order = [forced] if forced in BACKENDS else list(BACKENDS)
    reason = "npcap_missing"
    for backend in order:
        if backend == "npcap" and npcap_available():
            return "npcap", ""
        if backend == "windivert" and windivert_installed():
            if is_admin():
                return "windivert", ""
            reason = "needs_admin"
    return None, reason


def capture_available() -> Tuple[bool, str]:
    """(ok, reason). See select_backend for the reasons."""
    backend, reason = select_backend()
    return backend is not None, reason


def _psutil_interfaces() -> List[Dict[str, Any]]:
    """Adapters with a usable IPv4 address, from the OS (no capture driver needed)."""
    import socket

    import psutil

    stats = psutil.net_if_stats()
    out: List[Dict[str, Any]] = []
    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        ips = [a.address for a in addrs if a.family == socket.AF_INET]
        usable = [ip for ip in ips if not ip.startswith(("127.", "169.254."))]
        if usable:
            out.append({"name": name, "description": name, "ips": usable, "network_name": name})
    return out


def list_capture_interfaces() -> List[Dict[str, Any]]:
    """Interfaces with a usable IPv4 address (loopback / link-local only adapters skipped)."""
    import scapy.all  # noqa: F401
    from scapy.config import conf

    out: List[Dict[str, Any]] = []
    for iface in (conf.ifaces or {}).values():
        ips = [ip for ip in (getattr(iface, "ips", {}) or {}).get(4, []) if ip]
        usable = [ip for ip in ips if not ip.startswith(("127.", "169.254."))]
        if not usable:
            continue
        out.append({
            "name": getattr(iface, "name", str(iface)),
            "description": getattr(iface, "description", "") or getattr(iface, "name", ""),
            "ips": usable,
            "network_name": getattr(iface, "network_name", ""),
        })
    return out


# -------------------------------------------------------------
# Java CICFlowMeter semantics
# -------------------------------------------------------------
# cicflowmeter-python measures packet length as the whole IP packet, header length as the IP
# header and uses population std. The CIC-IDS2018 / lab training data (Java CICFlowMeter) uses
# the transport payload, the TCP/UDP header and sample std, so those fields are recomputed.

def _transport_sizes(pkt) -> Tuple[int, int]:
    """(payload bytes, transport header bytes) from the IP / TCP / UDP length fields."""
    ip = pkt["IP"]
    ip_payload = max(int(ip.len or len(ip)) - int(ip.ihl or 5) * 4, 0)
    if "TCP" in pkt:
        header = int(pkt["TCP"].dataofs or 5) * 4
    elif "UDP" in pkt:
        header = 8
    else:
        return ip_payload, 0
    return max(ip_payload - header, 0), header


def _stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"total": 0.0, "max": 0.0, "min": 0.0, "mean": 0.0, "std": 0.0, "var": 0.0}
    n = len(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / (n - 1) if n > 1 else 0.0
    return {"total": float(sum(values)), "max": float(max(values)), "min": float(min(values)),
            "mean": mean, "std": var ** 0.5, "var": var}


def java_cicflowmeter_fields(packets: List[Tuple[Any, Any]]) -> Dict[str, float]:
    """Length, header, rate and IAT fields with Java CICFlowMeter definitions (times in seconds)."""
    fwd_len: List[float] = []
    bwd_len: List[float] = []
    fwd_hdr: List[int] = []
    bwd_hdr: List[int] = []
    times: List[float] = []
    fwd_times: List[float] = []
    bwd_times: List[float] = []
    for pkt, direction in packets:
        payload, header = _transport_sizes(pkt)
        t = float(pkt.time)
        times.append(t)
        if getattr(direction, "name", str(direction)).endswith("FORWARD"):
            fwd_len.append(payload)
            fwd_hdr.append(header)
            fwd_times.append(t)
        else:
            bwd_len.append(payload)
            bwd_hdr.append(header)
            bwd_times.append(t)

    def iats(ts: List[float]) -> List[float]:
        ts = sorted(ts)
        return [b - a for a, b in zip(ts, ts[1:])]

    fwd, bwd, both = _stats(fwd_len), _stats(bwd_len), _stats(fwd_len + bwd_len)
    flow_iat, fwd_iat, bwd_iat = _stats(iats(times)), _stats(iats(fwd_times)), _stats(iats(bwd_times))
    duration = (max(times) - min(times)) if times else 0.0
    total_bytes = fwd["total"] + bwd["total"]
    count = len(fwd_len) + len(bwd_len)

    out: Dict[str, float] = {
        "totlen_fwd_pkts": fwd["total"],
        "totlen_bwd_pkts": bwd["total"],
        "pkt_size_avg": total_bytes / count if count else 0.0,
        "flow_byts_s": total_bytes / duration if duration > 0 else 0.0,
        "fwd_header_len": float(sum(fwd_hdr)),
        "bwd_header_len": float(sum(bwd_hdr)),
        "fwd_seg_size_min": float(min(fwd_hdr)) if fwd_hdr else 0.0,
        "down_up_ratio": float(len(bwd_len) // len(fwd_len)) if fwd_len else 0.0,
        "subflow_fwd_byts": fwd["total"],
        "subflow_bwd_byts": bwd["total"],
        "pkt_len_var": both["var"],
        "fwd_iat_tot": fwd_iat["total"],
        "bwd_iat_tot": bwd_iat["total"],
    }
    for prefix, s in (("fwd_pkt_len", fwd), ("bwd_pkt_len", bwd), ("pkt_len", both)):
        for stat in ("max", "min", "mean", "std"):
            out[f"{prefix}_{stat}"] = s[stat]
    for prefix, s in (("flow_iat", flow_iat), ("fwd_iat", fwd_iat), ("bwd_iat", bwd_iat)):
        for stat in ("max", "min", "mean", "std"):
            out[f"{prefix}_{stat}"] = s[stat]
    out["fwd_seg_size_avg"] = out["fwd_pkt_len_mean"]
    out["bwd_seg_size_avg"] = out["bwd_pkt_len_mean"]
    return out


# -------------------------------------------------------------
# Flow session with live-friendly expiry
# -------------------------------------------------------------

def _make_session(on_flow: Callable[[Dict[str, Any]], None]):
    import cicflowmeter.flow_session as flow_session
    from cicflowmeter.flow import Flow
    from cicflowmeter.flow_session import FlowSession

    class _JavaCompatibleFlow(Flow):
        def add_packet(self, packet, direction) -> None:
            # cicflowmeter 0.5.0 stores the first packet in Flow.__init__ and FlowSession.process()
            # adds it again (one extra forward packet and a zero IAT per flow).
            if len(self.packets) == 1 and self.packets[0][0] is packet:
                return
            super().add_packet(packet, direction)

        def get_data(self, include_fields=None) -> dict:
            data = super().get_data()
            data.update(java_cicflowmeter_fields(self.packets))
            if include_fields is not None:
                data = {k: v for k, v in data.items() if k in include_fields}
            return data

    flow_session.Flow = _JavaCompatibleFlow

    class _CallbackWriter:
        def write(self, data: Dict[str, Any]) -> None:
            on_flow(data)

    class LiveFlowSession(FlowSession):
        """FlowSession that emits finished flows to a callback instead of a CSV / URL."""

        def __init__(self) -> None:
            super().__init__(output_mode="csv", output=os.devnull)
            self.output_writer = _CallbackWriter()

        @staticmethod
        def _closed(flow) -> bool:
            for pkt, _ in flow.packets[-4:]:
                if "TCP" in pkt:
                    flags = pkt["TCP"].flags
                    if "F" in flags or "R" in flags:
                        return True
            return False

        def garbage_collect(self, latest_time) -> None:
            with self._lock:
                items = list(self.flows.items())
            for key, flow in items:
                if latest_time is not None:
                    idle = float(latest_time) - float(flow.latest_timestamp)
                    done = (
                        idle >= IDLE_TIMEOUT
                        or float(flow.duration) >= MAX_FLOW_DURATION
                        or len(flow.packets) >= MAX_FLOW_PACKETS
                        or (idle >= FIN_GRACE and self._closed(flow))
                    )
                    if not done:
                        continue
                with self._lock:
                    if self.flows.get(key) is not flow:
                        continue
                    del self.flows[key]
                try:
                    data = flow.get_data(self.fields)
                except Exception as exc:  # malformed / single odd packet
                    logger.debug("Skipping flow that failed feature extraction: %s", exc)
                    continue
                self.output_writer.write(data)

    return LiveFlowSession()


class NetworkSensor:
    """Sniffs the given interfaces (default: every adapter with an IPv4 address) and emits CIC flows."""

    def __init__(
        self,
        on_flow: Callable[[Dict[str, Any]], None],
        interfaces: Optional[Iterable[str]] = None,
    ) -> None:
        self.on_flow = on_flow
        self.requested_interfaces = list(interfaces) if interfaces else None
        self.interfaces: List[str] = []
        self.backend: str = ""
        self.packets_seen = 0
        self.flows_emitted = 0
        self.started_at: Optional[float] = None
        self.error: str = ""
        self._sniffer = None
        self._divert = None
        self._divert_thread: Optional[threading.Thread] = None
        self._session = None
        self._stop = threading.Event()
        self._gc_thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        if self.backend == "windivert":
            return self._divert_thread is not None and self._divert_thread.is_alive()
        return self._sniffer is not None and bool(getattr(self._sniffer, "running", False))

    def _emit(self, data: Dict[str, Any]) -> None:
        self.flows_emitted += 1
        try:
            self.on_flow(flow_to_event(data))
        except Exception as exc:
            logger.error("Live flow handler failed: %s", exc)

    def _on_packet(self, pkt) -> None:
        self.packets_seen += 1
        self._session.process(pkt)

    def start(self) -> None:
        backend, reason = select_backend()
        if backend is None:
            raise RuntimeError(reason)

        self._session = _make_session(self._emit)
        self._stop.clear()
        if backend == "npcap":
            self._start_npcap()
        else:
            self._start_windivert()
        self.backend = backend
        self.started_at = time.time()
        self._gc_thread = threading.Thread(target=self._gc_loop, name="nids-flow-gc", daemon=True)
        self._gc_thread.start()
        logger.info(
            "Live capture started (%s) on %d interface(s): %s",
            backend, len(self.interfaces), ", ".join(self.interfaces),
        )

    def _start_npcap(self) -> None:
        from scapy.sendrecv import AsyncSniffer

        if self.requested_interfaces:
            self.interfaces = self.requested_interfaces
        else:
            self.interfaces = [i["name"] for i in list_capture_interfaces()]
        if not self.interfaces:
            raise RuntimeError("no_interfaces")
        self._sniffer = AsyncSniffer(
            iface=self.interfaces if len(self.interfaces) > 1 else self.interfaces[0],
            filter=CAPTURE_FILTER,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    def _start_windivert(self) -> None:
        import pydivert

        # WinDivert sees every adapter at the IP layer; interface selection isn't supported.
        self.interfaces = [i["name"] for i in _psutil_interfaces()] or ["all adapters"]
        self._divert = pydivert.WinDivert(
            WINDIVERT_FILTER,
            layer=pydivert.Layer.NETWORK,
            flags=pydivert.Flag.SNIFF | pydivert.Flag.RECV_ONLY,
        )
        self._divert.open()
        self._divert_thread = threading.Thread(target=self._divert_loop, name="nids-windivert", daemon=True)
        self._divert_thread.start()

    def _divert_loop(self) -> None:
        from scapy.layers.inet import IP

        divert = self._divert
        while not self._stop.is_set():
            try:
                packet = divert.recv()
            except Exception as exc:
                if not self._stop.is_set():
                    self.error = f"windivert: {exc}"
                    logger.error("WinDivert capture stopped: %s", exc)
                return
            try:
                pkt = IP(bytes(packet.raw))
                pkt.time = time.time()
                self._on_packet(pkt)
            except Exception as exc:
                logger.debug("Skipping packet WinDivert couldn't decode: %s", exc)

    def _gc_loop(self) -> None:
        while not self._stop.wait(GC_INTERVAL):
            try:
                self._session.garbage_collect(time.time())
            except Exception as exc:
                logger.debug("Flow GC error: %s", exc)
            if self.backend == "windivert":
                if not self.running and not self._stop.is_set():
                    self.error = self.error or "capture_stopped"
                    break
                continue
            sniffer = self._sniffer
            if sniffer is not None and not getattr(sniffer, "running", False):
                exc = getattr(sniffer, "exception", None)
                self.error = str(exc) if exc else "capture_stopped"
                logger.error("Live capture stopped unexpectedly: %s", self.error)
                break

    def stop(self) -> None:
        self._stop.set()
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
        divert, self._divert = self._divert, None
        if divert is not None:
            try:
                divert.close()
            except Exception:
                pass
        if self._divert_thread is not None:
            self._divert_thread.join(timeout=2.0)
        if self._gc_thread is not None:
            self._gc_thread.join(timeout=2.0)
        if self._session is not None:
            try:
                self._session.garbage_collect(None)
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelAI live capture smoke test (prints flows)")
    parser.add_argument("--list", action="store_true", help="List capture interfaces and exit")
    parser.add_argument("--iface", action="append", help="Interface name (repeatable). Default: all with IPv4")
    parser.add_argument("--duration", type=float, default=60.0, help="Seconds to capture")
    args = parser.parse_args()

    backend, reason = select_backend()
    if backend is None:
        hint = (
            "Run this terminal as Administrator (WinDivert) or install Npcap from https://npcap.com."
            if reason == "needs_admin"
            else "Install Npcap from https://npcap.com, or `pip install pydivert` and run as Administrator."
        )
        print(f"Live capture unavailable: {reason}. {hint}")
        return
    if args.list:
        listing = list_capture_interfaces() if backend == "npcap" else _psutil_interfaces()
        for iface in listing:
            print(f"{iface['name']}: {', '.join(iface['ips'])}  ({iface['description']})")
        return

    local_ips = local_ipv4_addresses()

    def show(event: Dict[str, Any]) -> None:
        tag = "noise" if is_noise(event["src_ip"], event["dst_ip"]) else flow_direction(event, local_ips)
        raw = event["raw_features"]
        print(
            f"[{tag:8}] {event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']} "
            f"proto {event['protocol']} pkts {int(raw['Tot Fwd Pkts'])}/{int(raw['Tot Bwd Pkts'])} "
            f"dur {event['flow_duration']:.2f}s"
        )

    sensor = NetworkSensor(show, interfaces=args.iface)
    sensor.start()
    print(f"Capturing with {sensor.backend} on {sensor.interfaces} for {args.duration:.0f}s ...")
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        sensor.stop()
        print(f"{sensor.packets_seen} packets, {sensor.flows_emitted} flows")


if __name__ == "__main__":
    main()
