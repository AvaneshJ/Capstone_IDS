"""
SentinelAI - Packet Ingest Agent
Bridges raw network flow dictionaries from Member 2's sniffer/PCAP queue into validated FlowEvents.
"""

from __future__ import annotations
import math
import logging
from typing import Dict, Any, Optional

from agents.base_agent import BaseAgent
from core.schemas import FlowEvent
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.PacketAgent")


class PacketAgent(BaseAgent):
    """
    Validates, sanitizes, and normalizes raw network flow telemetry from Member 2.
    Cleans NaNs, infinite values, coerces types, and publishes structured FlowEvents.
    """

    def __init__(self, event_bus: Optional[EventBus] = None):
        super().__init__(name="PacketIngestAgent", event_bus=event_bus)

    def _on_initialize(self) -> None:
        if self.event_bus:
            # Can listen to raw packet inputs or be driven via direct method calls
            self.event_bus.subscribe("packet.raw", self.process, priority=1, agent_name=self.name)

    def _handle_event(self, event: Event) -> Optional[FlowEvent]:
        raw_data = event.data
        if not isinstance(raw_data, dict):
            logger.warning("PacketAgent received non-dict payload: %s", type(raw_data))
            return None

        flow_event = self.sanitize_flow(raw_data)
        if flow_event and self.event_bus:
            self.event_bus.publish("flow.ingested", flow_event, sender=self.name)
        return flow_event

    def sanitize_flow(self, raw: Dict[str, Any]) -> FlowEvent:
        """
        Validate dictionary fields, handle NaN/Inf, map common network feature names,
        and instantiate a clean FlowEvent.
        """
        def safe_float(val: Any, default: float = 0.0) -> float:
            try:
                f = float(val)
                return default if (math.isnan(f) or math.isinf(f)) else f
            except (ValueError, TypeError):
                return default

        def safe_int(val: Any, default: int = 0) -> int:
            try:
                f = float(val)
                if math.isnan(f) or math.isinf(f):
                    return default
                return int(f)
            except (ValueError, TypeError):
                return default

        def safe_str(val: Any, default: str = "0.0.0.0") -> str:
            if val is None or str(val).strip() == "":
                return default
            return str(val).strip()

        # Flexible key mapping for diverse datasets (e.g. CIC-IDS2017, custom scapy sniffer)
        src_ip = safe_str(raw.get("src_ip") or raw.get("Source IP") or raw.get("src") or "127.0.0.1")
        dst_ip = safe_str(raw.get("dst_ip") or raw.get("Destination IP") or raw.get("dst") or "127.0.0.1")
        src_port = safe_int(raw.get("src_port") or raw.get("Source Port") or raw.get("sport") or 0)
        dst_port = safe_int(raw.get("dst_port") or raw.get("Destination Port") or raw.get("dport") or 0)
        protocol = safe_int(raw.get("protocol") or raw.get("Protocol") or raw.get("proto") or 6)

        flow_duration = safe_float(raw.get("flow_duration") or raw.get("Flow Duration") or raw.get("duration") or 0.0)
        tot_fwd_pkts = safe_int(raw.get("tot_fwd_pkts") or raw.get("Total Fwd Packets") or raw.get("fwd_pkts") or 0)
        tot_bwd_pkts = safe_int(raw.get("tot_bwd_pkts") or raw.get("Total Backward Packets") or raw.get("bwd_pkts") or 0)
        fwd_pkt_len_mean = safe_float(raw.get("fwd_pkt_len_mean") or raw.get("Fwd Packet Length Mean") or 0.0)
        bwd_pkt_len_mean = safe_float(raw.get("bwd_pkt_len_mean") or raw.get("Bwd Packet Length Mean") or 0.0)
        flow_bytes_s = safe_float(raw.get("flow_bytes_s") or raw.get("Flow Bytes/s") or 0.0)
        flow_pkts_s = safe_float(raw.get("flow_pkts_s") or raw.get("Flow Packets/s") or 0.0)

        syn_flag_count = safe_int(raw.get("syn_flag_count") or raw.get("SYN Flag Count") or raw.get("syn_count") or 0)
        ack_flag_count = safe_int(raw.get("ack_flag_count") or raw.get("ACK Flag Count") or raw.get("ack_count") or 0)
        rst_flag_count = safe_int(raw.get("rst_flag_count") or raw.get("RST Flag Count") or raw.get("rst_count") or 0)
        psh_flag_count = safe_int(raw.get("psh_flag_count") or raw.get("PSH Flag Count") or 0)
        fin_flag_count = safe_int(raw.get("fin_flag_count") or raw.get("FIN Flag Count") or 0)

        flow_event = FlowEvent(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            flow_duration=flow_duration,
            tot_fwd_pkts=tot_fwd_pkts,
            tot_bwd_pkts=tot_bwd_pkts,
            fwd_pkt_len_mean=fwd_pkt_len_mean,
            bwd_pkt_len_mean=bwd_pkt_len_mean,
            flow_bytes_s=flow_bytes_s,
            flow_pkts_s=flow_pkts_s,
            syn_flag_count=syn_flag_count,
            ack_flag_count=ack_flag_count,
            rst_flag_count=rst_flag_count,
            psh_flag_count=psh_flag_count,
            fin_flag_count=fin_flag_count,
            raw_features=raw
        )

        return flow_event

    def ingest(self, raw_flow: Dict[str, Any]) -> FlowEvent:
        """Direct programmatic ingestion helper."""
        event = Event(topic="packet.raw", data=raw_flow, sender="direct_caller")
        return self.process(event)
