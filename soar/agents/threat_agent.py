"""
SentinelAI - Threat Analysis Agent
Performs deep signature forensics, extracts attack evidence indicators,
and maps threats to the MITRE ATT&CK matrix.
"""

from __future__ import annotations
import logging
from typing import Dict, Any, Optional, List

from agents.base_agent import BaseAgent
from core.schemas import FlowEvent, DetectionResult, ThreatEvidence
from core.event_bus import EventBus, Event
from rules.policy_engine import PolicyEngine

logger = logging.getLogger("SentinelAI.ThreatAgent")


class ThreatAnalysisAgent(BaseAgent):
    """
    Forensic analysis agent that isolates anomalous metrics, builds explainable evidence,
    and correlates observed threats with MITRE ATT&CK Tactics & Techniques.
    """

    def __init__(self, policy_engine: Optional[PolicyEngine] = None, event_bus: Optional[EventBus] = None):
        super().__init__(name="ThreatAnalysisAgent", event_bus=event_bus)
        self.policy_engine = policy_engine or PolicyEngine()

    def _on_initialize(self) -> None:
        if self.event_bus:
            self.event_bus.subscribe("detection.completed", self.process, priority=3, agent_name=self.name)

    def _handle_event(self, event: Event) -> Optional[ThreatEvidence]:
        data = event.data
        if not isinstance(data, dict) or "flow" not in data or "detection" not in data:
            logger.warning("ThreatAnalysisAgent received malformed data payload: %s", type(data))
            return None

        flow: FlowEvent = data["flow"]
        detection: DetectionResult = data["detection"]

        evidence = self.analyze_threat(flow, detection)
        if self.event_bus:
            # Publish with accumulated context for the Risk & Decision agents
            enriched_payload = {
                "flow": flow,
                "detection": detection,
                "threat": evidence
            }
            self.event_bus.publish("threat.analyzed", enriched_payload, sender=self.name)
        return evidence

    def analyze_threat(self, flow: FlowEvent, detection: DetectionResult) -> ThreatEvidence:
        """
        Synthesize forensic indicators and align with MITRE ATT&CK technique taxonomy.
        """
        attack_type = detection.attack_type
        indicators: List[str] = []
        observed: Dict[str, Any] = {}

        # 1. MITRE Mapping lookup
        tech_id, tech_name, tactic, description = self.policy_engine.get_mitre_mapping(attack_type)

        # 2. Forensic Indicator Synthesis based on attack profile
        if attack_type.upper() == "PORTSCAN":
            indicators.append(f"Elevated SYN flag transmission ({flow.syn_flag_count} SYN pkts)")
            indicators.append(f"High packet velocity ({flow.flow_pkts_s:.1f} pkts/s) with minimal return traffic")
            indicators.append(f"Asymmetric connection attempt toward target port {flow.dst_port}")
            explanation = (
                f"Rapid SYN probes ({flow.flow_pkts_s:.1f} pkts/s) targeting port {flow.dst_port}. "
                f"Zero/minimal ACK acknowledgments indicate port sweep discovery behavior."
            )
            signature = "SIG_RECON_PORTSCAN_SYN_SWEEP"
            observed = {
                "syn_flag_count": flow.syn_flag_count,
                "flow_pkts_s": flow.flow_pkts_s,
                "target_port": flow.dst_port
            }

        elif attack_type.upper() == "DDOS" or attack_type.upper() == "DOS":
            indicators.append(f"Abnormal bandwidth volume ({flow.flow_bytes_s:,.0f} bytes/sec)")
            indicators.append(f"High forward packet burst ({flow.tot_fwd_pkts} pkts in {flow.flow_duration:.2f}s)")
            indicators.append("Resource exhaustion pattern consistent with distributed denial of service")
            explanation = (
                f"Volumetric flood detected: {flow.flow_bytes_s:,.0f} B/s and {flow.flow_pkts_s:.1f} pkts/s. "
                f"Traffic parameters exceed safe network ingestion baselines."
            )
            signature = "SIG_IMPACT_DDOS_VOLUMETRIC_FLOOD"
            observed = {
                "flow_bytes_s": flow.flow_bytes_s,
                "tot_fwd_pkts": flow.tot_fwd_pkts,
                "duration": flow.flow_duration
            }

        elif (
            attack_type.upper() in ("BRUTEFORCE", "SSH-BRUTEFORCE", "FTP-BRUTEFORCE")
            or "BRUTE" in attack_type.upper()
        ):
            indicators.append(f"Repeated short-lived connections to sensitive auth port {flow.dst_port}")
            indicators.append(f"High connection repetition rate ({flow.tot_fwd_pkts} pkts)")
            indicators.append(f"Credential stuffing pattern ({attack_type})")
            explanation = (
                f"Repeated rapid connection attempts ({attack_type}) directed at authentication "
                f"service on port {flow.dst_port}. Consistent with credential discovery or dictionary attacks."
            )
            signature = "SIG_CRED_BRUTEFORCE_AUTH_BURST"
            observed = {
                "target_port": flow.dst_port,
                "fwd_packets": flow.tot_fwd_pkts,
                "duration": flow.flow_duration,
                "attack_label": attack_type,
            }

        elif attack_type.upper() == "BOTNET":
            indicators.append(f"Persistent periodic beaconing on non-standard port {flow.dst_port}")
            indicators.append(f"Uniform payload packet length ({flow.fwd_pkt_len_mean:.1f} bytes)")
            indicators.append("Command & Control (C2) heartbeat heartbeat signature")
            explanation = (
                f"Repetitive uniform packet bursts ({flow.fwd_pkt_len_mean:.1f} bytes mean length) to port {flow.dst_port}, "
                f"matching known botnet telemetry patterns."
            )
            signature = "SIG_C2_BOTNET_HEARTBEAT"
            observed = {
                "target_port": flow.dst_port,
                "mean_length": flow.fwd_pkt_len_mean
            }

        else:
            # BENIGN
            indicators.append("Standard bidirectional packet flow")
            indicators.append(f"Packet rates within normal operating baseline ({flow.flow_pkts_s:.1f} pkts/s)")
            explanation = "Normal legitimate network communication adhering to enterprise network policies."
            signature = "SIG_NORMAL_BASELINE"
            observed = {
                "flow_pkts_s": flow.flow_pkts_s,
                "flow_bytes_s": flow.flow_bytes_s
            }

        return ThreatEvidence(
            indicators=indicators,
            anomaly_explanation=explanation,
            mitre_technique_id=tech_id,
            mitre_technique_name=tech_name,
            mitre_tactic=tactic,
            signature_match=signature,
            observed_metrics=observed
        )
