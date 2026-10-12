"""
SentinelAI - GenAI SOC Explanation Agent
Generates plain-English SOC analyst briefings using Google Gemini API, local Ollama,
or a built-in expert security analysis system.
"""

from __future__ import annotations
import os
import json
import logging
import httpx
from typing import Dict, Any, Optional, List

from agents.base_agent import BaseAgent
from core.schemas import Incident, HostIncident, LLMExplanation
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.LLMAgent")


class LLMExplanationAgent(BaseAgent):
    """
    GenAI SOC Analyst Assistant.
    Translates raw network metrics, detection labels, and MITRE evidence into
    human-readable executive briefings and tactical remediation playbooks.
    """

    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        ollama_endpoint: str = "http://localhost:11434",
        ollama_model: str = "llama3",
        event_bus: Optional[EventBus] = None
    ):
        super().__init__(name="LLMExplanationAgent", event_bus=event_bus)
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.ollama_endpoint = ollama_endpoint
        self.ollama_model = ollama_model

    def _on_initialize(self) -> None:
        # Briefings are invoked synchronously by SentinelOrchestrator.process_flow
        # (so explanation is attached before DB persist). Do not also subscribe to
        # incident.created — that duplicated Gemini/Ollama calls and slowed demos.
        return

    def _handle_event(self, event: Event) -> Optional[LLMExplanation]:
        data = event.data
        if not isinstance(data, Incident):
            return None

        incident: Incident = data
        if incident.detection.attack_type.upper() == "BENIGN" and incident.risk.score < 4.0:
            return None

        explanation = self.generate_briefing(incident)
        incident.llm_explanation = explanation

        if self.event_bus:
            self.event_bus.publish("incident.explained", {"incident": incident, "explanation": explanation}, sender=self.name)

        return explanation

    def generate_briefing(self, incident: Incident) -> LLMExplanation:
        """
        Generate SOC narrative using Gemini, Ollama, or Expert System.
        """
        exp = self._try_genai(self._build_prompt(incident))
        if exp:
            return exp

        # 3. Deterministic Expert Security System Fallback
        return self._generate_expert_briefing(incident)

    def generate_host_briefing(self, incident: HostIncident) -> LLMExplanation:
        """Generate SOC narrative for a HIDS host incident using Gemini, Ollama, or Expert System."""
        exp = self._try_genai(self._build_host_prompt(incident))
        if exp:
            return exp
        return self._generate_host_expert_briefing(incident)

    def _try_genai(self, prompt: str) -> Optional[LLMExplanation]:
        # 1. Try Gemini API
        if self.gemini_api_key:
            try:
                exp = self._call_gemini_api(prompt)
                if exp:
                    return exp
            except Exception as exc:
                logger.warning("Gemini API call failed (%s). Falling back.", exc)

        # 2. Try Ollama Local LLM
        try:
            return self._call_ollama(prompt)
        except Exception:
            return None

    def _call_gemini_api(self, prompt: str) -> Optional[LLMExplanation]:
        """Call Google Gemini REST endpoint."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_api_key}"

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
        }

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text_content = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text_content)
                return LLMExplanation(
                    summary=parsed.get("summary", ""),
                    technical_analysis=parsed.get("technical_analysis", ""),
                    mitre_context=parsed.get("mitre_context", ""),
                    soc_recommendations=parsed.get("soc_recommendations", []),
                    provider="GEMINI"
                )
        return None

    def _call_ollama(self, prompt: str) -> Optional[LLMExplanation]:
        """Call local Ollama instance if active."""
        url = f"{self.ollama_endpoint}/api/generate"
        prompt = prompt + "\nOutput valid JSON only with keys: summary, technical_analysis, mitre_context, soc_recommendations."
        
        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        with httpx.Client(timeout=4.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                resp_json = resp.json()
                parsed = json.loads(resp_json["response"])
                return LLMExplanation(
                    summary=parsed.get("summary", ""),
                    technical_analysis=parsed.get("technical_analysis", ""),
                    mitre_context=parsed.get("mitre_context", ""),
                    soc_recommendations=parsed.get("soc_recommendations", []),
                    provider="OLLAMA"
                )
        return None

    def _generate_expert_briefing(self, incident: Incident) -> LLMExplanation:
        """
        Synthesizes expert-level SOC narrative without external network calls.
        """
        attack = incident.detection.attack_type
        src_ip = incident.flow.src_ip
        dst_port = incident.flow.dst_port
        risk = incident.risk.score
        action = incident.action_plan.action_type.value

        if attack.upper() == "PORTSCAN":
            summary = (
                f"Adversary host {src_ip} initiated a reconnaissance SYN scan across network services. "
                f"SentinelAI autonomous firewall triggered action '{action}' to isolate the probing source."
            )
            technical = (
                f"Observed rapid transmission of {incident.flow.syn_flag_count} SYN packets with minimal ACK responses "
                f"at a rate of {incident.flow.flow_pkts_s:.1f} pkts/s targeting port {dst_port}."
            )
            mitre_ctx = (
                f"Correlates with MITRE ATT&CK {incident.threat.mitre_technique_id} ({incident.threat.mitre_technique_name}). "
                "Adversaries frequently employ port scanning in the Discovery phase prior to exploitation."
            )
            recs = [
                f"Verify firewall block rule for IP {src_ip}.",
                f"Inspect external firewall logs for other sweep targets from {src_ip}.",
                f"Ensure services on port {dst_port} are patched and non-essential ports are closed."
            ]

        elif attack.upper() in ("DDOS", "DOS"):
            summary = (
                f"Volumetric denial of service pattern detected from {src_ip} with high risk rating ({risk}/10). "
                f"Automated traffic drop rule '{action}' successfully enforced."
            )
            technical = (
                f"Flow exhibited anomalous throughput of {incident.flow.flow_bytes_s:,.0f} bytes/sec and "
                f"{incident.flow.flow_pkts_s:.1f} packets/sec, surpassing typical service consumption thresholds."
            )
            mitre_ctx = (
                f"Mapped to MITRE ATT&CK {incident.threat.mitre_technique_id} ({incident.threat.mitre_technique_name}) "
                "under the Impact tactic. Aimed at exhausting bandwidth and degrading host availability."
            )
            recs = [
                "Maintain upstream rate-limiting and verify edge perimeter filtering.",
                "Monitor server memory and CPU health for secondary degradation.",
                "Check for correlated source IPs originating from the same ASN/subnet."
            ]

        elif attack.upper() == "BRUTEFORCE":
            summary = (
                f"Authentication brute-force assault detected against service port {dst_port} from {src_ip}. "
                f"Autonomous containment action '{action}' deployed."
            )
            technical = (
                f"Identified repeated connection bursts targeting authentication daemon on port {dst_port} "
                f"across short flow intervals ({incident.flow.flow_duration:.2f}s)."
            )
            mitre_ctx = (
                f"Classified under MITRE ATT&CK {incident.threat.mitre_technique_id} ({incident.threat.mitre_technique_name}) "
                "in Credential Access tactic."
            )
            recs = [
                "Audit authentication audit logs for any successful logins from this IP.",
                "Enforce multi-factor authentication (MFA) and account lockout policies.",
                "Restrict management port access via VPN or IP whitelist."
            ]

        elif attack.upper() == "BOTNET":
            summary = (
                f"Botnet Command & Control (C2) beaconing detected originating from or targeting {src_ip}. "
                f"Immediate mitigation policy '{action}' applied."
            )
            technical = (
                f"Periodic uniform payload transfers observed on port {dst_port} "
                f"(average packet length: {incident.flow.fwd_pkt_len_mean:.1f} bytes)."
            )
            mitre_ctx = (
                f"Aligned with MITRE ATT&CK {incident.threat.mitre_technique_id} ({incident.threat.mitre_technique_name}) "
                "under Command and Control tactic."
            )
            recs = [
                f"Isolate endpoint {incident.flow.dst_ip} immediately for malware scanning.",
                "Capture memory dump to identify persistent C2 processes or reverse shells.",
                "Block associated C2 domain and IP addresses across all egress gateways."
            ]

        else:
            summary = f"Security anomaly detected from {src_ip} (Risk {risk}/10). Action '{action}' enforced."
            technical = f"Flow metrics deviate from standard baseline with confidence {incident.detection.confidence*100:.1f}%."
            mitre_ctx = f"Associated with MITRE ATT&CK {incident.threat.mitre_technique_id}."
            recs = ["Review incident telemetry in SOC console.", "Monitor surrounding host network flows."]

        return LLMExplanation(
            summary=summary,
            technical_analysis=technical,
            mitre_context=mitre_ctx,
            soc_recommendations=recs,
            provider="EXPERT_SYSTEM"
        )

    def _generate_host_expert_briefing(self, incident: HostIncident) -> LLMExplanation:
        """Plain-language host incident narrative without external network calls."""
        proc = incident.process
        fe = incident.file_event
        action = incident.soar_action.value

        if fe.file_path:
            what = f"accessed {fe.file_type} belonging to {fe.target_browser}"
            access = f"{fe.event_type} access to '{fe.file_path}'"
        else:
            what = "behaved differently from normal programs on this computer but did not touch any protected file"
            access = "No protected-file access recorded"
        summary = (
            f"The program {proc.process_name} (PID {proc.pid}) {what}. SentinelAI classified this as "
            f"{incident.classification} activity with risk {incident.risk_score}/10 and responded with "
            f"'{action}' ({incident.action_status})."
        )
        if incident.reasons:
            summary += " Why it was flagged: " + " ".join(incident.reasons)
        technical = (
            f"{access} by '{proc.exe_path or proc.process_name}' "
            f"launched from parent '{proc.parent_name or 'unknown'}'. "
            f"Confidence {incident.confidence * 100:.1f}%, anomaly score {incident.anomaly_score:.2f}."
        )
        if incident.mitre_technique_id:
            mitre_ctx = (
                f"Mapped to MITRE ATT&CK {incident.mitre_technique_id} ({incident.mitre_technique_name}) "
                f"under the {incident.mitre_tactic} tactic."
            )
        else:
            mitre_ctx = "No MITRE ATT&CK technique mapped for this host event."

        if incident.classification == "Stealer":
            recs = [
                f"Sign out of all {fe.target_browser} sessions and change saved passwords from a clean device.",
                f"Confirm {proc.process_name} (PID {proc.pid}) is no longer running and scan '{proc.exe_path or proc.process_name}' with Defender.",
                f"Check outbound network connections made by PID {proc.pid} at the time of this incident for data exfiltration.",
            ]
        elif incident.classification in ("Ransomware", "Malware"):
            recs = [
                "Disconnect the host from the network until the process is contained.",
                f"Quarantine '{proc.exe_path or proc.process_name}' and run a full offline scan.",
                "Verify backups are intact before restoring any affected files.",
            ]
        elif incident.classification == "Anomalous":
            recs = [
                f"If you started {proc.process_name} yourself (a script, installer or developer tool), no action is needed.",
                f"Otherwise scan '{proc.exe_path or proc.process_name}' with Defender.",
                "Your saved passwords and cookies were not touched, so there is no need to change them.",
            ]
        else:
            recs = ["No action required. Event retained in the host audit trail."]

        return LLMExplanation(
            summary=summary,
            technical_analysis=technical,
            mitre_context=mitre_ctx,
            soc_recommendations=recs,
            provider="EXPERT_SYSTEM"
        )

    def _build_host_prompt(self, incident: HostIncident) -> str:
        """Construct prompt for external GenAI models from a HIDS host incident."""
        proc = incident.process
        fe = incident.file_event
        return f"""You are a Tier 3 Senior SOC Analyst explaining a host security event to a non-expert Windows user. Return a JSON object with keys "summary", "technical_analysis", "mitre_context", "soc_recommendations" (list of strings).

Telemetry:
- Classification: {incident.classification} (Confidence: {incident.confidence*100:.1f}%, Anomaly: {incident.anomaly_score:.2f})
- Risk Score: {incident.risk_score}/10 ({incident.severity.value})
- Process: {proc.process_name} (PID {proc.pid}), Path: {proc.exe_path or 'unknown'}, Parent: {proc.parent_name or 'unknown'}
- File Accessed: {f"{fe.file_path} ({fe.file_type}, {fe.event_type}, Browser: {fe.target_browser})" if fe.file_path else "none (flagged on process behaviour only; do not describe this as password theft)"}
- Why Flagged: {" ".join(incident.reasons) or "n/a"}
- MITRE Technique: {incident.mitre_technique_id} - {incident.mitre_technique_name} ({incident.mitre_tactic})
- Action Enforced: {incident.soar_action.value} ({incident.action_status})
"""

    def _build_prompt(self, incident: Incident) -> str:
        """Construct prompt for external GenAI models."""
        return f"""You are a Tier 3 Senior SOC Analyst. Analyze this security telemetry and return a JSON object with keys "summary", "technical_analysis", "mitre_context", "soc_recommendations" (list of strings).

Telemetry:
- Attack Type: {incident.detection.attack_type} (Confidence: {incident.detection.confidence*100:.1f}%)
- Risk Score: {incident.risk.score}/10 ({incident.risk.severity.value})
- Source IP: {incident.flow.src_ip} -> Dest Port: {incident.flow.dst_port}
- Flow Rate: {incident.flow.flow_pkts_s:.1f} pkts/s, {incident.flow.flow_bytes_s:.0f} bytes/s
- MITRE Technique: {incident.threat.mitre_technique_id} - {incident.threat.mitre_technique_name} ({incident.threat.mitre_tactic})
- Action Enforced: {incident.action_plan.action_type.value}
- Signature Evidence: {incident.threat.anomaly_explanation}
"""
