"""
SentinelAI - Core Schemas & Data Structures
Defines strongly-typed, serialization-ready data models for the multi-agent SOAR pipeline.
"""

from __future__ import annotations
import uuid
import time
from enum import Enum
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    TEMP_BAN_IP = "TEMP_BAN_IP"
    RATE_LIMIT = "RATE_LIMIT"
    ALERT_ONLY = "ALERT_ONLY"
    LOG_ONLY = "LOG_ONLY"
    IGNORE = "IGNORE"


class AgentStatus(str, Enum):
    UNINITIALIZED = "UNINITIALIZED"
    IDLE = "IDLE"
    PROCESSING = "PROCESSING"
    ERROR = "ERROR"
    OFFLINE = "OFFLINE"


@dataclass
class FlowEvent:
    """Represents a validated and normalized network flow event from Member 2's packet capture."""
    flow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    src_ip: str = "127.0.0.1"
    dst_ip: str = "127.0.0.1"
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6  # 6=TCP, 17=UDP, 1=ICMP
    flow_duration: float = 0.0
    tot_fwd_pkts: int = 0
    tot_bwd_pkts: int = 0
    fwd_pkt_len_mean: float = 0.0
    bwd_pkt_len_mean: float = 0.0
    flow_bytes_s: float = 0.0
    flow_pkts_s: float = 0.0
    syn_flag_count: int = 0
    ack_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    fin_flag_count: int = 0
    raw_features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionResult:
    """Represents the ML model inference output from Member 1's model (+ optional SOAR policy)."""
    attack_type: str = "BENIGN"  # effective label used by SOAR (may be policy-overridden)
    confidence: float = 0.0
    probabilities: Dict[str, float] = field(default_factory=dict)
    model_version: str = "1.0.0"
    inference_time_ms: float = 0.0
    is_anomaly: bool = False
    # Live trust layer (task 4) — preserves frozen-model output when policy fires
    ml_attack_type: str = ""
    ml_confidence: float = 0.0
    policy_applied: bool = False
    policy_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatEvidence:
    """Deep signature indicators and MITRE ATT&CK mapping."""
    indicators: List[str] = field(default_factory=list)
    anomaly_explanation: str = ""
    mitre_technique_id: str = "T0000"
    mitre_technique_name: str = "Unknown"
    mitre_tactic: str = "General"
    signature_match: str = "None"
    observed_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskScoreResult:
    """Multi-factor dynamic risk score computation result."""
    score: float = 0.0  # 1.0 to 10.0 scale
    severity: SeverityLevel = SeverityLevel.LOW
    base_attack_weight: float = 0.0
    confidence_factor: float = 0.0
    velocity_multiplier: float = 0.0
    target_sensitivity: float = 0.0
    frequency_count_60s: int = 0
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ActionPlan:
    """SOAR decision and response plan."""
    action_type: ActionType = ActionType.LOG_ONLY
    target_ip: str = ""
    ban_duration_seconds: int = 0
    priority: int = 1  # 1 (lowest) to 5 (highest/emergency)
    rationale: str = ""
    rule_matched: str = "default_policy"
    auto_unblock: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action_type"] = self.action_type.value
        return d


@dataclass
class FirewallRule:
    """Firewall rule state and execution tracking."""
    rule_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    rule_name: str = ""
    target_ip: str = ""
    direction: str = "INBOUND"
    action: str = "BLOCK"
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    status: str = "ACTIVE"  # ACTIVE, RELEASED, FAILED, SIMULATED
    command_executed: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AlertMessage:
    """Notification payload for desktop, dashboard, and webhook channels."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: float = field(default_factory=time.time)
    severity: SeverityLevel = SeverityLevel.LOW
    title: str = ""
    message: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    attack_type: str = "BENIGN"
    risk_score: float = 0.0
    action_taken: str = ""
    channels: List[str] = field(default_factory=lambda: ["DASHBOARD", "CONSOLE"])
    source: str = "NIDS"  # NIDS or HIDS
    incident_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class LLMExplanation:
    """GenAI plain-English SOC analyst briefing."""
    summary: str = ""
    technical_analysis: str = ""
    mitre_context: str = ""
    soc_recommendations: List[str] = field(default_factory=list)
    provider: str = "EXPERT_SYSTEM"  # GEMINI, OLLAMA, EXPERT_SYSTEM
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    """Master end-to-end incident structure."""
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    flow: FlowEvent = field(default_factory=FlowEvent)
    detection: DetectionResult = field(default_factory=DetectionResult)
    threat: ThreatEvidence = field(default_factory=ThreatEvidence)
    risk: RiskScoreResult = field(default_factory=RiskScoreResult)
    action_plan: ActionPlan = field(default_factory=ActionPlan)
    firewall_rule: Optional[FirewallRule] = None
    alert: Optional[AlertMessage] = None
    llm_explanation: Optional[LLMExplanation] = None
    status: str = "NEW"  # NEW, MITIGATED, CLOSED, WHITELISTED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "flow": self.flow.to_dict(),
            "detection": self.detection.to_dict(),
            "threat": self.threat.to_dict(),
            "risk": self.risk.to_dict(),
            "action_plan": self.action_plan.to_dict(),
            "firewall_rule": self.firewall_rule.to_dict() if self.firewall_rule else None,
            "alert": self.alert.to_dict() if self.alert else None,
            "llm_explanation": self.llm_explanation.to_dict() if self.llm_explanation else None,
            "status": self.status
        }


@dataclass
class SystemMetrics:
    """Real-time system telemetry and agent performance statistics."""
    timestamp: float = field(default_factory=time.time)
    total_flows: int = 0
    total_threats: int = 0
    total_blocked_ips: int = 0
    total_alerts: int = 0
    active_firewall_rules: int = 0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    uptime_seconds: float = 0.0
    agent_statuses: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =====================================================================
# Phase 5: HIDS (Host Intrusion Detection System) Schemas
# =====================================================================

class HostActionType(str, Enum):
    """SOAR action types for host-level mitigations."""
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    ALERT_ONLY = "ALERT_ONLY"
    LOG_ONLY = "LOG_ONLY"


@dataclass
class HostProcessInfo:
    """Process metadata collected via psutil sensor (Member 1)."""
    pid: int = 0
    process_name: str = ""
    parent_name: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    exe_path: str = ""
    cmdline: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostFileEvent:
    """Sensitive file access metadata collected via watchdog sensor (Member 2)."""
    file_path: str = ""
    file_type: str = ""  # CookieDB, LocalState, CryptoWallet, SavedPasswords
    event_type: str = "READ"  # READ, MODIFY, CREATE, DELETE
    target_browser: str = ""  # Google Chrome, Microsoft Edge, Mozilla Firefox

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostIncident:
    """Standardized Host Incident format produced by Member 5 (HIDS SOAR)."""
    incident_id: str = field(default_factory=lambda: f"HOST-INC-{uuid.uuid4().hex[:8].upper()}")
    timestamp: float = field(default_factory=time.time)
    source: str = "HIDS"
    hostname: str = "WINDOWS-HOST"
    process: HostProcessInfo = field(default_factory=HostProcessInfo)
    file_event: HostFileEvent = field(default_factory=HostFileEvent)
    classification: str = "Normal"  # Normal, Anomalous, Stealer, Ransomware, Malware
    confidence: float = 1.0
    anomaly_score: float = 0.0
    risk_score: float = 0.0
    severity: SeverityLevel = SeverityLevel.LOW
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""
    soar_action: HostActionType = HostActionType.LOG_ONLY
    action_status: str = "PENDING"  # SUCCESS, SIMULATED, FAILED, PENDING
    remediation_notes: str = ""
    reasons: List[str] = field(default_factory=list)  # plain-language "why was this flagged"
    raw_event: Dict[str, Any] = field(default_factory=dict)
    alert: Optional[AlertMessage] = None
    llm_explanation: Optional[LLMExplanation] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "hostname": self.hostname,
            "process": self.process.to_dict(),
            "file_event": self.file_event.to_dict(),
            "classification": self.classification,
            "confidence": round(self.confidence, 4),
            "anomaly_score": round(self.anomaly_score, 4),
            "risk_score": round(self.risk_score, 2),
            "severity": self.severity.value,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic": self.mitre_tactic,
            "soar_action": self.soar_action.value,
            "action_status": self.action_status,
            "remediation_notes": self.remediation_notes,
            "reasons": list(self.reasons),
            "raw_event": self.raw_event,
            "alert": self.alert.to_dict() if self.alert else None,
            "llm_explanation": self.llm_explanation.to_dict() if self.llm_explanation else None,
        }

