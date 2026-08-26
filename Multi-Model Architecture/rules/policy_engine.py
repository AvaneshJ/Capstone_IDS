"""
SentinelAI - Policy Engine
Evaluates threats, risk scores, and telemetry against policies.yaml rules to determine SOAR action plans.
"""

from __future__ import annotations
import os
import yaml
import logging
import ipaddress
from typing import Dict, Any, Tuple, Optional

from core.schemas import ActionPlan, ActionType, SeverityLevel

logger = logging.getLogger("SentinelAI.PolicyEngine")

DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(__file__), "policies.yaml")


class PolicyEngine:
    """
    Evaluates threat events against declarative security policies.
    Provides whitelist verification, dynamic threshold evaluation, and MITRE mapping.
    """

    def __init__(self, policy_path: str = DEFAULT_POLICY_PATH):
        self.policy_path = policy_path
        self.policies: Dict[str, Any] = {}
        self.load_policies()

    def load_policies(self) -> None:
        """Load or reload policies.yaml from disk."""
        if os.path.exists(self.policy_path):
            try:
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    self.policies = yaml.safe_load(f) or {}
                logger.info("Policies loaded successfully from: %s", self.policy_path)
            except Exception as exc:
                logger.error("Failed to parse policies.yaml (%s). Using fallback defaults.", exc)
                self.policies = self._get_fallback_policies()
        else:
            logger.warning("policies.yaml not found at %s. Using fallback defaults.", self.policy_path)
            self.policies = self._get_fallback_policies()

    def is_ip_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP is in the static whitelist or matches whitelisted subnets."""
        if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1", "::1"):
            return True

        whitelists = self.policies.get("whitelists", {})
        
        # 1. Exact IP match
        exact_ips = whitelists.get("ips", [])
        if ip_str in exact_ips:
            return True

        # 2. CIDR Subnet match
        subnets = whitelists.get("subnets", [])
        try:
            target_addr = ipaddress.ip_address(ip_str)
            for cidr in subnets:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if target_addr in network:
                        return True
                except ValueError:
                    continue
        except ValueError:
            # Invalid IP string
            return False

        return False

    def get_base_weight(self, attack_type: str) -> float:
        """Retrieve the base severity weight for a classified attack type."""
        weights = self.policies.get("base_attack_weights", {})
        # Normalize attack name lookup
        for key, weight in weights.items():
            if key.lower() == attack_type.lower():
                return float(weight)
        return 5.0 if attack_type.upper() != "BENIGN" else 0.0

    def get_velocity_multiplier(self, count_in_window: int) -> float:
        """Compute the velocity multiplier for event frequency in sliding window."""
        velocity_cfg = self.policies.get("velocity_settings", {})
        tiers = velocity_cfg.get("tiers", [])
        
        for tier in tiers:
            if count_in_window <= tier.get("max_count", 0):
                return float(tier.get("multiplier", 0.0))
        return 2.5

    def get_target_sensitivity(self, dst_ip: str, dst_port: int) -> float:
        """Calculate target asset sensitivity modifier based on IP subnet and sensitive ports."""
        sensitivity_cfg = self.policies.get("target_sensitivity", {})
        sensitive_ports = sensitivity_cfg.get("sensitive_ports", {})
        
        score = 0.0
        # Port sensitivity bonus
        if dst_port in sensitive_ports:
            score += float(sensitive_ports[dst_port])
        elif str(dst_port) in sensitive_ports:
            score += float(sensitive_ports[str(dst_port)])

        # Critical subnet check
        critical_subnets = sensitivity_cfg.get("critical_subnets", [])
        try:
            target_addr = ipaddress.ip_address(dst_ip)
            for cidr in critical_subnets:
                if target_addr in ipaddress.ip_network(cidr, strict=False):
                    score += 1.0
                    break
        except ValueError:
            pass

        return score

    def evaluate_response_action(self, src_ip: str, risk_score: float, attack_type: str) -> ActionPlan:
        """
        Determine the autonomous SOAR response plan based on whitelist rules and risk thresholds.
        """
        # 1. Whitelist Check
        if self.is_ip_whitelisted(src_ip):
            return ActionPlan(
                action_type=ActionType.IGNORE,
                target_ip=src_ip,
                ban_duration_seconds=0,
                priority=0,
                rationale=f"Source IP {src_ip} is in the verified whitelist. Mitigation bypassed.",
                rule_matched="whitelist_exception",
                auto_unblock=False
            )

        if attack_type.upper() == "BENIGN" and risk_score < 4.0:
            return ActionPlan(
                action_type=ActionType.LOG_ONLY,
                target_ip=src_ip,
                ban_duration_seconds=0,
                priority=1,
                rationale="Benign flow observed. Logged quietly.",
                rule_matched="benign_baseline",
                auto_unblock=False
            )

        thresholds = self.policies.get("thresholds", {})
        crit_cfg = thresholds.get("critical", {})
        high_cfg = thresholds.get("high", {})
        med_cfg = thresholds.get("medium", {})
        low_cfg = thresholds.get("low", {})

        # 2. Critical Threshold
        if risk_score >= crit_cfg.get("min_score", 8.5):
            return ActionPlan(
                action_type=ActionType.BLOCK_IP,
                target_ip=src_ip,
                ban_duration_seconds=crit_cfg.get("ban_duration_seconds", 86400),
                priority=crit_cfg.get("priority", 5),
                rationale=crit_cfg.get("rationale", "Critical risk detected. Immediate firewall block."),
                rule_matched="threshold_critical",
                auto_unblock=True
            )

        # 3. High Threshold
        if risk_score >= high_cfg.get("min_score", 7.0):
            return ActionPlan(
                action_type=ActionType.TEMP_BAN_IP,
                target_ip=src_ip,
                ban_duration_seconds=high_cfg.get("ban_duration_seconds", 1800),
                priority=high_cfg.get("priority", 4),
                rationale=high_cfg.get("rationale", "High risk detected. Temporary 30m quarantine."),
                rule_matched="threshold_high",
                auto_unblock=True
            )

        # 4. Medium Threshold
        if risk_score >= med_cfg.get("min_score", 5.0):
            return ActionPlan(
                action_type=ActionType.TEMP_BAN_IP,
                target_ip=src_ip,
                ban_duration_seconds=med_cfg.get("ban_duration_seconds", 900),
                priority=med_cfg.get("priority", 3),
                rationale=med_cfg.get("rationale", "Medium risk detected. Temporary 15m quarantine."),
                rule_matched="threshold_medium",
                auto_unblock=True
            )

        # 5. Low / Watchlist Threshold
        return ActionPlan(
            action_type=ActionType.LOG_ONLY,
            target_ip=src_ip,
            ban_duration_seconds=0,
            priority=low_cfg.get("priority", 1),
            rationale=low_cfg.get("rationale", "Low risk event logged to telemetry."),
            rule_matched="threshold_low",
            auto_unblock=False
        )

    def get_mitre_mapping(self, attack_type: str) -> Tuple[str, str, str, str]:
        """
        Look up MITRE ATT&CK technique details.
        Returns (technique_id, technique_name, tactic, description).
        """
        mappings = self.policies.get("mitre_mappings", {})
        for key, val in mappings.items():
            if key.lower() == attack_type.lower():
                return (
                    val.get("technique_id", "T0000"),
                    val.get("technique_name", "Unknown"),
                    val.get("tactic", "General"),
                    val.get("description", "")
                )
        
        # Generic fallback
        return ("T1046", "Network Service Discovery", "Discovery", "Anomalous network probing observed.")

    def _get_fallback_policies(self) -> Dict[str, Any]:
        """Hardcoded fallback policy configuration in case YAML cannot be read."""
        return {
            "whitelists": {"ips": ["127.0.0.1", "::1", "192.168.1.1", "8.8.8.8", "1.1.1.1"], "subnets": []},
            "base_attack_weights": {"DDoS": 9.0, "Botnet": 9.0, "BruteForce": 7.0, "PortScan": 5.0, "BENIGN": 0.0},
            "thresholds": {
                "critical": {"min_score": 8.5, "action": "BLOCK_IP", "ban_duration_seconds": 86400, "priority": 5},
                "high": {"min_score": 7.0, "action": "TEMP_BAN_IP", "ban_duration_seconds": 1800, "priority": 4},
                "medium": {"min_score": 5.0, "action": "TEMP_BAN_IP", "ban_duration_seconds": 900, "priority": 3},
                "low": {"min_score": 1.0, "action": "LOG_ONLY", "ban_duration_seconds": 0, "priority": 1}
            },
            "velocity_settings": {
                "sliding_window_seconds": 60,
                "tiers": [{"max_count": 3, "multiplier": 0.0}, {"max_count": 10, "multiplier": 0.8}, {"max_count": 1000, "multiplier": 2.5}]
            },
            "target_sensitivity": {"sensitive_ports": {3306: 1.5, 5432: 1.5, 22: 1.2, 3389: 1.5}},
            "mitre_mappings": {
                "PortScan": {"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"},
                "DDoS": {"technique_id": "T1498", "technique_name": "Network Denial of Service", "tactic": "Impact"},
                "BruteForce": {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
                "Botnet": {"technique_id": "T1071", "technique_name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
                "BENIGN": {"technique_id": "T0000", "technique_name": "Authorized Baseline Traffic", "tactic": "Legitimate"}
            }
        }
