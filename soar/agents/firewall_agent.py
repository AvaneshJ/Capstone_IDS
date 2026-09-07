"""
SentinelAI - Firewall Enforcement Agent
Autonomous firewall controller executing Windows netsh / Linux iptables block rules,
featuring a dry-run safety toggle and a background auto-unblock scheduler.
"""

from __future__ import annotations
import os
import sys
import time
import logging
import platform
import subprocess
import threading
from typing import Dict, List, Any, Optional

from agents.base_agent import BaseAgent
from core.schemas import Incident, FirewallRule, ActionType
from core.event_bus import EventBus, Event
from database.db_manager import DatabaseManager

logger = logging.getLogger("SentinelAI.FirewallAgent")


class FirewallAgent(BaseAgent):
    """
    OS-level Firewall Mitigation Agent.
    Enforces drop rules on Windows (netsh) and Linux (iptables).
    Maintains active rules, manages background unblock timers, and persists state to SQLite.
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        dry_run: bool = True,
        unblock_interval_seconds: float = 5.0,
        event_bus: Optional[EventBus] = None
    ):
        super().__init__(name="FirewallAgent", event_bus=event_bus)
        self.db_manager = db_manager or DatabaseManager()
        self.dry_run = dry_run
        self.unblock_interval = unblock_interval_seconds
        
        self.os_type = platform.system().lower()
        self._active_rules: Dict[str, FirewallRule] = {}
        self._lock = threading.RLock()
        
        # Background unblock worker thread
        self._stop_event = threading.Event()
        self._unblock_thread: Optional[threading.Thread] = None

    def _on_initialize(self) -> None:
        # Subscribe to firewall action topics
        if self.event_bus:
            self.event_bus.subscribe("action.firewall", self.process, priority=6, agent_name=self.name)

        # Start auto-unblock scheduler background thread
        self._stop_event.clear()
        self._unblock_thread = threading.Thread(
            target=self._unblock_worker_loop,
            name="SentinelAI-AutoUnblocker",
            daemon=True
        )
        self._unblock_thread.start()
        logger.info("FirewallAgent started with dry_run=%s on %s OS", self.dry_run, self.os_type)

    def _handle_event(self, event: Event) -> Optional[FirewallRule]:
        data = event.data
        if not isinstance(data, Incident):
            logger.warning("FirewallAgent received invalid data type: %s", type(data))
            return None

        incident: Incident = data
        target_ip = incident.flow.src_ip
        ban_seconds = incident.action_plan.ban_duration_seconds
        reason = f"Mitigating {incident.detection.attack_type} (Risk {incident.risk.score}/10)"

        rule = self.block_ip(target_ip=target_ip, duration_seconds=ban_seconds, reason=reason)
        incident.firewall_rule = rule

        if self.event_bus and rule:
            self.event_bus.publish("firewall.executed", {"incident": incident, "rule": rule}, sender=self.name)

        return rule

    def block_ip(self, target_ip: str, duration_seconds: int = 0, reason: str = "Automated Block") -> FirewallRule:
        """
        Construct and execute a firewall block rule.
        """
        rule_name = f"SentinelAI_Block_{target_ip.replace(':', '_')}"
        now = time.time()
        expires_at = (now + duration_seconds) if duration_seconds > 0 else None

        # Build OS-specific command
        if "windows" in self.os_type:
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={target_ip}'
        else:
            # Linux fallback
            cmd = f'iptables -A INPUT -s {target_ip} -j DROP'

        rule = FirewallRule(
            rule_name=rule_name,
            target_ip=target_ip,
            direction="INBOUND",
            action="BLOCK",
            created_at=now,
            expires_at=expires_at,
            status="ACTIVE",
            command_executed=cmd
        )

        if self.dry_run:
            rule.status = "SIMULATED"
            logger.info("[DRY RUN] Simulated Firewall Rule Added: %s (Target: %s, Expires in: %ss)", cmd, target_ip, duration_seconds)
        else:
            try:
                logger.info("Executing Live Firewall Command: %s", cmd)
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                if res.returncode != 0:
                    rule.status = "FAILED"
                    rule.error_message = res.stderr or res.stdout
                    logger.error("Firewall command failed with code %d: %s", res.returncode, rule.error_message)
                else:
                    rule.status = "ACTIVE"
                    logger.info("Successfully added firewall rule for %s", target_ip)
            except Exception as exc:
                rule.status = "FAILED"
                rule.error_message = str(exc)
                logger.error("Exception executing firewall rule: %s", exc)

        with self._lock:
            self._active_rules[rule.rule_id] = rule

        # Persist to SQLite
        self.db_manager.save_blocked_ip(rule, reason=reason)
        self.db_manager.save_audit_log(
            agent_name=self.name,
            action=f"BLOCK_IP ({rule.status})",
            details=f"IP={target_ip}, Duration={duration_seconds}s, Command={cmd}"
        )

        return rule

    def unblock_ip(self, rule_id: str) -> bool:
        """
        Remove a firewall block rule and update state.
        """
        with self._lock:
            rule = self._active_rules.get(rule_id)

        target_ip = rule.target_ip if rule else None
        rule_name = rule.rule_name if rule else f"SentinelAI_Block_{rule_id}"

        if not target_ip and self.db_manager:
            # Check database for rule
            active_blocks = self.db_manager.get_active_blocks()
            for b in active_blocks:
                if b["rule_id"] == rule_id:
                    target_ip = b["ip_address"]
                    rule_name = f"SentinelAI_Block_{target_ip.replace(':', '_')}"
                    break

        if not target_ip:
            logger.warning("Unblock failed: Rule ID %s not found.", rule_id)
            return False

        if "windows" in self.os_type:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            cmd = f'iptables -D INPUT -s {target_ip} -j DROP'

        if self.dry_run:
            logger.info("[DRY RUN] Simulated Firewall Rule Removed: %s (Target: %s)", cmd, target_ip)
            success = True
        else:
            try:
                logger.info("Executing Live Firewall Delete: %s", cmd)
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                success = (res.returncode == 0)
            except Exception as exc:
                logger.error("Error executing firewall delete: %s", exc)
                success = False

        status_str = "RELEASED" if success else "FAILED_RELEASE"
        with self._lock:
            if rule_id in self._active_rules:
                self._active_rules[rule_id].status = status_str

        self.db_manager.update_blocked_ip_status(rule_id, status_str)
        self.db_manager.save_audit_log(
            agent_name=self.name,
            action=f"UNBLOCK_IP ({status_str})",
            details=f"IP={target_ip}, Rule={rule_name}"
        )

        return success

    def _unblock_worker_loop(self) -> None:
        """Background thread polling for expired temporary bans."""
        while not self._stop_event.is_set():
            try:
                now = time.time()
                # Check DB for expired blocks
                expired_blocks = self.db_manager.get_expired_blocks(current_time=now)
                for b in expired_blocks:
                    rule_id = b["rule_id"]
                    logger.info("Cool-down expired for IP %s (Rule %s). Lifting firewall ban.", b["ip_address"], rule_id)
                    self.unblock_ip(rule_id)
            except Exception as exc:
                logger.error("Error in auto-unblock worker loop: %s", exc)

            self._stop_event.wait(self.unblock_interval)

    def _on_shutdown(self) -> None:
        """Stop background worker thread."""
        self._stop_event.set()
        if self._unblock_thread and self._unblock_thread.is_alive():
            self._unblock_thread.join(timeout=2.0)
