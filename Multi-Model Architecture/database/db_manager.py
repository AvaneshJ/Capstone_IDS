"""
SentinelAI - Database Manager
Thread-safe SQLite database manager providing high-level CRUD, telemetry storage,
and analytical aggregation queries for the SOAR pipeline, reports, and SOC dashboard.
"""

from __future__ import annotations
import os
import json
import sqlite3
import logging
import threading
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.schemas import Incident, FirewallRule, SystemMetrics, SeverityLevel

logger = logging.getLogger("SentinelAI.DatabaseManager")

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "sentinel.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


class DatabaseManager:
    """
    Thread-safe SQLite database manager with connection pooling semantics,
    automated migrations/schema execution, and analytical query helpers.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.initialize_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a configured SQLite connection."""
        conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def initialize_schema(self) -> None:
        """Execute schema.sql to ensure all tables and indexes exist."""
        with self._lock:
            if not os.path.exists(SCHEMA_PATH):
                logger.error("Schema file not found at: %s", SCHEMA_PATH)
                return
            
            with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                schema_sql = f.read()

            with self._get_connection() as conn:
                conn.executescript(schema_sql)
                conn.commit()
            logger.info("Database initialized successfully at: %s", self.db_path)

    # -------------------------------------------------------------
    # Incident CRUD Operations
    # -------------------------------------------------------------

    def save_incident(self, incident: Incident) -> bool:
        """Persist a fully orchestrated incident into the database."""
        with self._lock:
            query = """
            INSERT OR REPLACE INTO incidents (
                incident_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, attack_type, confidence, risk_score, severity,
                action_taken, mitre_technique_id, mitre_technique_name,
                explanation, raw_json, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            explanation_text = ""
            if incident.llm_explanation:
                explanation_text = incident.llm_explanation.summary
            elif incident.threat:
                explanation_text = incident.threat.anomaly_explanation

            raw_json_str = json.dumps(incident.to_dict())

            try:
                with self._get_connection() as conn:
                    conn.execute(query, (
                        incident.incident_id,
                        incident.timestamp,
                        incident.flow.src_ip,
                        incident.flow.dst_ip,
                        incident.flow.src_port,
                        incident.flow.dst_port,
                        incident.flow.protocol,
                        incident.detection.attack_type,
                        incident.detection.confidence,
                        incident.risk.score,
                        incident.risk.severity.value,
                        incident.action_plan.action_type.value,
                        incident.threat.mitre_technique_id,
                        incident.threat.mitre_technique_name,
                        explanation_text,
                        raw_json_str,
                        incident.status
                    ))
                    conn.commit()
                return True
            except Exception as exc:
                logger.error("Failed to save incident %s: %s", incident.incident_id, exc)
                return False

    def get_recent_incidents(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent incidents, optionally filtered by severity."""
        with self._lock:
            if severity:
                query = "SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC LIMIT ?"
                params = (severity.upper(), limit)
            else:
                query = "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?"
                params = (limit,)

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details of a specific incident."""
        with self._lock:
            query = "SELECT * FROM incidents WHERE incident_id = ?"
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (incident_id,))
                row = cursor.fetchone()
                return dict(row) if row else None

    # -------------------------------------------------------------
    # Blocked IPs Operations
    # -------------------------------------------------------------

    def save_blocked_ip(self, rule: FirewallRule, reason: str = "Autonomous SOAR Mitigation") -> bool:
        """Record or update a firewall block entry."""
        with self._lock:
            query = """
            INSERT INTO blocked_ips (
                rule_id, ip_address, direction, block_timestamp,
                expiry_timestamp, reason, status, command_executed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                status=excluded.status,
                expiry_timestamp=excluded.expiry_timestamp,
                command_executed=excluded.command_executed
            """
            try:
                with self._get_connection() as conn:
                    conn.execute(query, (
                        rule.rule_id,
                        rule.target_ip,
                        rule.direction,
                        rule.created_at,
                        rule.expires_at,
                        reason,
                        rule.status,
                        rule.command_executed
                    ))
                    conn.commit()
                return True
            except Exception as exc:
                logger.error("Failed to save blocked IP rule %s: %s", rule.rule_id, exc)
                return False

    def update_blocked_ip_status(self, rule_id: str, status: str) -> bool:
        """Update the status of a blocked IP rule (e.g., RELEASED, FAILED)."""
        with self._lock:
            query = "UPDATE blocked_ips SET status = ? WHERE rule_id = ?"
            try:
                with self._get_connection() as conn:
                    conn.execute(query, (status, rule_id))
                    conn.commit()
                return True
            except Exception as exc:
                logger.error("Failed to update status for rule %s: %s", rule_id, exc)
                return False

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Fetch all currently active firewall blocks (including simulated dry-run blocks)."""
        with self._lock:
            query = "SELECT * FROM blocked_ips WHERE status IN ('ACTIVE', 'SIMULATED') ORDER BY block_timestamp DESC"
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                return [dict(row) for row in cursor.fetchall()]

    def get_expired_blocks(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """Fetch blocks that are active but whose expiry timestamp has passed."""
        if current_time is None:
            current_time = time.time()
        
        with self._lock:
            query = """
            SELECT * FROM blocked_ips 
            WHERE status IN ('ACTIVE', 'SIMULATED') 
              AND expiry_timestamp IS NOT NULL 
              AND expiry_timestamp <= ?
            """
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (current_time,))
                return [dict(row) for row in cursor.fetchall()]

    # -------------------------------------------------------------
    # Telemetry, Metrics & Audit Logging
    # -------------------------------------------------------------

    def save_system_metrics(self, metrics: SystemMetrics) -> bool:
        """Record system resource and pipeline performance snapshot."""
        with self._lock:
            query = """
            INSERT INTO system_metrics (
                timestamp, total_flows, total_threats, total_blocked_ips,
                total_alerts, active_bans, cpu_percent, memory_percent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            try:
                with self._get_connection() as conn:
                    conn.execute(query, (
                        metrics.timestamp,
                        metrics.total_flows,
                        metrics.total_threats,
                        metrics.total_blocked_ips,
                        metrics.total_alerts,
                        metrics.active_firewall_rules,
                        metrics.cpu_percent,
                        metrics.memory_percent
                    ))
                    conn.commit()
                return True
            except Exception as exc:
                logger.error("Failed to save system metrics: %s", exc)
                return False

    def save_audit_log(self, agent_name: str, action: str, details: str = "", level: str = "INFO") -> bool:
        """Record an agent audit trail log for compliance."""
        with self._lock:
            query = "INSERT INTO audit_logs (timestamp, agent_name, action, details, level) VALUES (?, ?, ?, ?, ?)"
            try:
                with self._get_connection() as conn:
                    conn.execute(query, (time.time(), agent_name, action, details, level))
                    conn.commit()
                return True
            except Exception as exc:
                logger.error("Failed to save audit log: %s", exc)
                return False

    # -------------------------------------------------------------
    # Whitelist & Aggregation Analytics for Dashboard (Member 4)
    # -------------------------------------------------------------

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP address is registered in the whitelist table."""
        with self._lock:
            query = "SELECT 1 FROM whitelisted_ips WHERE ip_or_cidr = ? LIMIT 1"
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (ip,))
                return cursor.fetchone() is not None

    def add_whitelist_ip(self, ip_or_cidr: str, description: str = "") -> bool:
        """Add an IP to the whitelist table."""
        with self._lock:
            query = "INSERT OR IGNORE INTO whitelisted_ips (ip_or_cidr, description, added_at) VALUES (?, ?, ?)"
            try:
                with self._get_connection() as conn:
                    conn.execute(query, (ip_or_cidr, description, time.time()))
                    conn.commit()
                return True
            except Exception as exc:
                logger.error("Failed to add whitelist IP %s: %s", ip_or_cidr, exc)
                return False

    def get_top_offending_ips(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Aggregate top offending IPs by incident frequency and highest risk score."""
        with self._lock:
            query = """
            SELECT 
                src_ip, 
                COUNT(*) as incident_count,
                MAX(risk_score) as max_risk_score,
                GROUP_CONCAT(DISTINCT attack_type) as attack_types,
                MAX(timestamp) as last_seen
            FROM incidents
            WHERE attack_type != 'BENIGN'
            GROUP BY src_ip
            ORDER BY incident_count DESC, max_risk_score DESC
            LIMIT ?
            """
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (limit,))
                return [dict(row) for row in cursor.fetchall()]

    def get_attack_distribution(self) -> Dict[str, int]:
        """Get incident breakdown by attack type."""
        with self._lock:
            query = "SELECT attack_type, COUNT(*) as count FROM incidents GROUP BY attack_type"
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query)
                return {row["attack_type"]: row["count"] for row in cursor.fetchall()}

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """
        Aggregate high-level KPIs for Member 4's SOC Dashboard.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Total counts
                cursor.execute("SELECT COUNT(*) FROM incidents")
                total_incidents = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM incidents WHERE attack_type != 'BENIGN'")
                total_threats = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE status = 'ACTIVE'")
                active_blocks = cursor.fetchone()[0]

                cursor.execute("SELECT AVG(risk_score) FROM incidents WHERE attack_type != 'BENIGN'")
                avg_risk_row = cursor.fetchone()[0]
                avg_risk = round(avg_risk_row, 2) if avg_risk_row is not None else 0.0

            return {
                "total_flows_analyzed": total_incidents,
                "total_threats_detected": total_threats,
                "active_firewall_blocks": active_blocks,
                "average_threat_risk": avg_risk,
                "attack_distribution": self.get_attack_distribution(),
                "top_offenders": self.get_top_offending_ips(5)
            }
