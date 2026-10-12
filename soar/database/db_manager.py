"""
SentinelAI - Database Manager
Thread-safe SQLite database manager providing high-level CRUD, telemetry storage,
and analytical aggregation queries for the SOAR pipeline, reports, and SOC dashboard.
"""

from __future__ import annotations
import os
import sys
import json
import hashlib
import sqlite3
import logging
import threading
import time
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.schemas import Incident, FirewallRule, SystemMetrics, SeverityLevel, HostIncident

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import security  # noqa: E402
from config.paths import LEGACY_DB_PATH, database_path  # noqa: E402

logger = logging.getLogger("SentinelAI.DatabaseManager")

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def _anchor_file(db_path: str) -> Path:
    tag = hashlib.sha1(os.path.normcase(os.path.abspath(db_path)).encode()).hexdigest()[:12]
    return security.data_dir() / f"evidence_anchor_{tag}.json"


def _migrate_legacy_db(target: Path) -> None:
    """Copy the checkout's old soar/database/sentinel.db (and its evidence anchor) to the data folder once."""
    if target.exists() or not LEGACY_DB_PATH.exists():
        return
    if os.environ.get("SENTINEL_DATA_DIR") or os.environ.get("SENTINEL_DB_PATH"):
        return  # explicit locations (tests, service installs) start clean
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        src = sqlite3.connect(str(LEGACY_DB_PATH))
        dst = sqlite3.connect(str(target))
        with dst:
            src.backup(dst)  # consistent copy that includes rows still in the -wal file
        src.close()
        dst.close()
        old_anchor = _anchor_file(str(LEGACY_DB_PATH))
        if old_anchor.exists():
            _anchor_file(str(target)).write_bytes(old_anchor.read_bytes())
        logger.info("Moved database from %s to %s", LEGACY_DB_PATH, target)
    except Exception as exc:
        logger.error("Could not copy the old database to %s: %s", target, exc)
        try:
            target.unlink()
        except OSError:
            pass


def default_db_path() -> str:
    target = database_path()
    _migrate_legacy_db(target)
    return str(target)

CHAINED_TABLES = {"incidents": "incident_id", "host_incidents": "incident_id", "audit_logs": "id"}
GENESIS_HASH = "0" * 64


def record_hash(row: Dict[str, Any]) -> str:
    data = {k: v for k, v in row.items() if k not in ("id", "created_at")}
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


class DatabaseManager:
    """
    Thread-safe SQLite database manager with connection pooling semantics,
    automated migrations/schema execution, and analytical query helpers.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or default_db_path()
        self._lock = threading.RLock()
        self._chain_key: Optional[bytes] = None
        
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
                    head = self._append_chain(conn, "incidents", incident.incident_id)
                    conn.commit()
                self._write_anchor(head)
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
    # Phase 5: Host Incident CRUD Operations (HIDS)
    # -------------------------------------------------------------

    def save_host_incident(self, host_inc: HostIncident) -> bool:
        """Persist a Phase 5 HIDS host incident into SQLite."""
        with self._lock:
            query = """
            INSERT OR REPLACE INTO host_incidents (
                incident_id, timestamp, hostname, pid, process_name, parent_name,
                cpu_percent, memory_mb, file_path, file_type, event_type,
                classification, confidence, risk_score, severity,
                mitre_technique_id, mitre_technique_name, soar_action,
                action_status, remediation_notes, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            raw_json_str = json.dumps(host_inc.to_dict())
            try:
                with self._get_connection() as conn:
                    conn.execute(query, (
                        host_inc.incident_id,
                        host_inc.timestamp,
                        host_inc.hostname,
                        host_inc.process.pid,
                        host_inc.process.process_name,
                        host_inc.process.parent_name,
                        host_inc.process.cpu_percent,
                        host_inc.process.memory_mb,
                        host_inc.file_event.file_path,
                        host_inc.file_event.file_type,
                        host_inc.file_event.event_type,
                        host_inc.classification,
                        host_inc.confidence,
                        host_inc.risk_score,
                        host_inc.severity.value,
                        host_inc.mitre_technique_id,
                        host_inc.mitre_technique_name,
                        host_inc.soar_action.value,
                        host_inc.action_status,
                        host_inc.remediation_notes,
                        raw_json_str
                    ))
                    head = self._append_chain(conn, "host_incidents", host_inc.incident_id)
                    conn.commit()
                self._write_anchor(head)
                return True
            except Exception as exc:
                logger.error("Failed to save host incident %s: %s", host_inc.incident_id, exc)
                return False

    def get_recent_host_incidents(self, limit: int = 50, classification: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent host incidents from database."""
        with self._lock:
            if classification:
                query = "SELECT * FROM host_incidents WHERE classification = ? ORDER BY timestamp DESC LIMIT ?"
                params = (classification, limit)
            else:
                query = "SELECT * FROM host_incidents ORDER BY timestamp DESC LIMIT ?"
                params = (limit,)

            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]


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
                    cur = conn.execute(query, (time.time(), agent_name, action, details, level))
                    head = self._append_chain(conn, "audit_logs", str(cur.lastrowid))
                    conn.commit()
                self._write_anchor(head)
                return True
            except Exception as exc:
                logger.error("Failed to save audit log: %s", exc)
                return False

    # -------------------------------------------------------------
    # Tamper-evident evidence chain
    # -------------------------------------------------------------

    def _key(self) -> bytes:
        if self._chain_key is None:
            self._chain_key = security.integrity_key()
        return self._chain_key

    def _link(self, seq: int, table: str, key: str, rec_hash: str, prev_hash: str) -> str:
        return security.sign(f"{seq}|{table}|{key}|{rec_hash}|{prev_hash}".encode(), self._key())

    def _anchor_path(self) -> Path:
        return _anchor_file(self.db_path)

    def _read_anchor(self) -> Optional[Dict[str, Any]]:
        try:
            anchor = json.loads(self._anchor_path().read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return None
        body = json.dumps({k: anchor.get(k) for k in ("seq", "chain_hash", "breaks")}, sort_keys=True).encode()
        anchor["valid"] = security.tokens_equal(anchor.get("sig"), security.sign(body, self._key()))
        return anchor

    def _append_chain(self, conn: sqlite3.Connection, table: str, key: str) -> Optional[Dict[str, Any]]:
        """Link the stored row into the chain. Returns the new head plus the head it replaced."""
        try:
            col = CHAINED_TABLES[table]
            row = conn.execute(f"SELECT * FROM {table} WHERE {col} = ?", (key,)).fetchone()
            last = conn.execute("SELECT seq, chain_hash FROM evidence_chain ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = last["chain_hash"] if last else GENESIS_HASH
            rec_hash = record_hash(dict(row))
            cur = conn.execute(
                "INSERT INTO evidence_chain (timestamp, table_name, record_key, record_hash, prev_hash, chain_hash) "
                "VALUES (?, ?, ?, ?, ?, '')",
                (time.time(), table, key, rec_hash, prev_hash),
            )
            seq = cur.lastrowid
            chain_hash = self._link(seq, table, key, rec_hash, prev_hash)
            conn.execute("UPDATE evidence_chain SET chain_hash = ? WHERE seq = ?", (chain_hash, seq))
            return {"seq": seq, "chain_hash": chain_hash,
                    "prev_seq": last["seq"] if last else 0, "prev_hash": prev_hash}
        except Exception as exc:
            logger.error("Evidence chain append failed for %s/%s: %s", table, key, exc)
            return None

    def _write_anchor(self, head: Optional[Dict[str, Any]]) -> None:
        """Keep the chain head outside the DB so truncating or swapping the DB is detectable."""
        if not head:
            return
        try:
            anchor = self._read_anchor()
            breaks = list(anchor.get("breaks") or []) if anchor else []
            if anchor and (not anchor["valid"] or anchor.get("seq") != head["prev_seq"]
                           or anchor.get("chain_hash") != head["prev_hash"]):
                breaks.append({"at": time.time(), "anchor_seq": anchor.get("seq"), "db_seq": head["prev_seq"]})
                logger.critical("Evidence chain head did not match its anchor: database was edited or replaced")
            body = {"seq": head["seq"], "chain_hash": head["chain_hash"], "breaks": breaks[-20:]}
            sig = security.sign(json.dumps(body, sort_keys=True).encode(), self._key())
            path = self._anchor_path()
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps({**body, "sig": sig}), encoding="utf-8")
            os.replace(tmp, path)
        except Exception as exc:
            logger.error("Could not update evidence anchor: %s", exc)

    def verify_evidence_chain(self) -> Dict[str, Any]:
        """Walk the chain and compare it with the stored rows and the external anchor."""
        problems: List[str] = []
        with self._lock:
            with self._get_connection() as conn:
                entries = conn.execute("SELECT * FROM evidence_chain ORDER BY seq").fetchall()
                prev_hash, prev_seq = GENESIS_HASH, 0
                latest: Dict[tuple, str] = {}
                for e in entries:
                    if e["seq"] != prev_seq + 1:
                        problems.append(f"chain entries {prev_seq + 1}..{e['seq'] - 1} were deleted")
                    elif e["prev_hash"] != prev_hash:
                        problems.append(f"chain entry {e['seq']} does not link to the previous entry")
                    if self._link(e["seq"], e["table_name"], e["record_key"], e["record_hash"], e["prev_hash"]) != e["chain_hash"]:
                        problems.append(f"chain entry {e['seq']} was forged or edited")
                    prev_hash, prev_seq = e["chain_hash"], e["seq"]
                    latest[(e["table_name"], e["record_key"])] = e["record_hash"]

                first_ts = entries[0]["timestamp"] if entries else None
                for table, col in CHAINED_TABLES.items():
                    rows = {str(r[col]): dict(r) for r in conn.execute(f"SELECT * FROM {table}")}
                    for (t, key), rec_hash in latest.items():
                        if t != table:
                            continue
                        row = rows.get(key)
                        if row is None:
                            problems.append(f"{table} record {key} was deleted")
                        elif record_hash(row) != rec_hash:
                            problems.append(f"{table} record {key} was modified")
                    if first_ts is not None:
                        for key, row in rows.items():
                            if (table, key) not in latest and float(row.get("timestamp") or 0) >= first_ts:
                                problems.append(f"{table} record {key} was inserted outside the chain")

        anchor = self._read_anchor()
        if anchor is not None:
            if not anchor["valid"]:
                problems.append("evidence anchor file was forged or edited")
            elif anchor.get("seq", 0) > prev_seq:
                problems.append(f"database is missing chain entries {prev_seq + 1}..{anchor['seq']} (truncated or replaced)")
            elif anchor.get("seq") == prev_seq and anchor.get("chain_hash") != prev_hash:
                problems.append("chain head differs from its anchor (database replaced)")
            for b in anchor.get("breaks") or []:
                problems.append(f"chain head mismatch recorded at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(b.get('at', 0)))}")
        elif entries:
            problems.append("evidence anchor file is missing")

        return {
            "ok": not problems,
            "entries": len(entries),
            "problem_count": len(problems),
            "problems": problems[:50],
            "checked_at": time.time(),
        }

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
            WHERE UPPER(attack_type) != 'BENIGN'
            GROUP BY src_ip
            ORDER BY incident_count DESC, max_risk_score DESC
            LIMIT ?
            """
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (limit,))
                return [dict(row) for row in cursor.fetchall()]

    def add_checked_flows(self, count: int, day: Optional[str] = None) -> None:
        """Add live benign flows (not stored as incidents) to today's counter."""
        if count <= 0:
            return
        day = day or time.strftime("%Y-%m-%d")
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO traffic_stats (day, flows_checked) VALUES (?, ?) "
                    "ON CONFLICT(day) DO UPDATE SET flows_checked = flows_checked + excluded.flows_checked",
                    (day, count),
                )
                conn.commit()

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

                cursor.execute("SELECT COALESCE(SUM(flows_checked), 0) FROM traffic_stats")
                live_benign_flows = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM incidents WHERE UPPER(attack_type) != 'BENIGN'")
                total_threats = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE status = 'ACTIVE'")
                active_blocks = cursor.fetchone()[0]

                cursor.execute("SELECT AVG(risk_score) FROM incidents WHERE UPPER(attack_type) != 'BENIGN'")
                avg_risk_row = cursor.fetchone()[0]
                avg_risk = round(avg_risk_row, 2) if avg_risk_row is not None else 0.0

            return {
                "total_flows_analyzed": total_incidents + live_benign_flows,
                "total_threats_detected": total_threats,
                "active_firewall_blocks": active_blocks,
                "average_threat_risk": avg_risk,
                "attack_distribution": self.get_attack_distribution(),
                "top_offenders": self.get_top_offending_ips(5)
            }
