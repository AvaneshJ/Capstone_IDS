-- ==========================================================
-- SentinelAI Database Schema (SQLite)
-- Supports incidents, firewall blocks, time-series telemetry,
-- audit logs, and whitelists.
-- ==========================================================

PRAGMA foreign_keys = ON;

-- 1. Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT UNIQUE NOT NULL,
    timestamp REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,
    attack_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk_score REAL NOT NULL,
    severity TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    explanation TEXT,
    raw_json TEXT,
    status TEXT DEFAULT 'NEW',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_attack_type ON incidents(attack_type);
CREATE INDEX IF NOT EXISTS idx_incidents_risk_score ON incidents(risk_score);

-- 2. Blocked IPs Table
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    direction TEXT DEFAULT 'INBOUND',
    block_timestamp REAL NOT NULL,
    expiry_timestamp REAL,
    reason TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE', -- ACTIVE, RELEASED, FAILED, SIMULATED
    command_executed TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_status ON blocked_ips(status);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_expiry ON blocked_ips(expiry_timestamp);

-- 3. System Metrics Telemetry
CREATE TABLE IF NOT EXISTS system_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    total_flows INTEGER NOT NULL DEFAULT 0,
    total_threats INTEGER NOT NULL DEFAULT 0,
    total_blocked_ips INTEGER NOT NULL DEFAULT 0,
    total_alerts INTEGER NOT NULL DEFAULT 0,
    active_bans INTEGER NOT NULL DEFAULT 0,
    cpu_percent REAL DEFAULT 0.0,
    memory_percent REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp);

-- 4. Audit Log Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    agent_name TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    level TEXT DEFAULT 'INFO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- 5. Whitelisted IPs Table
CREATE TABLE IF NOT EXISTS whitelisted_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_or_cidr TEXT UNIQUE NOT NULL,
    description TEXT,
    added_at REAL NOT NULL
);

-- Seed default whitelisted addresses
INSERT OR IGNORE INTO whitelisted_ips (ip_or_cidr, description, added_at)
VALUES 
    ('127.0.0.1', 'Localhost IPv4 Loopback', strftime('%s', 'now')),
    ('::1', 'Localhost IPv6 Loopback', strftime('%s', 'now')),
    ('192.168.1.1', 'Default Gateway', strftime('%s', 'now')),
    ('8.8.8.8', 'Google Public DNS Primary', strftime('%s', 'now')),
    ('1.1.1.1', 'Cloudflare DNS Primary', strftime('%s', 'now'));
