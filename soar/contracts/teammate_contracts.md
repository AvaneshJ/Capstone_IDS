# SentinelAI — Teammate Integration Contracts & API Protocols

This document defines the interface specifications and contract protocols for parallel development across all 4 team members.

**Package layout:** Capstone root → `ml/`, `models/`, `nids/`, `hids/`, `soar/`, `dashboard/`.

---

## 1. Member 1 Contract (Machine Learning Lead)
**What Member 1 Provides (Phase 1 — actual artefacts):**

| File | Role |
|------|------|
| `models/sentinel_xgb_v2.pkl` | 6-class XGBoost classifier |
| `models/label_encoder_v2.pkl` | Maps class ids ↔ Benign / Botnet / DDoS / DoS / FTP-BruteForce / SSH-Bruteforce |
| `models/feature_columns_v2.pkl` | Ordered list of **77** CIC feature names (**no `Dst Port`**) |

SOAR loads these via `soar/adapters/cic_xgb_adapter.py`.  
Do **not** require `scaler.pkl` for this tree model. Dataset citation: **CSE-CIC-IDS2018**-style multiclass (`cic_multiclass_clean.csv`).
Optional hybrid: pass `dst_port` into `adapter.predict(...)` to resolve DoS ↔ FTP/SSH swaps (port is not a model feature).

### Python Model API (through adapter):
```python
from soar.adapters import CicXgbAdapter

adapter = CicXgbAdapter()
adapter.load()
label, confidence, probs = adapter.predict(raw_features_dict_77)
```

Legacy short `feature_names.json` sample contract is obsolete for Phase-1 NIDS.  
Live flows must populate `FlowEvent.raw_features` with the 77 CIC keys (`nids/feature_extractor.py`).

---

## 2. Member 2 Contract (Network Sniffer & PCAP Lead)
**What Member 2 Provides:** Live Flow Dictionary stream via Queue or Generator.

### Flow Dictionary Schema:
Member 2 pushes standardized dictionaries to a Python `queue.Queue` or `multiprocessing.Queue`:
```python
flow_dict = {
    "src_ip": "192.168.1.50",          # Attacker / Source IP (string)
    "dst_ip": "192.168.1.10",          # Destination / Victim IP (string)
    "src_port": 54120,                 # Source Port (int)
    "dst_port": 80,                    # Destination Port (int)
    "protocol": 6,                     # IP Protocol (6=TCP, 17=UDP, 1=ICMP)
    "flow_duration": 0.12,             # Duration in seconds (float)
    "tot_fwd_pkts": 4,                 # Total Forward Packets (int)
    "tot_bwd_pkts": 0,                 # Total Backward Packets (int)
    "fwd_pkt_len_mean": 24.0,          # Mean Fwd Packet Length in bytes (float)
    "bwd_pkt_len_mean": 0.0,           # Mean Bwd Packet Length in bytes (float)
    "flow_bytes_s": 2400.0,            # Flow throughput bytes/sec (float)
    "flow_pkts_s": 140.0,              # Flow packet rate pkts/sec (float)
    "syn_flag_count": 4,               # SYN Flags observed (int)
    "ack_flag_count": 0,               # ACK Flags observed (int)
    "rst_flag_count": 0,               # RST Flags observed (int)
    "timestamp": 1724500000.0          # Epoch timestamp (float)
}
```

### Feeding into Orchestrator:
```python
from core.orchestrator import SentinelOrchestrator

orchestrator = SentinelOrchestrator()
orchestrator.initialize()

# Single flow ingestion:
incident = orchestrator.process_flow(flow_dict)

# Queue listener loop:
# orchestrator.run_queue_listener(sniffer_queue)
```

---

## 3. Member 4 Contract (SOC Dashboard & UI Lead)
**What Member 4 Consumes:** FastAPI RESTful Endpoints (`http://localhost:8000/api/...`) + Real-Time WebSocket (`ws://localhost:8000/ws/live-stream`).

### Interactive Swagger API Documentation:
When the FastAPI backend is running, Member 4 can explore and test all endpoints interactively at:
`http://localhost:8000/docs`

---

### REST API Endpoints for React Frontend:

| Method | Endpoint | Description | Return Payload |
|--------|----------|-------------|----------------|
| `GET` | `/api/status` | System health & agent status matrix | `{ cpu_percent, memory_percent, uptime_seconds, agent_statuses: {...} }` |
| `GET` | `/api/metrics` | High-level Dashboard KPI cards | `{ total_flows_analyzed, total_threats_detected, active_firewall_blocks, average_threat_risk, attack_distribution, top_offenders }` |
| `GET` | `/api/incidents?limit=50&severity=CRITICAL` | Paginated incident list for tables | `{ count: 50, incidents: [...] }` |
| `GET` | `/api/incidents/{incident_id}` | Full incident forensic & MITRE details | `{ incident_id, flow, detection, threat, risk, action_plan, llm_explanation }` |
| `GET` | `/api/blocks` | List of active/released firewall rules | `{ count: 3, blocked_ips: [...] }` |
| `POST` | `/api/blocks/unblock/{rule_id}` | Manual unblock button in React UI | `{ status: "SUCCESS", message: "..." }` |
| `POST` | `/api/flows/ingest` | Submit custom flow (e.g. from sniffer or UI simulator) | `{ status: "PROCESSED", incident_id: "...", risk_score: 8.8, ... }` |
| `POST` | `/api/reports/generate` | Trigger on-demand PDF report generation | `{ status: "GENERATED", filename: "...", download_url: "/api/reports/download/..." }` |
| `GET` | `/api/reports/download/{filename}` | Download compiled PDF report | Binary PDF stream (`application/pdf`) |
| `WS` | `/ws/live-stream` | Real-time bi-directional alert stream | JSON events (`NEW_INCIDENT`, `THREAT_ALERT`, `CONNECTED`) |

---

### React.js Frontend Code Snippets for Member 4:

#### 1. Fetching Dashboard KPIs (React Hook):
```javascript
import React, { useState, useEffect } from 'react';

export function useDashboardMetrics() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/metrics');
      const data = await res.json();
      setMetrics(data);
    } catch (err) {
      console.error('Failed to load metrics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 3000); // Polling fallback
    return () => clearInterval(interval);
  }, []);

  return { metrics, loading, refetch: fetchMetrics };
}
```

#### 2. Real-Time Alert Stream (React WebSocket Hook):
```javascript
import { useEffect, useState } from 'react';

export function useLiveThreatStream(onNewAlert) {
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8000/ws/live-stream');

    ws.onopen = () => {
      console.log('Connected to SentinelAI Threat Stream');
      setConnected(true);
    };

    ws.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      console.log('Live Alert Received:', payload);
      if (onNewAlert) {
        onNewAlert(payload);
      }
    };

    ws.onclose = () => setConnected(false);
    ws.onerror = (err) => console.error('WebSocket error:', err);

    return () => ws.close();
  }, [onNewAlert]);

  return { connected };
}
```

#### 3. Manual Unblock Action Button in React:
```javascript
async function handleUnblock(ruleId) {
  const res = await fetch(`http://localhost:8000/api/blocks/unblock/${ruleId}`, {
    method: 'POST'
  });
  if (res.ok) {
    alert(`Rule ${ruleId} successfully lifted!`);
  }
}
```

