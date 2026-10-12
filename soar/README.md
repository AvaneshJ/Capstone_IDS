# SentinelAI — Autonomous Multi-Agent & SOAR Platform (`soar/`)

> **Role: Member 3 — Multi-Agent Orchestrator & SOAR Lead**  
> Package path: `Capstone/soar/` (renamed from `Multi-Model Architecture/`).

## NIDS model integration (v3 — active)

Detection uses `adapters/cic_xgb_adapter.py` → Capstone `models/sentinel_xgb_v3.pkl` via `config/paths.py`
(77 CIC features, `label_encoder_v3.pkl`, `feature_columns_v3.pkl`, **no scaler**).
Classes: Benign, Botnet, DDoS, DoS, FTP-BruteForce, PortScan, SSH-Bruteforce. Hybrid `dst_port` override and
the OOD policy (`rules/ood_policy.py`) run after the model.

Package notes: `../docs/ML_Package_v3.md` (active), `../docs/ML_Package_v2.md` (CIC-only rollback).

## HIDS integration

`agents/host_agent.py` takes host events (process + sensitive file access, optional Isolation Forest label from
`hids/`), classifies them, maps MITRE (T1555.003 browser credentials, T1539 session cookies, T1005 local data), scores risk
and decides `TERMINATE_PROCESS` / `ALERT_ONLY` / `LOG_ONLY`. Process termination has its own dry-run switch (`dry_run_host_response`, default `True`).


---

## 1. System Architecture & Information Flow

```
               [ Member 2: Live Sniffer / PCAP ]
                               │
                               ▼ Flow Features (Dict/JSON)
                   ┌─────────────────────────┐
                   │   Packet Ingest Agent   │
                   └───────────┬─────────────┘
                               │
                               ▼
                   ┌─────────────────────────┐
                   │     Detection Agent     │ ◄─── [ Member 1: model.pkl ]
                   └───────────┬─────────────┘
                               │ Attack Type + Confidence %
           ┌───────────────────┴───────────────────┐
           ▼                                       ▼
┌─────────────────────┐                 ┌─────────────────────┐
│ Threat Analysis     │                 │   Risk Assessment   │
│ Agent (Why & What)  │                 │   Agent (Severity)  │
└──────────┬──────────┘                 └──────────┬──────────┘
           │ Signature Evidence                    │ Risk Score (1-10)
           └───────────────────┬───────────────────┘
                               │
                               ▼
                   ┌─────────────────────────┐
                   │ Decision Engine /       │ ◄─── [ Rules & Policies ]
                   │ Response Planning Agent │
                   └───────────┬─────────────┘
                               │ Action Plan (Block/Alert/Log)
       ┌───────────────────────┼───────────────────────┐
       ▼                       ▼                       ▼
┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│Firewall Agent│        │ Alert Agent  │        │Logging Agent │
│(netsh/iptables)       │(Desktop/WS)  │        │(SQLite DB)   │
└──────────────┘        └──────────────┘        └───────┬──────┘
                                                        │
                                                        ▼
                                                ┌──────────────┐
                                                │ Report Agent │
                                                │ (PDF Gen)    │
                                                └──────────────┘
                                                        ▲
                                                        │
                                         [ Member 4: SOC Dashboard ]
```

---

## 2. Directory Structure

```
soar/
│
├── adapters/
│   └── cic_xgb_adapter.py    # Loads the active XGBoost package (v3) + hybrid dst_port override
│
├── api/
│   └── server.py             # FastAPI REST + WebSocket backend for the React dashboard
│
├── core/
│   ├── event_bus.py          # In-memory publish/subscribe event dispatcher with error isolation
│   ├── schemas.py            # Strongly typed data models (FlowEvent, Incident, ActionPlan, etc.)
│   ├── orchestrator.py       # Master runner coordinating all agents (process_flow / process_host_event)
│   └── __init__.py
│
├── agents/
│   ├── base_agent.py         # Abstract base class for all agents with lifecycle & telemetry
│   ├── packet_agent.py       # Validates and cleans Member 2's incoming flow telemetry
│   ├── detection_agent.py    # Runs the XGBoost adapter (with heuristic fallback)
│   ├── risk_agent.py         # Dynamic risk scoring (1-10 scale) using velocity & asset sensitivity
│   ├── threat_agent.py       # Attack signature analysis & MITRE ATT&CK mapping (T1046, T1498, etc.)
│   ├── decision_agent.py     # Policy evaluation, whitelist checks & SOAR response planning
│   ├── firewall_agent.py     # OS firewall execution (Windows netsh / Linux iptables) with dry-run & unblock
│   ├── alert_agent.py        # Desktop toast, Dashboard Queue (Member 4), and Telegram notifications
│   ├── logging_agent.py      # SQLite persistence into database/sentinel.db
│   ├── report_agent.py       # Automated PDF incident & shift summary reports using ReportLab
│   ├── llm_agent.py          # GenAI SOC analyst plain-English briefings (Gemini / Ollama / Expert System)
│   ├── host_agent.py         # HIDS: classify host events, MITRE map, risk, process termination (dry-run)
│   └── __init__.py
│
├── rules/
│   ├── policies.yaml         # Configurable security rules, thresholds, cooldowns, and whitelists
│   ├── policy_engine.py      # Evaluates rules against threats and computes sensitivities
│   ├── ood_policy.py         # Out-of-distribution override on top of the ML label
│   └── __init__.py
│
├── database/
│   ├── schema.sql            # SQLite DDL (incidents, host_incidents, blocked_ips, system_metrics, audit_logs)
│   ├── db_manager.py         # Thread-safe SQLite persistence and analytical queries for dashboard
│   └── __init__.py
│
├── contracts/
│   └── teammate_contracts.md # Model, sensor, host-event and dashboard API contracts
│
├── tests/
│   ├── mock_traffic.py       # Synthetic cyberattack flow generator
│   └── test_host_agent.py    # HostAgent / host pipeline tests
│
├── demo_runner.py            # Golden Demo 6-stage presentation script
├── demo_real_model.py        # Real XGBoost model on CSV rows through the full pipeline
├── lab_csv_to_soar.py        # Replay lab-captured flow CSVs into SOAR
├── main.py                   # Master CLI entrypoint (server / demo / simulate / report / status)
├── requirements.txt          # Points at the root requirements.txt
└── README.md
```

Models are loaded from the Capstone root `models/` folder (not inside `soar/`). The SQLite database is created at
`database/sentinel.db` on first run (gitignored).

---

## 3. Specifications of the Specialist Agents

| # | Agent Name | File | Role & Capabilities |
|---|------------|------|---------------------|
| 1 | **BaseAgent** | `agents/base_agent.py` | Unified lifecycle (`initialize()`, `process()`, `shutdown()`), health telemetry, status state-machine. |
| 2 | **PacketAgent** | `agents/packet_agent.py` | Sanitizes NaN/Inf values, normalizes IP addresses/ports, validates flow schemas. |
| 3 | **DetectionAgent** | `agents/detection_agent.py` | ML inference engine calling `model.predict_proba(X)` with heuristic fallback classifier. |
| 4 | **RiskAgent** | `agents/risk_agent.py` | Calculates multi-factor risk score (1.0–10.0) with 60s sliding window frequency tracker. |
| 5 | **ThreatAgent** | `agents/threat_agent.py` | Synthesizes forensic signature evidence and maps attacks to the **MITRE ATT&CK Matrix**. |
| 6 | **DecisionAgent** | `agents/decision_agent.py` | Evaluates `policies.yaml` rules, checks whitelists, and generates response `ActionPlan`. |
| 7 | **FirewallAgent** | `agents/firewall_agent.py` | Autonomous OS firewall execution (Windows `netsh` / Linux `iptables`) with dry-run safety and auto-unblocker. |
| 8 | **AlertAgent** | `agents/alert_agent.py` | Multi-channel notifications: Desktop Toast, Dashboard Queue (for Member 4), and Telegram. |
| 9 | **LoggingAgent** | `agents/logging_agent.py` | Thread-safe SQLite persistence for incidents, blocks, telemetry, and audit compliance. |
| 10 | **ReportAgent** | `agents/report_agent.py` | Generates professional executive & forensic PDF reports via ReportLab. |
| 11 | **LLMAgent** | `agents/llm_agent.py` | GenAI SOC analyst briefings via Google Gemini API, local Ollama, or built-in offline expert system. |
| 12 | **HostAgent** | `agents/host_agent.py` | HIDS: classifies host events (heuristics or Isolation Forest label), MITRE mapping, risk, and verified process termination (dry-run by default). |

`AlertAgent` puts every NIDS/HIDS alert on the dashboard queue with its `incident_id`, so the dashboard can link a live pop-up straight to the incident.

---

## 4. Multi-Factor Dynamic Risk Formula

$$\text{Risk Score} = (\text{Base Attack Weight} \times \text{Confidence}) + \text{Velocity Multiplier} + \text{Target Sensitivity}$$

- **Base Attack Weights:** DDoS / Botnet = `9.0`, Infiltration = `8.5`, DoS = `8.0`, Brute Force = `7.0`, Port Scan = `5.0`, Benign = `0.0`.
- **Velocity Multiplier:** 60-second sliding window tracking event frequency per source IP:
  - 1–3 events: `+0.0`
  - 4–10 events: `+0.8`
  - 11–25 events: `+1.6`
  - > 25 events: `+2.5`
- **Target Asset Sensitivity:** Critical DB ports (3306, 5432, 1433: `+1.5`), Admin ports (22, 3389: `+1.5`), Critical Subnets: `+1.0`.
- **Severity Categories:**
  - `CRITICAL` (8.5–10.0) $\rightarrow$ Immediate Permanent/24h Firewall Block + Urgent Alerts + LLM Briefing.
  - `HIGH` (7.0–8.4) $\rightarrow$ Temporary Ban (30 mins) + High Alert + LLM Briefing.
  - `MEDIUM` (5.0–6.9) $\rightarrow$ Temporary Ban (15 mins) + Warning Alert.
  - `LOW` (1.0–4.9) $\rightarrow$ Passive Watchlist Log.

---

## 5. Quickstart & Installation

### Step 1: Install Dependencies
From the Capstone root (one list for the whole project, includes FastAPI and uvicorn):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Step 2: Run the Tests
From the Capstone root:
```powershell
python -m pytest soar/tests -q
```

---

## 6. How to Run the System

All commands below run from inside `soar/`.

### 1. Launch the FastAPI Backend Server (for the React dashboard)
```powershell
python main.py server                       # defaults: --host 127.0.0.1 --port 8000
python main.py server --reload              # auto-reload while editing
```
- **Interactive Swagger REST API Docs:** `http://localhost:8000/docs`
- **Real-Time WebSocket Feed for React:** `ws://localhost:8000/ws/live-stream`
- The server always starts in **test mode**: firewall blocks and process kills are simulated, desktop toasts off.
- Then start the dashboard (`dashboard/README.md`). Full endpoint list: `contracts/teammate_contracts.md`.

### 2. Launch the Golden Demo (Evaluation Presentation Mode)
```powershell
python demo_runner.py
# or
python main.py demo
```

### 3. Run Synthetic Cyberattack Simulation Stream
```powershell
python main.py simulate --dry-run
```

### 4. Generate On-Demand SOC Executive PDF Summary
```powershell
python main.py report
```

### 5. Inspect Live SOC Database Status & KPIs
```powershell
python main.py status
```

---

## 7. Golden Demo Script (For Final Project Defense)

When presenting to evaluators, execute `python demo_runner.py`:
1. **Stage 1 (System Boot):** Demonstrates all agents initializing, SQLite connecting, and policies loading.
2. **Stage 2 (Normal Baseline):** Ingests normal HTTPS flows $\rightarrow$ Classified as `BENIGN` $\rightarrow$ Risk `0.2/10` $\rightarrow$ LoggingAgent logs quietly without alerts.
3. **Stage 3 (Simulated Attack):** Simulates an authorized `nmap -sS` SYN sweep targeting 10 ports from `192.168.1.50`.
4. **Stage 4 (Real-Time Choreography):**
   - `DetectionAgent` fires: **PortScan** (98% confidence).
   - `ThreatAgent` extracts evidence: *"Rapid SYN probes (140 pkts/s) with 0 ACK responses"*. Mapped to **MITRE T1046**.
   - `RiskAgent` spikes score to **8.8/10 (CRITICAL)** due to high probe velocity and sensitive ports.
   - `DecisionAgent` triggers policy **BLOCK_IP**.
   - `FirewallAgent` instantly executes OS block rule: `netsh advfirewall firewall add rule name="SentinelAI_Block_192.168.1.50" dir=in action=block remoteip=192.168.1.50`.
   - `AlertAgent` notifies desktop and pushes payload to Member 4's dashboard stream.
   - `LLMAgent` produces plain-English executive analysis and actionable mitigation steps.
5. **Stage 5 (Verification):** Subsequent packets from `192.168.1.50` are instantly dropped.
6. **Stage 6 (Forensic Report):** Compiles high-resolution incident and SOC summary PDFs into `reports/`.

---

## 8. Viva Defense: Why Multi-Agent Architecture Beats a Monolithic Script

1. **Separation of Concerns:** Each specialist agent handles one specific domain (ingestion, ML inference, threat forensics, risk scoring, response planning, firewall enforcement, reporting, alerting).
2. **Fault Isolation & Resilience:** If an external LLM API or alert webhook fails, the `EventBus` isolates the failure; the firewall enforcement and SQLite logging continue running without disruption.
3. **Independent Scalability:** Packet ingest and inference can scale across worker threads/processes, while report compilation runs asynchronously in the background.
4. **Dynamic Policy Reconfigurability:** Security rules (`rules/policies.yaml`) can be hot-reloaded without stopping the live network sniffer or retraining ML models.
5. **Clear Team Division:** Distinct contracts allow the ML Lead (Member 1), Network Lead (Member 2), and Dashboard Lead (Member 4) to develop and test their components in parallel without blocking each other.

---

## 9. Self-Protection (Anti-Tamper)

| Protection | Where | What raises a CRITICAL `Tamper` host incident |
|---|---|---|
| Integrity manifest (SHA-256, HMAC-signed) | `config/integrity.py`, `core/self_protection.py` | Models, `rules/policies.yaml`, `schema.sql`, core code (soar/hids/nids/config, Electron main) modified, deleted or added. Models are hashed **before** unpickling; tampered/unlisted models are refused. |
| API token | `config/security.py`, `api/server.py` | All `/api/*` and `/ws/live-stream` need `X-SentinelAI-Token` (or `?token=`). CORS limited to the dashboard origins. |
| Sensor heartbeats | `core/watchdog.py`, `core/live_monitor.py`, `POST /api/sensors/heartbeat` | A sensor thread dies or stops beating; the supervisor stops beating. |
| Unclean shutdown | `core/self_protection.py` | Previous engine run ended without a clean/planned stop (killed). |
| Tamper sensor | `hids/tamper_monitor.py` | Security log 1102 (cleared), 1100 (logging stopped), 4719 (audit removed); `taskkill`/`Stop-Process`/`wmic`/`sc stop` aimed at SentinelAI, `wevtutil cl`, `auditpol /clear`, firewall off, destructive commands on the install folder. |
| Evidence chain | `database/db_manager.py` (`evidence_chain` table) | Incidents, host incidents or audit rows edited, deleted, injected, or the DB truncated/replaced (HMAC chain + anchor outside the DB). |
| Append-only logs | `config/integrity.py` (`AppendOnlyWatch`) | `hids/logs/*.csv` truncated, edited or deleted. |

Secrets live outside the repo in `%PROGRAMDATA%\SentinelAI` (fallback `%LOCALAPPDATA%\SentinelAI`, override `SENTINEL_DATA_DIR`), ACL'd to the owner, SYSTEM and Administrators: `api_token`, `integrity.key`, `integrity_manifest.json`, `evidence_anchor_*.json`.

```powershell
.venv\Scripts\python -m config.integrity generate   # trust current models/policies/code (re-run after intended updates)
.venv\Scripts\python -m config.integrity verify     # exit code 1 if anything changed
.venv\Scripts\python -m config.integrity show       # where the token / key / manifest live
cd soar; ..\.venv\Scripts\python supervisor.py      # optional: keep the backend running, report kills
.\scripts\install_service.ps1                       # optional (Admin + NSSM): service + restart-on-failure + ACLs
```

Environment: `SENTINEL_AUTH=0` disables the token (demos only), `SENTINEL_INTEGRITY_REQUIRED=1` refuses to load models without a manifest, `SENTINEL_CORS_ORIGINS` adds dashboard origins, `SENTINEL_API_TOKEN` overrides the token. Browser dev mode: set `VITE_API_TOKEN` in `dashboard/.env`; the Electron app reads the token file itself.

Status: `GET /api/selfprotect/status` (also inside `/api/status` as `self_protection`), `POST /api/selfprotect/verify`; shown on the dashboard **System health** page and as a *Tamper alert* badge in the top bar.

Limits: user-mode protection only. Malware running as the same user can read that user's token/key; an Administrator can stop the service and rewrite files. Kernel-level self-defense (Protected Process Light, ELAM, minifilter drivers) needs signed drivers and is out of scope. Command-line detection relies on the 2 s process scan, so very short-lived `taskkill` runs can be missed — the heartbeat watchdog, unclean-shutdown check and supervisor cover the result.
