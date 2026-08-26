# 🛡️ SentinelAI — Autonomous Multi-Agent & SOAR Platform

> **Role: Member 3 — Multi-Agent Orchestrator & SOAR (Security Orchestration, Automation, and Response) Lead**  
> **Objective:** The "Brain & Autonomous Action Engine" of SentinelAI that ingests raw network flow telemetry, coordinates 11 specialist agents, executes ML inference, maps threats to MITRE ATT&CK, computes dynamic multi-factor risk scores, enforces OS firewall mitigations, logs events, broadcasts multi-channel alerts, and compiles executive PDF SOC reports.

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
sentinel-ai/
│
├── core/
│   ├── event_bus.py          # In-memory publish/subscribe event dispatcher with error isolation
│   ├── schemas.py            # Strongly typed data models (FlowEvent, Incident, ActionPlan, etc.)
│   ├── orchestrator.py       # Master runner coordinating all 11 agents & background workers
│   └── __init__.py
│
├── agents/
│   ├── base_agent.py         # Abstract base class for all agents with lifecycle & telemetry
│   ├── packet_agent.py       # Validates and cleans Member 2's incoming flow telemetry
│   ├── detection_agent.py    # Loads Member 1's model.pkl + scaler.pkl (with heuristic fallback)
│   ├── risk_agent.py         # Dynamic risk scoring (1-10 scale) using velocity & asset sensitivity
│   ├── threat_agent.py       # Attack signature analysis & MITRE ATT&CK mapping (T1046, T1498, etc.)
│   ├── decision_agent.py     # Policy evaluation, whitelist checks & SOAR response planning
│   ├── firewall_agent.py     # OS firewall execution (Windows netsh / Linux iptables) with dry-run & unblock
│   ├── alert_agent.py        # Desktop toast, Dashboard Queue (Member 4), and Telegram notifications
│   ├── logging_agent.py      # SQLite persistence into database/sentinel.db
│   ├── report_agent.py       # Automated PDF incident & shift summary reports using ReportLab
│   ├── llm_agent.py          # GenAI SOC analyst plain-English briefings (Gemini / Ollama / Expert System)
│   └── __init__.py
│
├── rules/
│   ├── policies.yaml         # Configurable security rules, thresholds, cooldowns, and whitelists
│   ├── policy_engine.py      # Evaluates rules against threats and computes sensitivities
│   └── __init__.py
│
├── database/
│   ├── schema.sql            # SQLite DDL tables (incidents, blocked_ips, system_metrics, audit_logs)
│   ├── db_manager.py         # Thread-safe SQLite persistence and analytical queries for dashboard
│   └── __init__.py
│
├── models/                   # Member 1 ML artifacts
│   ├── model.pkl             # Trained Classifier
│   ├── scaler.pkl            # Feature Scaler
│   └── feature_names.json    # Feature vector ordering
│
├── contracts/
│   └── teammate_contracts.md # Standardized API specifications for Members 1, 2, and 4
│
├── scripts/
│   └── generate_sample_model.py # Sample ML artifact generator for immediate testing
│
├── tests/
│   ├── mock_traffic.py       # High-fidelity synthetic cyberattack flow generator
│   └── test_agents.py        # Comprehensive 12-test unit and integration suite
│
├── demo_runner.py            # Golden Demo 6-stage presentation script
├── main.py                   # Master CLI entrypoint
├── requirements.txt          # Python dependencies
└── README.md
```

---

## 3. Specifications of the 11 Specialist Agents

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
```powershell
python -m pip install -r requirements.txt
```

### Step 2: Generate Sample Model Artifacts (Optional)
```powershell
python scripts/generate_sample_model.py
```

### Step 3: Run Full Unit & Integration Test Suite
```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 6. How to Run the System

### 1. Launch the FastAPI Backend Server (For Member 4's React Frontend)
```powershell
python main.py server --host 127.0.0.1 --port 8000 --reload
```
- **Interactive Swagger REST API Docs:** `http://localhost:8000/docs`
- **Real-Time WebSocket Feed for React:** `ws://localhost:8000/ws/live-stream`

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
1. **Stage 1 (System Boot):** Demonstrates all 11 agents initializing, SQLite connecting, and policies loading.
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
