# SentinelAI — Project Gameplan & Blueprint

**Status date:** September 2026  
**Vision:** Hybrid **NIDS + HIDS + multi-agent SOAR + explainable alerts** for Windows  
**Repo:** `AvaneshJ/Capstone_IDS` (SSH: `git@github-personal:…`)

This document is the working blueprint from **today’s codebase** to the full platform in the new problem statement. It replaces the old “NIDS-only offline CSV” end goal without throwing away Phase 1 or the multi-agent work already on GitHub.

---

## 1. One-sentence mission

Detect **network attacks** and **host malware behaviour** on Windows, explain them in plain language (MITRE + user-facing text), then **orchestrate a response** (alert → optional block → log → PDF), all through specialized agents.

---

## 2. What you already have (do not rebuild)

| Area | Location | Reality check |
|------|----------|----------------|
| Offline NIDS ML (3-class) | `ml/`, `models/` | XGBoost + encoder + **77 features (no `Dst Port`)** on CSE-CIC-**IDS2018**-style brute-force data (Benign / FTP / SSH). Cite **2018**, not 2017, in pitches. |
| Robustness story | `docs/Phase1_Progress_Report.md` | Experiments A–C, port-rule baseline, false-alarm argument |
| Feature contract | `docs/features_list.md`, `models/feature_columns.pkl` | Canonical 77-column order for live inference |
| Multi-agent SOAR skeleton | `Multi-Model Architecture/` | Packet → Detection → Threat → Risk → Decision → Firewall → Alert → Logging → Report (+ LLM agent) |
| Policies / SQLite / FastAPI stub | `rules/`, `database/`, `api/` | Present; need wiring to **real** models and live inputs |
| Demo path | `demo_runner.py`, `main.py` | Good for supervisor walkthrough of agent pipeline |

### Critical gap (integration)

Member-3 contracts expect things like `model.pkl`, `scaler.pkl`, `feature_names.json` and a **short** feature list.  
Member-1 artefacts are `sentinel_xgb.pkl`, `label_encoder.pkl`, `feature_columns.pkl` (**77** CIC names, **no scaler** for trees).

**Blueprint rule:** one adapter layer that maps live/flow dict → 77-vector → `sentinel_xgb.pkl`, instead of retraining just to match the sample contract.

---

## 3. Target architecture (end state)

```text
                    ┌─────────────────────┐
   Kali / lab VM    │  Attack generator   │  (Hydra, Nmap — own VMs only)
                    └──────────┬──────────┘
                               │ packets
┌──────────────────────────────┼──────────────────────────────┐
│ Windows laptop (victim + SentinelAI)                        │
│                                                              │
│  A. NIDS                         B. HIDS                     │
│  Packet/flow capture             Process / file / cookie     │
│  Feature extractor → 77 cols     Host feature vector         │
│  XGBoost (network)               XGB / Isolation Forest      │
│           \                         /                        │
│            \                       /                         │
│             ▼                     ▼                          │
│           Evidence events (common schema)                    │
│             │                                                │
│             ▼                                                │
│   Multi-agent SOAR (already sketched in repo)                │
│   Threat(MITRE) → Risk → Decision(YAML) → Firewall/Alert     │
│   → SQLite → PDF → Dashboard (React + WebSocket)             │
└──────────────────────────────────────────────────────────────┘
```

**User-facing promise:** never show “SYN anomaly”; show plain language via Alert/LLM agents.

---

## 4. Honest scope ladder (what to promise when)

Do **not** claim all attack types on day one. Expand labels only when you have data + live features.

| Tier | Capability | When |
|------|------------|------|
| **T0 — Now** | Offline 3-class NIDS + agent demo on synthetic/CSV flows | Done / wire model |
| **T1 — Next** | Lab PCAP/live flows → feature bridge → real XGBoost predict + log | Immediate priority |
| **T2** | SOAR on live NIDS hits (dry-run firewall → approved block) | After T1 stable |
| **T3** | Minimal HIDS (process + sensitive file/cookie path access) + second model | Parallel after T1 starts |
| **T4** | Correlation (host + network same incident) + React dashboard | After T2/T3 evidence exists |
| **T5** | Extra NIDS classes (Port Scan, DDoS) via more CIC days / retrain | Only after T1 works |

Supervisor CVE note: if required, **anchor HIDS** to one Windows CVE as a **case study** (mitigation + behavioural simulation). Platform stays the same; case study changes. Prefer network-visible or behaviour-demo CVEs — not “we wrote an RCE exploit.”

---

## 5. Blueprint: folder evolution

Keep current repos layout working; grow toward the plan’s `sentinelAI/` shape **without** a big-bang rewrite.

```text
Capstone/
├── docs/                          # Plans, Phase 1 report, this blueprint
├── data/                          # Local only (gitignored)
├── ml/                            # Offline train / EDA / experiments
├── models/                        # sentinel_xgb.pkl + encoder + feature_columns
│
├── nids/                          # NEW — live path (Member 2)
│   ├── capture.py                 # scapy / exporter wrapper
│   ├── feature_extractor.py       # packets/flows → 77 columns
│   └── live_predict.py            # load models/ + predict_proba
│
├── hids/                          # NEW — host path (later)
│   ├── process_monitor.py
│   ├── file_monitor.py
│   └── hids_model.pkl
│
├── soar/                          # Multi-agent SOAR brain (was Multi-Model Architecture)
│   ├── adapters/                  # CIC XGBoost adapter → Detection Agent
│   ├── agents/ ...
│   ├── core/ ...
│   ├── api/ ...
│   └── ...
│
└── dashboard/                     # React (Member 4), later
```

**Integration rule:** `nids/` and `hids/` emit events; they do not own firewall/PDF logic. Agents own response.

---

## 6. Development roadmap (revised from the pasted plan)

### Phase 1 — Offline NIDS baseline — **DONE**
- EDA, clean CSV, DT / RF / XGBoost, robustness A–C, saved artefacts  
- Docs: `Phase1_Progress_Report.md`, `features_list.md`

### Phase 2 — Wire real ML into agents — **NEXT (short)**
The pasted “Phase 2 = train models” is largely **already done** for NIDS. Remaining:

1. Adapter: Detection Agent loads `../models/sentinel_xgb.pkl` + `feature_columns.pkl` + `label_encoder.pkl`  
2. Align flow schema (CIC names vs snake_case contract) in one mapper  
3. Golden demo using **real** model on rows from `cic_clean.csv` and on synthetic lab flows  

**Exit criteria:** `demo_runner` / orchestrator prints Benign vs FTP vs SSH with confidence from the real XGBoost file.

### Phase 3 — Live NIDS lab + feature bridge — **CRITICAL PATH**
1. VirtualBox + Kali host-only network  
2. Capture (Scapy and/or CICFlowMeter) on Windows  
3. Feature extractor → **77 columns, training order**  
4. Ground-truth lab log: what you ran vs what model said  
5. Feed live flow dict into orchestrator queue  

**Exit criteria:** Hydra SSH against **your** lab target → model often says SSH-Bruteforce; browsing → mostly Benign (expect some drift).

### Phase 4 — SOAR hardening (NIDS-triggered)
1. Policies in `policies.yaml` (thresholds, whitelist, cooldown)  
2. Firewall agent **dry-run first**, then optional `netsh` with user approval  
3. SQLite incident trail + PDF report on real incidents  
4. Plain-language alert text (LLM agent or templates)

**Exit criteria:** One end-to-end NIDS incident: detect → risk → decision → (dry) block → DB → PDF.

### Phase 5 — HIDS module
1. `psutil` + `watchdog`: process create, path touches under Chrome/Discord/Steam cookie/token locations  
2. Small labelled behavioural dataset (benign vs simulated stealer-like access patterns in **lab**)  
3. Isolation Forest and/or second XGBoost  
4. Host Agent → same event bus / incident schema  

**Exit criteria:** Simulated “cookie DB read + sudden outbound” story produces host incident + user-readable alert (quarantine/kill **only** for processes you launched in lab).

### Phase 6 — Correlation + Dashboard
1. Correlate host + network windows (same time / same outbound IP)  
2. React + WebSocket live alerts, timeline, Recharts  
3. FastAPI already in repo — extend for dashboard contract  

**Exit criteria:** User sees story-style alerts, not raw flags.

### Phase 7 — Expand NIDS classes (optional)
- Add CIC days for Port Scan / DDoS only after live bridge works  
- Retrain; update MITRE map (`T1046`, `T1498`, etc.)

---

## 7. How to test that predictions are right (lab doctrine)

You **never** judge the model on random public Wi‑Fi first. You generate labelled traffic.

| Step | Action | Success signal |
|------|--------|----------------|
| 1 | Host-only lab: Windows + Kali | Ping visible in sniffer |
| 2 | Benign: browse / download on Windows | Mostly Benign |
| 3 | Attack **own** VM/service: Hydra SSH/FTP, Nmap | Expected class (or known gap if class not in model yet) |
| 4 | Packets → flows → **77 features** | Row shape `(1, 77)` matches `feature_columns.pkl` |
| 5 | `predict` + `predict_proba` | Label + confidence |
| 6 | Scorecard | Confusion table: Actual (what you ran) vs Predicted |

**Current model truth table (honest):**

| You generate | Model can output today |
|--------------|-------------------------|
| Web / ping / most benign | Benign |
| SSH Hydra | SSH-Bruteforce |
| FTP Hydra | FTP-BruteForce |
| Nmap / DDoS | **Not trained** — expect Benign or wrong; do not claim until retrain |

Keep a simple CSV: `timestamp, scenario, expected, predicted, confidence, notes`.

---

## 8. Immediate gameplan (next 2–3 weeks)

Ordered; do not skip ahead to React.

### Week A — Integration + honesty in demos
1. Document feature/name mismatch (77 CIC vs agent sample features).  
2. Implement **one** mapper + point Detection Agent at real `models/`.  
3. Run offline CSV row through full agent pipeline (SOAR demo with real ML).  
4. Fix supervisor wording: **CSE-CIC-IDS2018** brute-force subset; 77 features without `Dst Port`.

### Week B — Lab plumbing
1. VirtualBox + Kali OVA; host-only adapter; note IPs.  
2. OpenSSH (and/or FTP) **on a disposable lab VM**, not production.  
3. Scapy sniff proof: Kali `ping` → Windows prints packets.  
4. Choose exporter path: CICFlowMeter **or** reduced feature set + retrain (decide explicitly).

### Week C — First live scorecard
1. Feature extractor MVP (even partial columns: document gaps).  
2. 20+ labelled trials (benign + SSH; FTP if ready).  
3. One page results for supervisor: live accuracy ≠ CIC offline accuracy.  
4. Only then: dry-run firewall on high-confidence SSH hits.

### Parallel (light)
- Sketch HIDS feature list (process name, signed/unsigned, path category, outbound count).  
- No full stealer simulation until NIDS live path exists.

---

## 9. Team split (matches repo + new vision)

| Member | Owns | Near-term deliverable |
|--------|------|------------------------|
| **1 — AIML** | `ml/`, `models/`, HIDS model later, live eval scorecard | Adapter + feature contract; later HIDS features |
| **2 — Capture / security** | `nids/` capture + extractor, lab attacks | PCAP/live → flow dict |
| **3 — SOAR** | `Multi-Model Architecture/` | Real-model load, policies, dry-run response |
| **4 — Dashboard** | `dashboard/` + API consumer | Wait for stable incident JSON; then React + WS |

---

## 10. Tech checklist (from the plan — prioritized)

**Now:** Python, joblib, XGBoost, pandas, scikit-learn, PyYAML, SQLite (existing), Scapy  
**Soon:** psutil, watchdog, netsh (dry-run), FastAPI/WebSocket polish  
**Later:** React, Recharts, Tailwind  

Skip buying commercial IDS. Stay in isolated VMs for attacks.

---

## 11. 45-second pitch (corrected)

> SentinelAI is a hybrid AI Windows defence platform. Our NIDS uses XGBoost on CSE-CIC-IDS2018-style flow features to detect SSH and FTP brute force, and we are bridging live lab traffic into that model. A multi-agent SOAR layer already maps MITRE techniques, scores risk, can drive firewall actions, logs to SQLite, and builds PDF reports. Next we add a Windows HIDS for behavioural threats such as session-cookie theft, then a user-friendly dashboard so alerts read like plain language, not packet flags. Goal: detect on both network and host, explain, and respond.

---

## 12. Definition of done (project)

Minimum shippable Capstone story:

1. Live or lab-captured **NIDS** path with documented feature bridge and scorecard.  
2. Multi-agent **SOAR** on those detections (alert + log + report; firewall at least dry-run).  
3. **HIDS** MVP with at least one behavioural scenario (e.g. sensitive browser DB access pattern) and MITRE tag (e.g. T1539).  
4. Dashboard **or** strong CLI/API demo if UI slips — prefer thin React if time allows.  
5. Clear limitations: not all CVEs, not encrypted payload inspection, live accuracy ≠ CIC CSV scores.

---

## 13. What to do tomorrow morning

1. Open `Multi-Model Architecture/demo_runner.py` and confirm it runs.  
2. List exact files Detection Agent loads vs files in `Capstone/models/`.  
3. Write a half-page “adapter design” (names + shapes).  
4. Install/verify VirtualBox; download Kali OVA if not present.  
5. Do **not** start the React app yet.

---

*This blueprint is the source of truth for sequencing. Update it when a phase’s exit criteria are met.*
