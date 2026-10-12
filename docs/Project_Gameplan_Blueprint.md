# SentinelAI — Project Gameplan & Blueprint

**Status date:** October 2026 — **project complete** (shipped as the Windows installer `SentinelAI Setup 1.0.0.exe`:
live NIDS v3 + HIDS + SOAR + self-protection + desktop app). Only host–network correlation remains open.
For the research paper start at `docs/README.md` and `docs/Research_Paper_Guide.md`.  
**Vision:** Hybrid **NIDS + HIDS + multi-agent SOAR + explainable alerts** for Windows  
**Repo:** `AvaneshJ/Capstone_IDS` (SSH: `git@github-personal:…`)

This document is the working blueprint from **today’s codebase** to the full platform in the new problem statement. It replaces the old “NIDS-only offline CSV” end goal without throwing away Phase 1 or the multi-agent work already on GitHub.

**ML packages:** CIC offline baseline frozen at **v2** (`docs/ML_Package_v2.md`). **Active package is v3** — CIC + lab merge (`docs/ML_Package_v3.md`).

---

## 1. One-sentence mission

Detect **network attacks** and **host malware behaviour** on Windows, explain them in plain language (MITRE + user-facing text), then **orchestrate a response** (alert → optional block → log → PDF), all through specialized agents.

---

## 2. What you already have (do not rebuild)

| Area | Location | Reality check |
|------|----------|----------------|
| Offline NIDS ML (**v2, 6-class, FROZEN**) | `ml/`, `models/`, `docs/ML_Package_v2.md` | XGBoost + encoder + **77 features (no `Dst Port`)** on CSE-CIC-**IDS2018**-style multiclass: Benign / Botnet / DDoS / DoS / FTP / SSH. Hybrid `dst_port` override in adapter. Cite **2018**, not 2017. |
| Phase-1 robustness story (3-class archive) | `docs/Phase1_Progress_Report.md` | Experiments A–C, port-rule baseline; historical only |
| Feature contract | `docs/features_list.md`, `models/feature_columns_v2.pkl` | Canonical 77-column order for live inference |
| Multi-agent SOAR + real model | `soar/` | Packet → Detection (CicXgbAdapter) → Threat → Risk → Decision → Firewall → Alert → Logging → Report (+ LLM) |
| Policies / SQLite / FastAPI | `soar/rules/`, `soar/database/`, `soar/api/` | Wired to the v3 model; REST + WebSocket used by the dashboard |
| Demo path | `soar/demo_real_model.py`, `soar/demo_runner.py`, `soar/main.py` | Supervisor walkthrough of agent pipeline |
| HIDS | `hids/`, `soar/agents/host_agent.py` | Process + credential-file sensors, Isolation Forest, HostBridge → SOAR (dry-run kill) |
| Dashboard | `dashboard/` | React 19 + Vite; live alerts over WebSocket, network + host incidents, unblock, PDF reports, Demo panel |
| Active NIDS model (**v3, 7-class**) | `models/*_v3.pkl`, `docs/ML_Package_v3.md` | CIC + Kali→Ubuntu lab merge; adds PortScan; OOD policy layer in `soar/rules/ood_policy.py` |
| Live capture | `nids/live_capture.py`, `soar/core/live_monitor.py` | Npcap or WinDivert fallback → Java-CICFlowMeter-compatible 77 features → SOAR; inbound-only, cooldowns, port-scan fan-out rule |
| Self-protection | `config/integrity.py`, `config/security.py`, `soar/core/self_protection.py`, `hids/tamper_monitor.py` | Signed integrity manifest, API token, HMAC evidence chain, heartbeats, tamper sensor, unclean-shutdown detection |
| False-positive handling | `hids/trust.py`, Settings → Trusted programs | Code-signing reputation, user allow rules (hash / publisher), "Stop this program now" |
| Desktop app + installer | `dashboard/electron/`, `packaging/` | Electron app with tray, admin elevation, start-at-login task; PyInstaller engine; NSIS per-machine installer |

### Integration gap — closed

Live packets now flow through `nids/live_capture.py` → 77 CIC keys + `dst_port` → orchestrator. Shipping artefacts
are the v3 files (`sentinel_xgb_v3.pkl`, `label_encoder_v3.pkl`, `feature_columns_v3.pkl`) loaded through
`soar/adapters/cic_xgb_adapter.py`; v2 stays on disk as rollback.

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
| **T0 — Done** | Offline **6-class** NIDS v2 + SOAR demo on CSV / synthetic flows | Frozen (`ML_Package_v2.md`) |
| **T1 — Done** | Lab PCAP/live flows → feature bridge → real XGBoost predict + log | `nids/live_capture.py` |
| **T2 — Done** | SOAR on live NIDS hits (dry-run firewall → approved block) | Test mode by default |
| **T3 — Done** | Minimal HIDS (process + sensitive file/cookie path access) + Isolation Forest | Plus trust layer |
| **T4 — Dashboard done** | Correlation (host + network same incident) + React dashboard | Correlation still open |
| **T5 — Done** | Extra NIDS classes (Port Scan) via lab data / retrain | v3 + live fan-out rule |

Supervisor CVE note: if required, **anchor HIDS** to one Windows CVE as a **case study** (mitigation + behavioural simulation). Platform stays the same; case study changes. Prefer network-visible or behaviour-demo CVEs — not “we wrote an RCE exploit.”

---

## 5. Blueprint: folder evolution

Keep current repos layout working; grow toward the plan’s `sentinelAI/` shape **without** a big-bang rewrite.

```text
Capstone/
├── docs/                          # Plans, Phase 1 report, this blueprint
├── data/                          # Local only (gitignored)
├── ml/                            # Offline train / EDA / experiments
├── models/                        # sentinel_xgb_v2.pkl + encoder_v2 + feature_columns_v2
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
- EDA, clean CSV, DT / RF / XGBoost, robustness A–C (3-class archive)  
- Docs: `Phase1_Progress_Report.md`

### Phase 1b / Package v2 — Multiclass + hybrid — **DONE / FROZEN**
- 6-class dataset + `train_xgb_v2.py` → `*_v2.pkl`  
- Hybrid port override in adapter + Detection Agent  
- Docs: `ML_Package_v2.md`, `features_list.md`, contracts  

### Phase 2 — Wire real ML into agents — **DONE**
1. Adapter: Detection Agent loads `sentinel_xgb_v2.pkl` + `feature_columns_v2.pkl` + `label_encoder_v2.pkl`  
2. Flow schema mapper: `nids/feature_extractor.py` + PacketAgent  
3. Golden demo: `soar/demo_real_model.py` on multiclass CSV rows  

**Exit criteria met:** real XGBoost labels + confidence through SOAR on CSV paths.

### Phase 3 — Live NIDS lab + feature bridge — **DONE**
Lab built (Kali `192.168.56.101` → Ubuntu `192.168.56.102`), lab flows merged into model v3, live capture with
Npcap or WinDivert, and a Java-CICFlowMeter-compatible feature bridge (`nids/live_capture.py`).

1. VirtualBox + Kali host-only network  
2. Capture (Scapy and/or CICFlowMeter) on Windows  
3. Feature extractor → **77 columns, training order**  
4. Ground-truth lab log: what you ran vs what model said  
5. Feed live flow dict into orchestrator queue  

**Exit criteria:** Hydra SSH against **your** lab target → model often says SSH-Bruteforce; browsing → mostly Benign (expect some drift).

### Phase 4 — SOAR hardening (NIDS-triggered) — **DONE**
Plus the OOD policy layer, inbound-only routing, cooldowns and incident budget (`soar/core/live_monitor.py`).

1. Policies in `policies.yaml` (thresholds, whitelist, cooldown)  
2. Firewall agent **dry-run first**, then optional `netsh` with user approval  
3. SQLite incident trail + PDF report on real incidents  
4. Plain-language alert text (LLM agent or templates)

**Exit criteria:** One end-to-end NIDS incident: detect → risk → decision → (dry) block → DB → PDF.

### Phase 5 — HIDS module — **PROTOTYPE DONE**
Sensors (`hids/process_monitor.py`, `hids/file_monitor.py`), stealer simulator + dataset, Isolation Forest
(`models/hids_isolation_forest.joblib`), `hids/live.py` → `HostAgent` (MITRE T1555.003 / T1539, dry-run termination).

1. `psutil` + `watchdog`: process create, path touches under Chrome/Discord/Steam cookie/token locations  
2. Small labelled behavioural dataset (benign vs simulated stealer-like access patterns in **lab**)  
3. Isolation Forest and/or second XGBoost  
4. Host Agent → same event bus / incident schema  

**Exit criteria:** Simulated “cookie DB read + sudden outbound” story produces host incident + user-readable alert (quarantine/kill **only** for processes you launched in lab).

### Phase 6 — Correlation + Dashboard — **DASHBOARD DONE, CORRELATION OPEN**
1. Correlate host + network windows (same time / same outbound IP) — **not started**  
2. React + WebSocket live alerts, timeline, Recharts — **done** (`dashboard/`)  
3. FastAPI extended for dashboard contract — **done** (host endpoints, `incident_id` on live alerts; `soar/contracts/teammate_contracts.md`)  

**Exit criteria:** User sees story-style alerts, not raw flags. — **met** in the prototype (verified end to end:
SSH brute-force flow → simulated block, stealer event → simulated kill, both shown live with a linked detail page).

### Phase 7 — Expand NIDS classes — **DONE (v3)**
- PortScan added from lab nmap captures; DDoS/DoS lab overlays; MITRE map includes `T1046`, `T1498`, `T1499`  

### Phase 8 — Self-protection, false-positive handling, packaging — **DONE**
- Integrity manifest, API token, HMAC evidence chain, heartbeat watchdog, tamper sensor, unclean-shutdown
  detection with Windows-shutdown attribution  
- Program trust (code-signing reputation + user allow rules) and real "Stop this program now"  
- Electron desktop app (simple/expert modes, tray, admin elevation), PyInstaller engine, NSIS installer  
- Docs: `System_Architecture.md`, `Methodology_and_Algorithms.md`, `Evaluation_and_Results.md`

---

## 7. How to test that predictions are right (lab doctrine)

You **never** judge the model on random public Wi‑Fi first. You generate labelled traffic.

| Step | Action | Success signal |
|------|--------|----------------|
| 1 | Host-only lab: Windows + Kali | Ping visible in sniffer |
| 2 | Benign: browse / download on Windows | Mostly Benign |
| 3 | Attack **own** VM/service: Hydra SSH/FTP, Nmap | Expected class (or known gap if class not in model yet) |
| 4 | Packets → flows → **77 features** | Row shape `(1, 77)` matches `feature_columns_v2.pkl` |
| 5 | `predict` + `predict_proba` | Label + confidence |
| 6 | Scorecard | Confusion table: Actual (what you ran) vs Predicted |

**Current model truth table (honest):**

| You generate | Model can output today |
|--------------|-------------------------|
| Web / ping / most benign | Benign |
| SSH Hydra | SSH-Bruteforce (hybrid helps if DoS/SSH ambiguous on port 22) |
| FTP Hydra | FTP-BruteForce (hybrid helps if DoS/FTP ambiguous on port 21) |
| DoS / DDoS lab floods | DoS / DDoS (trained in v2; live feature quality may still drift) |
| Botnet-like C2 (if lab matches training) | Botnet |
| Nmap / Port Scan | PortScan (v3 lab class) and the live fan-out rule (≥ 15 ports from one source in 20 s) |

Keep a simple CSV: `timestamp, scenario, expected, predicted, confidence, notes`.

---

## 8. Original gameplan (September 2026, kept for history)

Superseded by section 13 now that HIDS and the dashboard prototype exist.

### Week A — Integration + honesty in demos — **DONE**
1. Feature contract + v2 artefacts documented (`ML_Package_v2.md`).  
2. Mapper + Detection Agent → real `models/*_v2.pkl`.  
3. Offline CSV through SOAR (`demo_real_model.py`).  
4. Supervisor wording: **CSE-CIC-IDS2018** multiclass; 77 features without `Dst Port`; hybrid deploy policy.

### Week B — Lab plumbing — **NEXT**
1. VirtualBox + Kali OVA; host-only adapter; note IPs.  
2. OpenSSH (and/or FTP) **on a disposable lab VM**, not production.  
3. Scapy sniff proof: Kali `ping` → Windows prints packets.  
4. Choose exporter path: CICFlowMeter **or** reduced feature set + retrain (decide explicitly). Do **not** break the v2 freeze unless you choose retrain.

### Week C — First live scorecard
1. Feature extractor MVP (even partial columns: document gaps).  
2. 20+ labelled trials (benign + SSH; FTP / DoS if ready).  
3. One page results for supervisor: live accuracy ≠ CIC offline accuracy.  
4. Only then: dry-run firewall on high-confidence SSH hits.

### Parallel (light)
- Sketch HIDS feature list (process name, signed/unsigned, path category, outbound count).  
- No full stealer simulation until NIDS live path exists.

---

## 9. Team split (matches repo + new vision)

| Member | Owns | Near-term deliverable |
|--------|------|------------------------|
| **1 — AIML** | `ml/`, `models/`, HIDS model, live eval scorecard | Paper: dataset analysis, v3 + HIDS results (Evaluation V-A to V-D) |
| **2 — Capture / security** | `nids/` capture + extractor, lab attacks, `hids/` sensors | Paper: lab setup, feature bridge, held-out lab results (V-C) |
| **3 — SOAR** | `soar/`, self-protection, trust | Paper: architecture, risk/OOD/trust/self-protection methodology |
| **4 — Dashboard** | `dashboard/`, packaging | Paper: deployment, UI figures, system measurements (V-E) |

---

## 10. Tech checklist (from the plan — prioritized)

**Now:** Python, joblib, XGBoost, pandas, scikit-learn, PyYAML, SQLite (existing), Scapy  
**Soon:** psutil, watchdog, netsh (dry-run), FastAPI/WebSocket polish  
**Later:** React, Recharts, Tailwind  

Skip buying commercial IDS. Stay in isolated VMs for attacks.

---

## 11. 45-second pitch (corrected)

> SentinelAI is a hybrid AI defence platform for Windows, shipped as one installer. Its network side classifies live traffic into seven classes (Benign, Botnet, DDoS, DoS, FTP and SSH brute force, port scan) with an XGBoost model trained on CSE-CIC-IDS2018 plus our own attack-lab captures, without the destination-port shortcut, and a runtime policy that catches attacks the model is over-confident about. Its host side spots password-stealing programs with an anomaly model and audited access to browser credential files, while code-signing reputation keeps trusted software from being flagged. Eleven agents map each event to MITRE ATT&CK, score risk, block or stop the threat (test mode by default), explain it in plain language and record it in a tamper-evident log. Goal: detect on both network and host, explain, and respond, for people without a security team.

---

## 12. Definition of done (project)

Minimum shippable Capstone story:

1. Live or lab-captured **NIDS** path with documented feature bridge and scorecard.  
2. Multi-agent **SOAR** on those detections (alert + log + report; firewall at least dry-run).  
3. **HIDS** MVP with at least one behavioural scenario (e.g. sensitive browser DB access pattern) and MITRE tag (e.g. T1539).  
4. Dashboard **or** strong CLI/API demo if UI slips — prefer thin React if time allows.  
5. Clear limitations: not all CVEs, not encrypted payload inspection, live accuracy ≠ CIC CSV scores.

---

All five items above are met (item 4 with the full desktop app).

---

## 13. What to do next (research paper phase)

1. Write the paper from `docs/Research_Paper_Guide.md`; fill the 📝 result tables in
   `docs/Evaluation_and_Results.md` on the machine that holds `data/lab/` and the HIDS run logs.  
2. Optional research extension: host + network correlation into one incident (Phase 6, item 1).  
3. Keep the installer and the end-to-end demo working for the viva.

---

*This blueprint is the source of truth for sequencing. Update it when a phase’s exit criteria are met.*
