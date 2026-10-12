# SentinelAI — Supervisor Presentation Script

**Length:** about 15 minutes of talking + 5 minutes of live demo + questions.
**How to use:** the plain text is what you say. Lines starting with **[SHOW]** are what to put on screen.
**[DO]** lines are actions during the demo.

---

## 0. Before the meeting (10 minutes earlier)

Open two PowerShell windows at the repo root.

```powershell
# Window 1 — backend
.\.venv\Scripts\Activate.ps1
cd soar
python main.py server            # wait for "Uvicorn running on http://127.0.0.1:8000"

# Window 2 — dashboard
cd dashboard
npm run dev                      # http://localhost:5173
```

Open in the browser, in tabs:

1. `http://localhost:5173` (dashboard, switch to **Expert** mode in the top bar)
2. `http://localhost:8000/docs` (Swagger API)
3. The repo in Cursor/VS Code with the folder tree visible

Backup if anything fails: set `VITE_USE_MOCKS=true` in `dashboard/.env.local` and restart `npm run dev` — the
dashboard then runs on bundled sample data with no backend.

---

## 1. Opening — what the project is (1 min)

> "Good morning. Our project is **SentinelAI**, a hybrid AI security platform for Windows.
> It does three things:
>
> 1. **Detects network attacks** — a Network Intrusion Detection System (NIDS) using an XGBoost model on network
>    flow features.
> 2. **Detects malicious behaviour on the computer itself** — a Host Intrusion Detection System (HIDS) that watches
>    processes and browser credential files, to catch infostealer malware, using an Isolation Forest model.
> 3. **Responds automatically** — a multi-agent SOAR layer (Security Orchestration, Automation and Response) that
>    explains the attack, scores the risk, decides what to do, blocks the IP or kills the process, logs everything,
>    and generates PDF reports.
>
> Everything is shown live on a React dashboard written for non-technical users.
>
> Current status: it is a **working end-to-end prototype**. Sensors feed the SOAR pipeline, the SOAR pipeline stores
> incidents in a database and pushes them to the dashboard live. For safety, blocking and process killing run in
> **test mode (dry-run)** by default."

---

## 2. The architecture in one picture (2 min)

**[SHOW]** draw or display this:

```text
   NETWORK                                   HOST (Windows PC)
   ───────                                   ─────────────────
   Traffic / lab CSV flows                   Process sensor + credential-file sensor
          │                                            │
   nids/feature_extractor.py                 hids/predict.py (Isolation Forest)
   (77 CIC flow features)                    hids/live.py (HostBridge)
          │                                            │
          └──────────────────┬─────────────────────────┘
                             ▼
                 soar/  — Multi-agent SOAR pipeline
   Packet → Detection (XGBoost v3) → Threat (MITRE) → Risk (1–10)
          → Decision (policies.yaml) → Firewall / Process kill → Alert
          → Logging (SQLite) → Report (PDF) + LLM plain-English briefing
                             │
                 soar/api/server.py  (FastAPI REST + WebSocket)
                             │
                 dashboard/  (React, live alerts)
```

> "One important design rule: the sensors — `nids/` and `hids/` — only **produce evidence**. They never block or
> kill anything themselves. **Only the SOAR layer owns the response.** The dashboard only talks to the SOAR API.
> That gave us clean contracts between team members, written down in `soar/contracts/teammate_contracts.md`."

---

## 3. Where everything is in the repo (1 min)

**[SHOW]** the folder tree.

| Folder | What is in it |
|--------|---------------|
| `ml/` | Offline dataset building, model training and evaluation scripts |
| `models/` | Trained models: XGBoost v2 (rollback) and v3 (active), HIDS Isolation Forest |
| `config/paths.py` | Single place that says which model files are active (points to v3) |
| `nids/` | Network side: packet capture (Scapy), feature extractor to the 77 CIC columns, prediction |
| `hids/` | Host side: process sensor, file sensor, Isolation Forest scoring, bridge to SOAR |
| `hids/dataset/` | Safe stealer simulator, feature engineering, dataset builder, model training |
| `soar/` | The multi-agent brain: agents, orchestrator, policies, SQLite database, FastAPI server |
| `dashboard/` | React + TypeScript SOC dashboard |
| `docs/` | Progress report, ML package notes, feature list, project blueprint |

> "Each folder has its own README, and there are unit tests for NIDS, ML, HIDS and SOAR — 224 tests in total."

---

## 4. Part A — Network detection (NIDS) (3 min)

### 4.1 Dataset and the honest story

> "We used **CSE-CIC-IDS2018**, a standard intrusion-detection benchmark of network flows. Each row is one network
> conversation described by about 80 statistics — packet counts, sizes, timings, TCP flags, rates.
>
> In Phase 1 we started with 3 classes: Benign, FTP brute force and SSH brute force — about one million rows.
> We compared Decision Tree, Random Forest and XGBoost. All of them scored above 99.99%, which looked suspicious,
> so we investigated."

> "We found two problems:
>
> 1. **Port leakage:** the destination port almost gives away the answer — port 21 means FTP attack, 22 means SSH.
>    A simple 'if port is 21 or 22, it's an attack' rule already scores 99.96%.
> 2. **Duplicate rows:** about 38% of test rows were exact copies of training rows, so part of the score was
>    memorisation.
>
> So we ran three experiments: we **removed the destination port** from the model, we evaluated on **only unseen
> rows**, and we compared against the **port rule** as a baseline. Without the port, XGBoost still had zero false
> alarms, while the port rule had 75. That proved the model is learning traffic behaviour, not just the port number.
> That is why we chose **XGBoost with 77 features and no destination port**."

**[SHOW]** `docs/Phase1_Progress_Report.md`, section 8.2 (the comparison table).

### 4.2 Model versions

> "We then improved it in two steps:
>
> - **v2:** 6 classes — Benign, Botnet, DDoS, DoS, FTP brute force, SSH brute force. This is frozen as a rollback.
> - **v3 (active):** we generated our own attack traffic in a lab — Kali Linux attacking an Ubuntu machine — and
>   merged it with the CIC data. This adapts the model to modern traffic and adds a 7th class, **PortScan**
>   (nmap-style scans). One lab SSH attack file was kept completely out of training for an external check."

**[SHOW]** `docs/ML_Package_v3.md`.

### 4.3 Two safety layers on top of the model

> "Two extra rules run after the model, inside SOAR:
>
> 1. **Hybrid port override** (`soar/adapters/cic_xgb_adapter.py`): the model sometimes confuses DoS and FTP.
>    Only in that specific case, the port decides — 21 means FTP, 22 means SSH. We did not put the port back into
>    training, so there's no leakage.
> 2. **Out-of-distribution policy** (`soar/rules/ood_policy.py`): if the model says Benign, but the flow looks
>    unusual for live traffic — hitting login ports, SYN bursts, odd TCP window sizes — the system escalates it.
>    The original model answer is kept for transparency."

### 4.4 Live side

> "`nids/capture.py` sniffs packets with Scapy, and `nids/feature_extractor.py` converts flows into exactly the 77
> columns in the order the model was trained on. `soar/lab_csv_to_soar.py` replays our lab-captured flows through
> the full pipeline, and the API has `/api/flows/ingest` so a live capture can post flows directly."

---

## 5. Part B — Host detection (HIDS) (3 min)

> "The second half protects the computer itself against **infostealer malware** — programs that copy your saved
> browser passwords and cookies."

### 5.1 Two sensors

> "- **Process sensor** (`hids/process_monitor.py`): records every process's start, resource usage and exit —
>   where it ran from, its parent, its command line, how long it lived.
> - **File sensor** (`hids/file_monitor.py`): watches the exact files stealers go after — Chrome/Edge/Brave/Opera
>   `Login Data` and `Cookies`, Firefox `logins.json` and `key4.db`, even Bitcoin `wallet.dat` — for every
>   browser profile of the current user.
>
> A key detail: stealers **read** these files, they don't modify them. Normal file watching only sees changes, so
> we use **Windows security auditing** (event 4663) in admin mode, which tells us exactly *which process* read the
> file. We also check if the reader is the browser itself from its real install folder — a `chrome.exe` running
> from the Temp folder is flagged."

### 5.2 Dataset and model

> "We can't use real malware, so we wrote a **safe stealer simulator** (`hids/dataset/stealer_simulator.py`). It
> behaves like a real stealer — runs disguised from the Temp folder and copies the credential files — then shreds
> the copies. **Nothing ever leaves the machine.** Every run is recorded in a manifest, so labels are exact, not
> guessed.
>
> We collected normal activity on our own PCs, built one row per process run, and trained an **Isolation Forest**
> — an anomaly detector trained only on normal behaviour, so it can flag behaviour it has never seen before. On our
> current sample it detected all simulated stealer runs at about 1% false positives. The sample is small, so we
> treat that as a prototype result."

### 5.3 Why two paths into SOAR

> "Stealers often finish in a second. If we waited for the process to exit before scoring it, we'd be too late.
> So `hids/live.py` uses two paths: a suspicious credential-file read goes to SOAR **immediately**, and finished
> processes are scored by the Isolation Forest when they exit. The SOAR `HostAgent` maps it to MITRE techniques —
> **T1555.003** (credentials from browsers), **T1539** (steal session cookie) — and decides whether to kill the
> process, alert, or just log."

---

## 6. Part C — Multi-agent SOAR (3 min)

**[SHOW]** `soar/agents/` folder.

> "Instead of one big script, response is split into specialised **agents** that talk through an **event bus**
> (`soar/core/event_bus.py`), coordinated by `soar/core/orchestrator.py`."

| Agent | Job |
|-------|-----|
| PacketAgent | Cleans and validates incoming flows |
| DetectionAgent | Runs XGBoost v3 + port override + OOD policy |
| ThreatAgent | Explains the evidence and maps to MITRE ATT&CK (e.g. T1046 port scan, T1110 brute force) |
| RiskAgent | Scores risk 1–10 |
| DecisionAgent | Applies the rules in `rules/policies.yaml` (thresholds, whitelist, cooldowns) |
| FirewallAgent | Blocks the IP with Windows `netsh` (dry-run by default), auto-unblocks after the ban |
| HostAgent | HIDS events: classify, MITRE map, risk, terminate process (dry-run by default) |
| AlertAgent | Dashboard notification, desktop toast, optional Telegram |
| LoggingAgent | Saves everything in SQLite (`soar/database/sentinel.db`) |
| ReportAgent | Generates PDF incident and summary reports |
| LLMAgent | Plain-English briefing — Gemini, local Ollama, or an offline expert system if no API |

### Risk formula

> "Risk = (attack weight × model confidence) + velocity bonus + target sensitivity.
>
> - Attack weight: DDoS/Botnet 9, DoS 8, brute force 7, port scan 5, benign 0.
> - Velocity: how many events from the same IP in the last 60 seconds — up to +2.5.
> - Sensitivity: database or admin ports like 3306, 22, 3389 add +1.5.
>
> Critical (8.5+) means block 24 hours, High means 30 minutes, Medium 15 minutes, Low just goes on a watchlist."

### Why multi-agent

> "Three reasons: **fault isolation** — if the LLM or Telegram fails, blocking and logging still work;
> **configurable** — rules live in a YAML file, no retraining needed; and **parallel teamwork** — each member could
> build and test their part against a written contract."

---

## 7. Part D — Backend API and dashboard (1 min)

> "`soar/api/server.py` is a FastAPI server with REST endpoints — incidents, host incidents, blocked IPs, metrics,
> reports — and a **WebSocket** `/ws/live-stream` that pushes new alerts instantly."

**[SHOW]** Swagger at `http://localhost:8000/docs`.

> "The dashboard (`dashboard/`) is React + TypeScript. It has two modes: **Simple** — plain-language stories for a
> normal user, no jargon — and **Expert** — full technical details, model probabilities, and a Demo panel."

Pages: Home (overall status + KPIs), Activity (all alerts), Alert detail (story + risk gauge + actions taken),
Blocked connections (with manual unblock), Computer protection (host alerts), Reports (PDF), System health, Learn.

---

## 8. Live demo (5 min)

**[DO]** Dashboard **Home** page.
> "This is the home screen. It shows overall status and the 'Live' indicator — that means the WebSocket to the
> backend is connected."

**[DO]** Go to **Demo** (Expert mode) → send the **network attack** sample (SSH brute force).
> "I'm sending an SSH brute-force flow through the **real** pipeline — the real XGBoost model, real agents."

**[DO]** Point at the pop-up toast and bell → click it → **Alert detail** page.
> "The alert popped up live. Here's the story in plain language, the risk score, the MITRE technique, and the
> action: the IP was blocked — marked **Simulated** because we're in test mode."

**[DO]** Open **Blocked connections**.
> "The firewall rule is listed here, and I can unblock it manually."

**[DO]** Back to **Demo** → send the **host stealer** sample → open **Computer protection**.
> "Now a host event: an unknown program from the Temp folder reading Chrome's password database. SOAR maps it to
> T1555.003 and decides to terminate the process — again simulated."

**[DO]** **Reports** → Generate PDF → open it.
> "Every incident is logged in SQLite and can be exported as a PDF report."

**Optional CLI demos** (if asked, from repo root):

```powershell
python soar\demo_real_model.py            # real model on CSV rows through full SOAR, printed in terminal
cd soar; python main.py demo              # scripted 6-stage golden demo
python -m pytest nids/tests ml/tests hids/tests soar/tests -q
```

---

## 9. Honest limitations (1 min) — say these yourself before you're asked

> "We want to be clear about what's not done yet:
>
> 1. **Offline accuracy is not live accuracy.** CIC scores are very high, but real campus traffic will be lower. Our
>    next step is a live scorecard: what we ran vs what the model said.
> 2. **Host + network correlation** — joining a stealer on the PC with its outbound connection into one incident —
>    is not started.
> 3. **Test mode:** real `netsh` blocking and automatic process killing are implemented but off by default for
>    safety. The user can still really stop a flagged program from its alert.
> 4. **HIDS dataset is small** and built from a simulator, so its numbers are a prototype result.
> 5. **No kernel-level self-defence.** An administrator can stop SentinelAI; we detect and record that, but cannot
>    prevent it without signed drivers.
> 6. We don't decrypt HTTPS — detection uses flow metadata only — and we don't claim to detect every attack type."

---

## 10. Next steps (30 sec)

> "1. Write the research paper (`docs/Research_Paper_Guide.md`) with the held-out lab and HIDS results.
> 2. Correlate host and network events into one incident.
> 3. Grow the HIDS dataset on more machines.
> 4. Decide with you when it is safe to switch from test mode to real blocking."

---

## 11. Likely supervisor questions — short answers

**Q: Why XGBoost and not deep learning?**
Tabular flow statistics — tree models are state of the art there, fast, need no scaling, and give feature
importance. We chose it from experiments (Phase 1 comparison with Decision Tree and Random Forest), not popularity.

**Q: 99.99% accuracy — isn't that overfitting?**
We investigated exactly that. We found port leakage and duplicate rows, removed the port, tested on unseen rows,
and compared against a port rule. The real win is far fewer false alarms than the rule, not the headline number.

**Q: Why Isolation Forest for HIDS?**
Malware samples are rare and change constantly. Isolation Forest trains only on normal behaviour and flags
anything unusual, so it can catch a stealer it has never seen.

**Q: How do you know the HIDS labels are correct?**
Every simulator run records its exact process ID and start time in a manifest. A row is labelled Stealer only if
that exact key matches — no guessing by process name.

**Q: Is it safe? Could it kill the wrong process or block the wrong IP?**
Test mode is on by default for both. There's a whitelist and cooldowns in `policies.yaml`, the browser's own
legitimate access is recognised, and blocks auto-expire.

**Q: What about false alarms from legitimate software (e.g. an antivirus reading browser files)?**
That happened with McAfee. Programs with a valid code-signing certificate installed in Program Files are now
reported once a day at LOW and never stopped. The user can also trust a program by file fingerprint or publisher,
like Defender or CrowdStrike allow-lists. Script hosts such as PowerShell and Python are never trusted, because
attackers use them too.

**Q: Can an attacker just switch SentinelAI off or delete the evidence?**
They can stop it with admin rights, but it is detected: heartbeats, a run marker that tells a kill apart from a
Windows shutdown, and a tamper sensor for log clearing and kill commands. Every incident is in an HMAC hash chain
with an anchor outside the database, so edits or deletions show up.

**Q: What does the LLM do, and what if there's no internet?**
It writes a plain-English explanation and remediation steps. It tries Gemini, then local Ollama, then falls back
to a built-in rule-based expert system, so it always works offline.

**Q: What is MITRE ATT&CK?**
A global catalogue of attacker techniques. Tagging each alert (e.g. T1110 brute force, T1539 cookie theft) makes
alerts comparable to industry SOC tools.

**Q: Why CIC-IDS2018 and not your own data only?**
It's a standard benchmark, so results are comparable. We added our own lab traffic in v3 to adapt it to modern
traffic and add PortScan.

**Q: Who did what?**
(Fill in per member: AIML + models, network capture + lab attacks, SOAR + backend, dashboard. Mention the sensor
and simulator contributors from the HIDS work.)

---

## 12. 30-second closing

> "To summarise: SentinelAI detects attacks on both the network and the host, explains them in plain language with
> MITRE mapping, and responds automatically through a multi-agent SOAR pipeline — all visible live on a dashboard.
> It runs on live traffic today, protects itself against tampering, and ships as a single Windows installer, in safe
> test mode by default. Thank you — happy to take questions."
