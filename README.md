# SentinelAI — Hybrid NIDS + HIDS + Multi-Agent SOAR

Windows defence platform that detects **network attacks** (XGBoost on CSE-CIC-**IDS2018**-style flow features)
and **host infostealer behaviour** (Isolation Forest on process + credential-file activity), then orchestrates a
response through a multi-agent SOAR pipeline and shows it live in a Windows desktop app.

**Status:** working end-to-end prototype. Sensors → SOAR → SQLite → FastAPI/WebSocket → desktop app, with firewall
blocks and process kills in **test mode (dry-run)** by default.

**ML packages:** active NIDS model is **v3** (CIC + lab merge, 7 classes incl. `PortScan`) — see `docs/ML_Package_v3.md`.
The CIC-only **v2** package stays on disk as rollback (`docs/ML_Package_v2.md`).

## Layout

```text
Capstone/
├── config/           # Shared paths (single source of truth: config/paths.py, points at v3)
├── data/             # Local datasets only (gitignored)
├── docs/             # Reports, feature contract, gameplan, ML package notes
├── ml/               # Offline dataset building / train / eval  (+ tests/)
├── models/           # XGBoost v2/v3 artefacts + HIDS Isolation Forest
├── nids/             # Live capture + feature bridge + predict  (+ tests/)
├── hids/             # Host sensors, Isolation Forest scoring, SOAR bridge (+ tests/)
│   └── dataset/      # Stealer simulator, feature engineering, dataset builder, training
├── soar/             # Multi-agent SOAR + FastAPI backend  (+ tests/)
├── dashboard/        # SentinelAI desktop app (Electron + React + Vite, live via WebSocket)
├── requirements.txt  # Single Python dependency list for the whole project
└── README.md
```

## Quick start

Python 3.11+ (tested on 3.14) and Node.js 20+.

```powershell
# 1. Python environment (repo root)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt          # one list covers NIDS, ML, SOAR (incl. FastAPI/uvicorn), HIDS

# 2. Desktop app (starts the backend API on http://127.0.0.1:8000 by itself)
cd dashboard
npm install
npm run desktop                          # or: npm run desktop:dev  (hot reload)
```

To run the backend on its own instead: `cd soar; python main.py server` (Swagger: `/docs`). The desktop app connects
to it if it's already running. See `dashboard/README.md` for the browser dev server and building the installer.

Turn on **Expert** mode in the app's top bar to get the **Demo Panel**, which sends a sample network attack
or host stealer event through the real pipeline.

### Other entry points

```powershell
# Active model on one CSV row
python -m nids.live_predict --row 0

# Real model through full SOAR pipeline (CLI)
python soar\demo_real_model.py

# Agent golden demo / synthetic stream (from soar/)
python main.py demo
python main.py simulate --dry-run

# HIDS: score a finished run, or run the sensors into SOAR (dry-run, no process kill)
python -m hids.predict
python -m hids.live --duration 600
```

## Tests

```powershell
python -m pytest nids/tests ml/tests hids/tests soar/tests -q

cd dashboard
npm run build                            # type-check (tsc -b) + production build
```

## Dataset citation

Network flow CSVs follow **CSE-CIC-IDS2018** multiclass labels
(`Benign`, `Botnet`, `DDoS`, `DoS`, `FTP-BruteForce`, `SSH-Bruteforce`); v3 adds a lab `PortScan` class.

## Integration rule

`nids/` and `hids/` emit evidence. **`soar/` owns response** (risk, firewall, process kill, alerts, SQLite, PDF).
`dashboard/` only talks to the SOAR API (`soar/contracts/teammate_contracts.md`).

See `docs/Project_Gameplan_Blueprint.md` for the roadmap.
