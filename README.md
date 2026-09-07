# SentinelAI — Hybrid NIDS + HIDS + Multi-Agent SOAR

CSE-CIC-**IDS2018**-style network detection (XGBoost, 77 flow features, no `Dst Port`)
plus a multi-agent SOAR pipeline, with HIDS and dashboard stubs for later phases.

## Layout

```text
Capstone/
├── config/           # Shared paths (models, data, packages)
├── data/             # Local datasets only (gitignored)
├── docs/             # Reports, feature contract, gameplan
├── ml/               # Offline EDA / train / experiments
├── models/           # sentinel_xgb.pkl, label_encoder.pkl, feature_columns.pkl
├── nids/             # Live capture + feature bridge + predict
├── hids/             # Host monitoring stubs (Phase 5)
├── soar/             # Multi-agent SOAR (Detection → Response → Report)
├── dashboard/        # React UI placeholder (Phase 6)
└── README.md
```

## Quick start

```powershell
cd c:\Capstone
pip install -r requirements.txt
pip install -r soar\requirements.txt

# Phase-1 model on one CSV row
python -m nids.live_predict --row 0

# Real model through full SOAR pipeline
python soar\demo_real_model.py

# Agent golden demo (heuristics if CSV rows not attached)
cd soar
python demo_runner.py
```

## Dataset citation

Working flow CSV matches **CSE-CIC-IDS2018** brute-force style labels
(`Benign`, `FTP-BruteForce`, `SSH-Bruteforce`), not CICIDS2017 Patator names.

## Integration rule

`nids/` and `hids/` emit evidence. **`soar/` owns response** (risk, firewall dry-run, alerts, SQLite, PDF).

See `docs/Project_Gameplan_Blueprint.md` for the full roadmap.
