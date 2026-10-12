# SentinelAI — NIDS ML Package v3 (CIC + Lab merge)

**Status date:** September 2026  
**Status:** **ACTIVE** for live lab + SOAR. v2 CIC-only artefacts remain on disk (`*_v2.pkl`) as rollback.

v3 is a **domain-adapted** retrain: stratified CIC multiclass sample **plus** cleaned Kali→Ubuntu lab overlays — not a lab-only overwrite.

---

## Canonical artefacts

| File | Role |
|------|------|
| `models/sentinel_xgb_v3.pkl` | Merged multiclass XGBoost |
| `models/label_encoder_v3.pkl` | Class id ↔ label name |
| `models/feature_columns_v3.pkl` | Ordered **77** CIC feature names (same contract as v2) |

`config/paths.py` points the live stack at **v3**.  
SOAR loads via `soar/adapters/cic_xgb_adapter.py`.

---

## Classes (v3)

| Label | Source |
|-------|--------|
| Benign | CIC (primary) + tiny cleaned lab non-SSH |
| Botnet | CIC only |
| DDoS | CIC + capped lab flood overlay |
| DoS | CIC + capped lab flood overlay |
| FTP-BruteForce | CIC + replicated lab FTP |
| SSH-Bruteforce | CIC + replicated lab SSH |
| PortScan | Lab nmap-style overlay |

**Held out of training:** `data/lab/ssh_attacks.csv` (external lab check).

---

## Merge safeguards

- CIC subsampled per class (see `ml/build_merged_dataset.py` `CIC_CAPS`) so training stays tractable without discarding class coverage.
- Lab DoS/DDoS hard-capped; SSH/FTP replicated so modern init-window regime is learned.
- Lab Benign drops dst:22 and multicast/noise (avoids teaching SSH = Benign).
- Feature contract unchanged: **77 cols, no `Dst Port` in X**; hybrid port override still in adapter.

---

## Build / train / eval

```powershell
cd c:\Capstone
python ml\build_merged_dataset.py
python ml\train_xgb_v3.py
python ml\eval_v3_dual.py
python soar\demo_real_model.py
```

Dataset: `data/processed/cic_lab_merged_clean.csv`

---

## Paper / results

Hyper-parameters, merge settings and the evaluation protocol are written up in
`docs/Methodology_and_Algorithms.md` (section A) and `docs/Evaluation_and_Results.md` (V-B, V-C). Paste the
output of `train_xgb_v3.py` and `eval_v3_dual.py` into those tables.

---

## Rollback

Point `config/paths.py` back to `*_v2.pkl` if needed. Do not delete v2 artefacts.

---

*Update this file when intentionally changing the active package.*
