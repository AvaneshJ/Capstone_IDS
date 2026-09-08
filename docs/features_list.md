# SentinelAI — Model Feature Contract (77 columns)

**Source:** `models/feature_columns_v2.pkl`
**Model:** XGBoost (`models/sentinel_xgb_v2.pkl`), trained **without** `Dst Port`
**Order matters:** inference must supply values in this exact index order.

This list is the Phase 1 → live pipeline contract. Any flow exporter output must be mapped into these names (or documented as missing).

---

## Summary

| Item | Value |
|------|------:|
| Feature count | 77 |
| Excluded from model | `Dst Port`, `Label`, `Timestamp` |
| Classes | Benign, FTP-BruteForce, SSH-Bruteforce |

---

## Full list (index → name)

| Index | Feature name |
|------:|--------------|
| 0 | Protocol |
| 1 | Flow Duration |
| 2 | Tot Fwd Pkts |
| 3 | Tot Bwd Pkts |
| 4 | TotLen Fwd Pkts |
| 5 | TotLen Bwd Pkts |
| 6 | Fwd Pkt Len Max |
| 7 | Fwd Pkt Len Min |
| 8 | Fwd Pkt Len Mean |
| 9 | Fwd Pkt Len Std |
| 10 | Bwd Pkt Len Max |
| 11 | Bwd Pkt Len Min |
| 12 | Bwd Pkt Len Mean |
| 13 | Bwd Pkt Len Std |
| 14 | Flow Byts/s |
| 15 | Flow Pkts/s |
| 16 | Flow IAT Mean |
| 17 | Flow IAT Std |
| 18 | Flow IAT Max |
| 19 | Flow IAT Min |
| 20 | Fwd IAT Tot |
| 21 | Fwd IAT Mean |
| 22 | Fwd IAT Std |
| 23 | Fwd IAT Max |
| 24 | Fwd IAT Min |
| 25 | Bwd IAT Tot |
| 26 | Bwd IAT Mean |
| 27 | Bwd IAT Std |
| 28 | Bwd IAT Max |
| 29 | Bwd IAT Min |
| 30 | Fwd PSH Flags |
| 31 | Bwd PSH Flags |
| 32 | Fwd URG Flags |
| 33 | Bwd URG Flags |
| 34 | Fwd Header Len |
| 35 | Bwd Header Len |
| 36 | Fwd Pkts/s |
| 37 | Bwd Pkts/s |
| 38 | Pkt Len Min |
| 39 | Pkt Len Max |
| 40 | Pkt Len Mean |
| 41 | Pkt Len Std |
| 42 | Pkt Len Var |
| 43 | FIN Flag Cnt |
| 44 | SYN Flag Cnt |
| 45 | RST Flag Cnt |
| 46 | PSH Flag Cnt |
| 47 | ACK Flag Cnt |
| 48 | URG Flag Cnt |
| 49 | CWE Flag Count |
| 50 | ECE Flag Cnt |
| 51 | Down/Up Ratio |
| 52 | Pkt Size Avg |
| 53 | Fwd Seg Size Avg |
| 54 | Bwd Seg Size Avg |
| 55 | Fwd Byts/b Avg |
| 56 | Fwd Pkts/b Avg |
| 57 | Fwd Blk Rate Avg |
| 58 | Bwd Byts/b Avg |
| 59 | Bwd Pkts/b Avg |
| 60 | Bwd Blk Rate Avg |
| 61 | Subflow Fwd Pkts |
| 62 | Subflow Fwd Byts |
| 63 | Subflow Bwd Pkts |
| 64 | Subflow Bwd Byts |
| 65 | Init Fwd Win Byts |
| 66 | Init Bwd Win Byts |
| 67 | Fwd Act Data Pkts |
| 68 | Fwd Seg Size Min |
| 69 | Active Mean |
| 70 | Active Std |
| 71 | Active Max |
| 72 | Active Min |
| 73 | Idle Mean |
| 74 | Idle Std |
| 75 | Idle Max |
| 76 | Idle Min |

---

## Grouped by theme (for mapping / learning)

### Protocol and duration
- `Protocol`
- `Flow Duration`

### Packet and byte counts; directional packet-length stats
- `Tot Fwd Pkts`, `Tot Bwd Pkts`
- `TotLen Fwd Pkts`, `TotLen Bwd Pkts`
- `Fwd Pkt Len Max/Min/Mean/Std`
- `Bwd Pkt Len Max/Min/Mean/Std`

### Flow rates
- `Flow Byts/s`, `Flow Pkts/s`
- `Fwd Pkts/s`, `Bwd Pkts/s`

### Inter-arrival times (IAT)
- `Flow IAT Mean/Std/Max/Min`
- `Fwd IAT Tot/Mean/Std/Max/Min`
- `Bwd IAT Tot/Mean/Std/Max/Min`

### Flags and headers
- `Fwd PSH Flags`, `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`
- `Fwd Header Len`, `Bwd Header Len`
- `FIN/SYN/RST/PSH/ACK/URG Flag Cnt`, `CWE Flag Count`, `ECE Flag Cnt`

### Overall packet length and size averages
- `Pkt Len Min/Max/Mean/Std/Var`
- `Down/Up Ratio`, `Pkt Size Avg`
- `Fwd Seg Size Avg`, `Bwd Seg Size Avg`

### Bulk / subflow / window
- `Fwd/Bwd Byts/b Avg`, `Fwd/Bwd Pkts/b Avg`, `Fwd/Bwd Blk Rate Avg`
- `Subflow Fwd/Bwd Pkts`, `Subflow Fwd/Bwd Byts`
- `Init Fwd Win Byts`, `Init Bwd Win Byts`
- `Fwd Act Data Pkts`, `Fwd Seg Size Min`

### Active / idle periods
- `Active Mean/Std/Max/Min`
- `Idle Mean/Std/Max/Min`

---

## Reload the canonical list in code

```python
import joblib
cols = joblib.load("models/feature_columns_v2.pkl")  # run from Capstone root
assert len(cols) == 77
```

If this markdown and the pickle ever disagree, **trust the pickle** and update this file.

---

*Reference for Phase 2 feature bridge / live inference.*
