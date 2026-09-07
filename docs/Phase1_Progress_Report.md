# SentinelAI — Phase 1 Progress Report

**Project:** SentinelAI — Machine Learning based Network Intrusion Detection System  
**Programme:** BTech Computer Science & Engineering (Final Year)  
**Period covered:** Dataset study, EDA, preprocessing, baseline ML, robustness checks, model save  
**Date:** August 2026  
**Status:** Phase 1 (data + supervised baseline) complete. Live packet capture is **not** started.

This document records **what has actually been implemented and measured**. Planned components (dashboard, response engine, HIDS, live capture) are listed only as future work.

---

## 1. Project aim (current scope)

SentinelAI is intended to become a practical IDS that:

1. Monitors network traffic (NIDS first; HIDS later if time allows).
2. Detects suspicious flows using machine learning.
3. Classifies known attack types present in the training data.
4. Reports a class label and confidence for later alerts.

**What we do not claim:** detection of every cyberattack, decryption of HTTPS payloads, detection of stolen session cookies, or live-network performance equal to offline CSV scores.

The first working slice is a **3-class supervised classifier** on flow metadata:

| Class | Meaning |
|-------|---------|
| Benign | Normal traffic |
| FTP-BruteForce | Repeated FTP login-style behaviour |
| SSH-Bruteforce | Repeated SSH login-style behaviour |

Detection uses **flow-level features** (counts, sizes, timing, flags, rates), not packet payloads. Encrypted traffic can still be analysed at this metadata level; contents of TLS payloads are not inspected.

---

## 2. Team and my responsibility

Four-member team. This report covers the **AIML + dataset + evaluation** work.

| Member | Role (agreed) |
|--------|----------------|
| Member 1 (this work) | AIML lead, dataset, EDA, models, evaluation |
| Member 2 | Detection/security research, rules, testing |
| Member 3 | Backend, pipeline, response (later) |
| Member 4 | Dashboard, alerts, integration (later) |

---

## 3. Dataset

### 3.1 Source used in this phase

Working files:

- Raw: `data/raw/cic.csv`
- Clean: `data/processed/cic_clean.csv`

Shape of the raw file: **1,048,575 rows × 80 columns**.  
Target column: **Label**.

**Labelling note for the report/viva:** column names are abbreviated (`Dst Port`, `Tot Fwd Pkts`, …) and class names are `FTP-BruteForce` / `SSH-Bruteforce`. That matches the **CSE-CIC-IDS2018** style (this capture is consistent with the 14 February 2018 brute-force day), **not** CICIDS2017 (`FTP-Patator` / `SSH-Patator` and full names such as `Destination Port`). The file should be cited as **CSE-CIC-IDS2018 (brute-force subset)** unless the original download page says otherwise.

This is a **lab-generated benchmark**, useful for a reproducible baseline. It is not modern internet traffic.

### 3.2 Original class distribution (`cic.csv`)

| Class | Count | Percentage |
|-------|------:|-----------:|
| Benign | 667,626 | 63.67% |
| FTP-BruteForce | 193,360 | 18.44% |
| SSH-Bruteforce | 187,589 | 17.89% |

### 3.3 Why this dataset is enough for Phase 1

We did **not** merge KDD99, DARPA, or Bot-IoT. Different datasets use different features and labels. The plan is: one clean baseline first, more attack days later if needed.

---

## 4. Exploratory data analysis (completed)

EDA (`ml/eda.py`) checked:

- Shape, column names, dtypes  
- Missing values  
- Infinite values  
- Duplicate rows  
- Class distribution  
- Statistical summary  

### 4.1 Infinite values

Rate features can become infinite when duration is zero (`bytes / 0`).

| Feature | Infinite count (raw) |
|---------|---------------------:|
| Flow Byts/s | 1,547 |
| Flow Pkts/s | 3,824 |

These caused pandas `RuntimeWarning` during statistics. **Correct handling:** replace `±inf` with NaN, then drop rows with NaN. That removes invalid rates; it does not rewrite valid flows.

Rows affected: **3,824 (0.3647%)**.

### 4.2 Duplicates — decision and reason

Raw duplicate rows: **225,628**.

Removing all duplicates **distorted** the class mix (FTP dropped far more than Benign). Repeated flows are also realistic for brute-force traffic.

**Decision: keep duplicates in the training dataset.**  
**Later evaluation change:** do **not** treat copies that appear in both train and test as “unseen” (see Section 8, Experiment B).

---

## 5. Preprocessing (completed)

Pipeline (`ml/preprocess.py`):

```text
cic.csv
  → replace ±inf with NaN
  → drop rows with NaN
  → drop Timestamp
  → save cic_clean.csv
```

Timestamp was removed because it is not a traffic-behaviour feature and can leak “when the attack was generated.”

Duplicates were **not** dropped.

### 5.1 Clean dataset

| Item | Value |
|------|------:|
| Original shape | 1,048,575 × 80 |
| Rows removed (NaN after inf) | 3,824 |
| After drop Timestamp | **1,044,751 × 79** |
| Remaining missing | 0 |
| Remaining inf | 0 |
| Features | 78 numeric + 1 Label |

### 5.2 Clean class distribution

| Class | Count | Percentage |
|-------|------:|-----------:|
| Benign | 663,808 | 63.54% |
| FTP-BruteForce | 193,354 | 18.51% |
| SSH-Bruteforce | 187,589 | 17.96% |

Preprocessing cleaned invalid rows without a large shift in class balance.

A class-distribution bar chart was produced (`ml/visualise.py`). The Y-axis is **percentage**, not raw counts.

---

## 6. Train / test split and encoding

- Features **X**, target **y** = `Label`  
- `LabelEncoder`: Benign → 0, FTP-BruteForce → 1, SSH-Bruteforce → 2  
- Split: **80% train / 20% test**, `stratify=y`, `random_state=42`  

| Set | Rows | Features (with port) |
|-----|-----:|---------------------:|
| Train | 835,800 | 78 |
| Test | 208,951 | 78 |

Train and test class percentages matched (~63.54% / 18.51% / 17.96%). Stratification worked.

Tree models (Decision Tree, Random Forest, XGBoost) were **not** standardised. Scaling is unnecessary for these algorithms.

---

## 7. Baseline models (with `Dst Port`)

Three models, same split, default hyperparameters, `random_state=42`:

1. Decision Tree  
2. Random Forest  
3. XGBoost  

**First results (full test set, 78 features including destination port):**

| Model | Accuracy | Errors / 208,951 | Attack → Benign | Benign → Attack | SSH → FTP |
|-------|----------|------------------|-----------------|-----------------|-----------|
| Decision Tree | 0.999952 | 10 | 0 | 0 | 10 |
| Random Forest | 0.999947 | 11 | 0 | 1 | 10 |
| XGBoost | 0.999952 | 10 | 0 | 0 | 10 |

These numbers look extremely high. They are **not** sufficient proof of a real IDS. Two dataset issues were then measured (Section 8).

---

## 8. Robustness experiments A–C

### 8.1 Why extra experiments were required

**Port–label alignment (almost a lookup table):**

| Dst Port | Benign | FTP-BruteForce | SSH-Bruteforce |
|---------:|-------:|---------------:|---------------:|
| 21 | 38 | **193,354** | 30 |
| 22 | 322 | 0 | **187,559** |
| Other | 663,448 | 0 | 0 |

A rule “21 → FTP, 22 → SSH, else Benign” already scores about **99.96%**. Legitimate SSH also uses port 22, so a model that only reads the port is not doing intrusion detection.

**Train/test copies:** with all features, **37.58%** of test rows also appeared in training. **Every FTP test row** was a copy of a training row. Perfect FTP recall on the official split is therefore partly memorisation.

Keeping duplicates for **training** remains valid. Scoring **identical** rows as held-out test data does not.

---

### Experiment A — train without `Dst Port`

`X` has **77** features. Same 80/20 split.

| Model | Accuracy | Errors | False alarms | Missed attacks | SSH → FTP |
|-------|----------|-------:|-------------:|---------------:|----------:|
| Decision Tree | 0.999947 | 11 | 1 | 0 | 10 |
| Random Forest | 0.999943 | 12 | 2 | 0 | 10 |
| XGBoost | **0.999952** | **10** | **0** | **0** | 10 |

**Finding:** removing destination port did **not** collapse accuracy. Other flow features already separate these three classes on this capture.

---

### Experiment B — unseen test (no row whose 77-feature vector appears in train)

Overlap after dropping port: **89,931 / 208,951 (43.0%)**.  
Unseen test size: **119,020**.

Unseen class counts:

| Class | Count |
|-------|------:|
| Benign | 100,202 |
| SSH-Bruteforce | 18,818 |
| FTP-BruteForce | **0** |

FTP cannot be evaluated on this unseen split. Macro-average F1 ≈ 0.67 is an artefact of support 0 for FTP and **must not** be quoted as model quality. Use per-class scores and weighted average.

| Model | Unseen accuracy | Unseen errors |
|-------|-----------------|---------------|
| Decision Tree | 0.999992 | 1 Benign → SSH |
| Random Forest | 0.999983 | 2 Benign → SSH |
| **XGBoost** | **1.000000** | **0** |

**Finding:** Benign vs SSH-Bruteforce generalises on unique flows without using port. Unseen FTP detection is **not demonstrated** on this file/split.

---

### Experiment C — port-rule baseline (no ML)

Rule: port 21 → FTP-BruteForce, port 22 → SSH-Bruteforce, else Benign.  
Same test rows as the models.

**Accuracy: 0.999593** (85 errors).

| Actual \ Predicted | Benign | FTP | SSH |
|--------------------|-------:|----:|----:|
| Benign | 132,687 | 7 | 68 |
| FTP-BruteForce | 0 | 38,671 | 0 |
| SSH-Bruteforce | 0 | 10 | 37,508 |

The port rule never labelled an attack as Benign here, but it produced **75 false alarms** (Benign traffic on ports 21/22).

---

### 8.2 Comparison that matters for the viva

On the **full test set**:

| Method | Accuracy | False alarms (Benign → attack) |
|--------|----------|-------------------------------:|
| Port rule (C) | 0.999593 | **75** |
| Random Forest (no port) | 0.999943 | 2 |
| Decision Tree (no port) | 0.999947 | 1 |
| **XGBoost (no port)** | **0.999952** | **0** |

**Conclusion:** ML is not only copying the port rule. Without `Dst Port` it still matches attack recall and **greatly reduces false alarms** versus “everything on 21/22 is an attack.”

The remaining **10 SSH → FTP** errors appear in both the port rule and the ML models (likely SSH-labelled flows on port 21 that also look like FTP brute force in other features).

**Selected Phase 1 model:** XGBoost trained **without `Dst Port`** (77 features), on experimental evidence, not because XGBoost is popular.

---

## 9. Saved detection artefacts

After selection, the following were saved under `models/`:

| File | Purpose |
|------|---------|
| `sentinel_xgb.pkl` | Trained XGBoost classifier |
| `label_encoder.pkl` | Maps 0/1/2 back to class names |
| `feature_columns.pkl` | Ordered list of 77 training columns |

A small inference check (`ml/predict_test.py`) loads these files, shapes one CSV row to `(1, 77)`, and calls `predict` / `predict_proba`.

Examples (single rows from `cic_clean.csv`, **not** a test-set score):

- One Benign row → predicted Benign, ~100% confidence  
- One FTP-BruteForce row → predicted FTP-BruteForce, ~99.99% confidence  

This only proves the **save/load pipeline**. Live packets are not involved yet.

---

## 10. Repository layout (current)

```text
Capstone/
  data/raw/cic.csv
  data/processed/cic_clean.csv
  models/          saved XGBoost + encoder + column list
  ml/              EDA, preprocess, split, models, experiments, predict_test
```

`ml/paths.py` stores all file locations so scripts run from the project root.

---

## 11. What is implemented vs what is not

### Implemented

- EDA and documented preprocessing  
- Decision to keep training duplicates, with evaluation caveats  
- Decision Tree, Random Forest, XGBoost  
- Experiments A, B, C with recorded metrics  
- Model choice: XGBoost, 77 features, no destination port  
- Persist + reload + single-row prediction  

### Not implemented (do not present as done)

- Packet capture / CICFlowMeter-style live features  
- Real-time IDS, dashboard, firewall response  
- HIDS / hybrid host+network  
- Isolation Forest / unknown-attack detector  
- Additional attack types (DDoS, port scan, botnet, …)  
- Evasion testing (fragmentation, etc.)  

---

## 12. Limitations (for supervisor discussion)

1. **Three labels only** on one CIC 2018 brute-force capture.  
2. **FTP** has no unique held-out flows in Experiment B.  
3. Offline CIC scores will not automatically hold on campus Wi-Fi.  
4. Feature extraction for live traffic must **match** the 77 CIC columns (hardest remaining ML/network task).  
5. High accuracy is typical on this benchmark; the useful result is **beating the port baseline on false alarms** and **unseen SSH vs Benign**.

---

## 13. Proposed next phase

1. Map CIC flow features to a free flow exporter (or a reduced student feature set, with a clear gap analysis if not 1:1).  
2. Capture traffic on a lab machine (with permission).  
3. Send each completed flow through the saved model (`predict` + `predict_proba`).  
4. Log: timestamp, predicted class, confidence — still no dashboard required.  
5. Only then: simple alert UI and **user-approved** blocking.

No extra datasets until the live feature pipeline exists, unless the supervisor wants more CIC days (e.g. DDoS) for a broader classifier.

---

## 14. Tools (all free)

Python, pandas, NumPy, scikit-learn, XGBoost, joblib, matplotlib.  
No paid cloud or commercial IDS licence.

---

## 15. One-paragraph summary (can be used in a weekly meeting)

We cleaned a CSE-CIC-IDS2018-style brute-force flow dataset (Benign / FTP / SSH), kept duplicates in training, and compared Decision Tree, Random Forest, and XGBoost. Headline accuracy above 99.99% is largely because this capture is easy and because many test rows copy the training set; in particular, FTP never appears as a unique test flow. After dropping destination port, the models still work, and they produce far fewer false alarms than a port-21/22 rule. XGBoost without `Dst Port` is the saved Phase 1 engine. Next work is live flow feature extraction, not a dashboard.

---

*End of Phase 1 progress report.*
