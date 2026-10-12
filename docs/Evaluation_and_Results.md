# SentinelAI — Evaluation and Results

**Status date:** October 2026.
**Paper use:** Section V (Evaluation) and VI (Discussion / Limitations).

Legend:

* ✅ **Measured** — number recorded in this repository or from a documented run; safe to quote.
* 📝 **TO FILL** — the experiment is defined and the script exists, but the result must be generated on the
  machine that holds the dataset (the lab CSVs and the HIDS run logs are gitignored and are not on every
  laptop). Run the command, paste the numbers, and delete the 📝 mark.

Do **not** quote the Phase 1 three-class 99.99 % accuracy as the score of the shipped seven-class model.

---

## V-A. Offline NIDS baseline (Phase 1, three classes) ✅

Source: `Phase1_Progress_Report.md`. Dataset: CSE-CIC-IDS2018 brute-force day, 1,044,751 clean flows
(Benign 63.5 %, FTP-BruteForce 18.5 %, SSH-Bruteforce 18.0 %), 80/20 stratified split, seed 42.

**Table V-1. Models with and without the destination port (full test set, 208,951 flows).**

| Model | Features | Accuracy | Errors | False alarms | Missed attacks |
|-------|---------:|---------:|-------:|-------------:|---------------:|
| Port rule only (21 → FTP, 22 → SSH) | 1 | 0.999593 | 85 | **75** | 0 |
| Decision Tree | 78 (with port) | 0.999952 | 10 | 0 | 0 |
| Decision Tree | 77 (no port) | 0.999947 | 11 | 1 | 0 |
| Random Forest | 77 (no port) | 0.999943 | 12 | 2 | 0 |
| **XGBoost** | **77 (no port)** | **0.999952** | **10** | **0** | **0** |

**Table V-2. Train/test duplication (Experiment B).**

| Measure | Value |
|---------|------:|
| Test rows whose 77-feature vector also appears in training | 89,931 / 208,951 (43.0 %) |
| FTP test rows that are copies of training rows | 100 % |
| "Unseen" test set (no copy in training) | 119,020 flows (Benign 100,202; SSH 18,818; FTP 0) |
| XGBoost accuracy on the unseen set | 1.000000 (0 errors) |

**Findings to state in the paper.**

1. A one-line port rule already scores 99.96 %, so headline accuracy on this benchmark measures the dataset more
   than the model. The port was therefore removed from the feature set.
2. Without the port, XGBoost keeps full attack recall and removes all 75 port-rule false alarms.
3. 43 % of test rows duplicate training rows; unseen FTP detection cannot be shown on this split. This motivates
   the lab capture and the held-out lab evaluation (V-C).

---

## V-B. Seven-class model v3 (CIC + lab) 📝

Protocol: `ml/build_merged_dataset.py` → `ml/train_xgb_v3.py` (80/20 stratified holdout of the merged set).

```powershell
python ml\build_merged_dataset.py
python ml\train_xgb_v3.py      # prints accuracy, confusion matrix, classification report
```

**Table V-3. v3 holdout, per class.** 📝

| Class | Precision | Recall | F1 | Support |
|-------|----------:|-------:|---:|--------:|
| Benign | | | | |
| Botnet | | | | |
| DDoS | | | | |
| DoS | | | | |
| FTP-BruteForce | | | | |
| PortScan | | | | |
| SSH-Bruteforce | | | | |
| **Weighted avg** | | | | |
| Accuracy | | | | |

Also export the confusion matrix as **Figure 5** (heat map). Report weighted and per-class scores; macro averages
are misleading when a class has very small support.

**Recommended extra column (strongly advised for reviewers):** repeat Experiment B on the merged data — drop test
rows whose 77-feature vector appears in training and re-score. One way:

```python
dup = X_test.merge(X_train.drop_duplicates(), how="left", indicator=True)["_merge"].eq("both").values
unseen = ~dup   # score model on X_test[unseen], y_test[unseen]
```

---

## V-C. Domain shift: held-out lab traffic 📝

`data/lab/ssh_attacks.csv` was captured in the Kali → Ubuntu lab and never used for training.

```powershell
python ml\eval_v3_dual.py      # [HELD-OUT LAB] SSH hits, [CIC SAMPLE] per-class accuracy, [LAB FAMILY SANITY]
```

**Table V-4. Effect of domain adaptation and the OOD layer on held-out lab SSH flows.** 📝

| Configuration | SSH flows detected / total | Detection rate |
|---------------|---------------------------:|---------------:|
| v2 (CIC only), model alone | | |
| v3 (CIC + lab), model alone | | |
| v3 + hybrid port rule | | |
| v3 + port rule + OOD policy (shipped) | | |

How to get the v2 row: temporarily point `config/paths.py` at the `*_v2.pkl` artefacts and rerun. How to get the
OOD row: send the same flows through `soar/demo_real_model.py` or `POST /api/flows/ingest` and count incidents.

This table is the main evidence for the paper's claim that **offline benchmark accuracy does not transfer to live
traffic** and that domain adaptation plus a runtime OOD layer recovers detection.

---

## V-D. HIDS Isolation Forest 📝 (partly measured)

✅ Measured / stored in `models/hids_isolation_forest.joblib`:

| Item | Value |
|------|-------|
| Normal process runs used for training | 1,956 |
| Hosts | 3 Windows PCs (team members) |
| Features | `log_life`, `from_user_space`, `from_temp_or_downloads`, `parent_is_shell` |
| Target false-positive rate | 2 % (threshold ≈ 0 on the decision function) |
| Preliminary result on the current sample | 100 % stealer detection at about 1 % false positives (`hids/dataset/README.md`) |

```powershell
python -m hids.dataset.build_dataset
python -m hids.dataset.train_model     # prints validation + leave-one-host-out table
```

**Table V-5. HIDS validation.** 📝

| Split | Normal runs | Stealer runs | Stealer detection | False-positive rate | ROC-AUC |
|-------|------------:|-------------:|------------------:|--------------------:|--------:|
| Held-out validation | | | | | |

**Table V-6. Leave-one-host-out (train on two PCs, test on the unseen PC).** 📝

| Held-out host | Normal runs | False-positive rate | Stealer detection |
|---------------|------------:|--------------------:|------------------:|
| Host A | | | |
| Host B | | | |
| Host C | | | |

Anonymise host names in the paper (Host A/B/C). State clearly that stealer runs come from the **safe simulator**,
not real malware.

---

## V-E. System-level verification ✅

Results from runs on a Windows 10 laptop (Intel-class CPU, Wi-Fi) during development.

**Table V-7. Engineering measurements.**

| Check | Result |
|-------|--------|
| Automated tests | 224 passing (`pytest soar nids hids` + `ml` tests) |
| Live capture without Npcap (WinDivert fallback) | 657 packets assembled into 39 flows in 20 s on Wi-Fi |
| Frozen engine cold start | ≈ 10 s to a ready API |
| End-to-end attack through frozen engine | Injected SSH brute-force flow → labelled SSH-Bruteforce, risk 9.0, CRITICAL, block simulated in test mode |
| Integrity manifest on a fresh install | `ok` (all files match) |
| Program-trust and terminate flow (real `ping.exe`) | Test-mode kill → `SIMULATED`; "Stop this program now" → `SUCCESS`; second press → `ALREADY_EXITED`; evidence chain still valid afterwards |
| Installer | `SentinelAI Setup 1.0.0.exe`, ≈ 227 MB; engine folder ≈ 254 MB installed |

**Table V-8. Suggested runtime measurements to add.** 📝

| Metric | How to measure | Value |
|--------|----------------|-------|
| Per-flow inference latency (median / p95) | Time `DetectionAgent.process` over 10,000 CIC rows | |
| End-to-end flow → incident latency | Timestamp at flow emit vs incident `timestamp` | |
| Engine CPU and memory, idle | Task Manager / `psutil` over 10 min, normal browsing | |
| Engine CPU and memory, under attack | Same, during a lab `hydra` SSH run | |
| Flows per day vs incidents per day | `traffic_stats` vs `incidents` table after one day of normal use | |

The last row gives the **alert-reduction ratio** (benign flows checked per alert raised), a strong usability number.

---

## V-F. Case studies (qualitative evaluation) ✅

### Case 1 — Signed security software flagged as an infostealer

* **Observation:** after installation on a laptop with McAfee, McAfee's `uihost.exe` and `servicehost.exe`
  (installed in Program Files) read Chrome/Edge `Local State` and `Login Data`. SentinelAI raised CRITICAL
  "Stealer" alerts and, outside test mode, would have stopped them.
* **Root cause:** the behaviour is identical to an infostealer; the system had no notion of software reputation.
* **Fix:** program trust levels (Methodology C). Both binaries now evaluate as `trusted_vendor` (valid
  "McAfee, LLC" signature, protected folder) → LOW, alert only, never stopped. An unsigned script run with the
  project's own Python still evaluates as `unverified` and keeps full detection.
* **Lesson for the paper:** behaviour-only HIDS needs a reputation layer, but the layer must not trust script
  hosts or the OS publisher, or living-off-the-land attacks inherit the trust. A first implementation trusted
  "Microsoft Windows" as a publisher after the user trusted `ping.exe`; this was caught in testing and replaced by
  the platform-publisher guard.

### Case 2 — False "engine killed" alert after a normal laptop shutdown

* **Observation:** after shutting the laptop down, the next start raised a CRITICAL tamper alert ("engine
  stopped without a planned shutdown").
* **Root cause:** Windows ends background processes at shutdown without notice, so the engine never wrote its
  planned-stop marker. The registry `ShutdownTime` value was weeks old because Fast Startup performs a hybrid
  shutdown that does not update it.
* **Fix:** the run marker now carries a heartbeat (`alive_at`, every 30 s) and the shutdown time is read from the
  System event log (IDs 1074 / 6006). A stop is attributed to Windows when the engine was alive within 90 s of
  the shutdown (Methodology D). A kill well before the shutdown is still reported.
* **Lesson:** self-protection signals need the same false-positive discipline as detection signals.

### Case 3 — Model over-confidence on modern live traffic

* **Observation:** live brute-force flows from a modern Linux client (initial TCP window 64240) were classified
  Benign with probability ≈ 1.0 by the CIC-only model.
* **Root cause:** CIC-IDS2018 SSH training flows only contain a handful of initial-window values.
* **Fix:** lab domain adaptation (v3) and the OOD policy layer (Methodology A.4). Quantify with Table V-4.

### Case 4 — Training–serving skew in flow features

* **Observation:** the Python `cicflowmeter` produced feature values with different definitions from the Java tool
  used to build CIC-IDS2018 (IP vs payload length, IP vs transport header, population vs sample std, seconds vs
  microseconds, first packet counted twice).
* **Fix:** a Java-compatible flow subclass recomputes those fields (Methodology A.5).
* **Suggested figure:** distribution of one feature (e.g. `Fwd Pkt Len Mean`) for the same lab capture before and
  after the fix, overlaid on the CIC distribution.

---

## VI. Threats to validity and limitations

**Internal validity**

* Benchmark accuracy on CIC-IDS2018 is inflated by port shortcuts and duplicated rows (V-A); we mitigate by
  removing the port and evaluating on unseen and held-out lab data, but the lab set is small.
* Lab oversampling (SSH ×20, FTP ×12) can make the holdout optimistic for those classes; the held-out lab file is
  the fairer test.
* HIDS stealer runs are produced by a safe simulator, not by real malware families.

**External validity**

* Lab topology is a single attacker and victim on a VirtualBox host-only network; enterprise traffic mixes are
  not represented.
* HIDS normal behaviour comes from three student laptops; other user populations may have different process
  lifetimes and parent patterns.
* Windows-only host sensors and firewall actions.

**Construct validity**

* Flow-level detection cannot see inside encrypted payloads and is not designed for application-layer attacks
  (SQL injection, XSS) or stolen-cookie replay.
* Classes outside the training set (zero-day network attacks) are only partially covered by the OOD layer, which
  is limited to authentication ports.

**System limitations**

* No kernel-mode self-defence (Protected Process Light, ELAM, minifilter drivers need signed drivers); an
  administrator can stop the engine — this is detected and recorded, not prevented.
* Host and network incidents are not yet correlated into a single attack story.
* Firewall and termination default to test mode; real blocking is an explicit user choice.
