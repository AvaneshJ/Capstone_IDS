# SentinelAI — Methodology and Algorithms

**Status date:** October 2026.
**Paper use:** Section IV (Methodology). Every constant below is quoted from the code (file in brackets) so it can be
cited exactly. If you change a constant, update this file.

---

## A. Network intrusion detection (NIDS)

### A.1 Dataset and feature contract

* **Base dataset:** CSE-CIC-IDS2018 flow CSVs (Java CICFlowMeter output). Phase 1 cleaning: drop NaN/Inf rows,
  drop the `Timestamp`, `Flow ID`, `Src IP`, `Dst IP`, `Src Port` identifiers, remove constant columns.
  Details: `Phase1_Progress_Report.md`.
* **Feature contract:** 77 numeric CIC flow features, **without `Dst Port`** (`features_list.md`,
  `models/feature_columns_v3.pkl`). The port was removed after Phase 1 showed it is a dataset shortcut: in
  CIC-IDS2018 every flow to port 22 is SSH brute force and every flow to port 21 is FTP brute force, so a
  port-aware model learns the port rather than the behaviour (Experiment B, Phase 1).
* **Domain adaptation (v3):** CIC flows merged with flows captured in an isolated VirtualBox lab
  (Kali `192.168.56.101` attacking Ubuntu `192.168.56.102`), processed with the same CICFlowMeter definitions
  (`ml/build_merged_dataset.py`).

| Setting | Value [`ml/build_merged_dataset.py`] |
|---------|------|
| CIC caps per class | Benign 100,000; Botnet, DDoS, DoS, FTP-BruteForce, SSH-Bruteforce 50,000 each |
| Lab caps per class | DoS 4,000; DDoS 4,000; PortScan 2,000 |
| Lab oversampling (replication) | SSH ×20, FTP ×12 (few lab brute-force flows) |
| Held-out lab file | `data/lab/ssh_attacks.csv` — never used in training, used for the domain check |
| Classes (7) | Benign, Botnet, DDoS, DoS, FTP-BruteForce, PortScan, SSH-Bruteforce |

### A.2 Classifier

XGBoost gradient-boosted trees [`ml/train_xgb_v3.py`]:

| Hyper-parameter | Value |
|-----------------|-------|
| `n_estimators` | 350 |
| `max_depth` | 7 |
| `learning_rate` | 0.07 |
| `subsample` / `colsample_bytree` | 0.85 / 0.85 |
| `min_child_weight` | 2 |
| `tree_method` | `hist` |
| Objective | `multi:softprob` |
| Class imbalance | balanced sample weights (`compute_sample_weight("balanced")`) |
| Split | 80/20 stratified, fixed random seed |

Tree models need no scaling, so no scaler is shipped. Version history: v2 = 6 CIC classes (frozen rollback,
`ML_Package_v2.md`); v3 = 7 classes with lab data (active, `ML_Package_v3.md`).

### A.3 Hybrid port post-processing

The port is not a model input, but it is a reliable tie-breaker between classes that look alike at flow level
(high-rate short TCP sessions). After inference [`soar/adapters/cic_xgb_adapter.py`, `apply_port_override`]:

```
if label ∈ {DoS, FTP-BruteForce, SSH-Bruteforce}:
    if dst_port == 21: label ← FTP-BruteForce
    if dst_port == 22: label ← SSH-Bruteforce
```

Benign and other attack labels are never changed, so the rule cannot create a detection out of benign traffic.
The raw ML label and confidence are preserved on the result for transparency.

### A.4 Out-of-distribution (OOD) policy layer

**Problem.** A model trained on 2018 CIC captures can be over-confident on modern live traffic, for example a
brute-force flow from a current Linux TCP stack (initial window 64240, never seen in CIC SSH data) classified
Benign with probability ≈ 1.0.

**Method.** A rule layer re-examines flows the model calls **Benign** on authentication ports, without retraining
the model [`soar/rules/ood_policy.py`, `policies.yaml → ood_policy`]:

| Signal | Condition (auth ports 21, 22, 3389, 445) |
|--------|------------------------------------------|
| `syn_on_auth` | SYN flag count ≥ 1 |
| `fwd_pkts_on_auth` | forward packets ≥ 2 |
| `ood_init_win` | initial forward window ≥ 40,000 **and** not in the CIC set {0, 241, 8192, 26883, 29200, 65535} |
| `ml_benign_overconfident` | P(Benign) ≥ 0.999 together with SYN or forward-packet activity |
| `auth_velocity` | ≥ 3 such flows from the same source in 60 s |

**Decision.** Override when (number of strong signals ≥ 2) **or** the velocity signal fired. Hitting an auth port
alone never counts. The new label comes from the port (22 → SSH-Bruteforce, 21 → FTP-BruteForce,
3389/445 → BruteForce) with fixed confidence 0.78, and the reason string lists the signals.

### A.5 Live capture and the feature bridge

[`nids/live_capture.py`, `nids/feature_extractor.py`]

* **Capture backends:** Npcap via Scapy if installed; otherwise WinDivert in sniff-only mode (bundled with
  `pydivert`, needs administrator rights). Filter `ip and (tcp or udp)`.
* **Flow termination:** FIN/RST + 1 s grace, idle 30 s, active duration 120 s (Java CICFlowMeter default) or
  5,000 packets (memory cap).
* **Training–serving skew correction.** The Python `cicflowmeter` package differs from the Java tool used to make
  CIC-IDS2018: it measures packet length as the whole IP packet instead of the transport payload, header length as
  the IP header instead of the TCP/UDP header, uses population instead of sample standard deviation, counts the
  first packet twice, and reports times in seconds instead of microseconds. A subclass of its `Flow` recomputes
  those fields with the Java definitions before the 77-feature vector is built.
* **Orientation:** the forward direction is client → server; ephemeral ports (≥ 49152) mark the client side.

### A.6 Live routing (alert-fatigue controls)

[`soar/core/live_monitor.py`] Every flow is classified, but only some become incidents:

| Control | Rule |
|---------|------|
| Direction | Only **inbound** threats (source outside this machine, destination this machine) create incidents; outbound and internal flows are counted only, so the user's own address is never blocked |
| Benign volume | Benign flows are counted per day (`traffic_stats`), not stored |
| Port-scan fan-out | One source touching ≥ 15 distinct ports on this machine within 20 s → PortScan incident (a scan is many 1–2 packet flows the per-flow model cannot see) |
| Cooldown | One incident per (source, attack type) per 60 s |
| Budget | At most 30 incidents per minute |
| Host alerts | One alert per (program, file) per 600 s; once per 24 h for trusted vendors |

### A.7 Risk scoring and response decision

Network risk [`soar/agents/risk_agent.py`, `soar/rules/policy_engine.py`]:

\[
R = \operatorname{clip}_{[0.1,\,10]}\big(W_{\text{attack}} \cdot c + V(n_{60}) + S(\text{dst})\big)
\]

* \(W\): base attack weight — DDoS 9.0, Botnet 9.0, DoS 8.0, SSH/FTP brute force 7.5, BruteForce 7.0,
  PortScan 5.0, AnomalousTraffic 4.0, Benign 0.
* \(c\): detection confidence.
* \(V\): velocity bonus from events by the same source in a 60 s sliding window: 0 (1–3), 0.8 (4–10),
  1.6 (11–25), 2.5 (> 25).
* \(S\): target sensitivity = port bonus (SMB 1.8; MySQL, PostgreSQL, MSSQL, RDP 1.5; SSH 1.2; FTP 1.0;
  HTTP(S) 0.5; 8080 0.6) + 1.0 if the destination is in a critical subnet.
* Benign flows get a fixed 0.2 (0.3 under high volume).

Decision [`soar/rules/policies.yaml → thresholds`], after the whitelist check:

| Risk | Severity | Action | Duration |
|------|----------|--------|----------|
| ≥ 8.5 | CRITICAL | `BLOCK_IP` | 24 h |
| ≥ 7.0 | HIGH | `TEMP_BAN_IP` | 30 min |
| ≥ 5.0 | MEDIUM | `TEMP_BAN_IP` | 15 min |
| < 5.0 | LOW | `LOG_ONLY` | — |

Worked example (SSH brute force against the lab host): \(7.5 \times 0.78 + 0 + (1.2 + 1.0) = 8.05\) → HIGH,
30-minute ban; repeated attempts raise the velocity term and push it to CRITICAL.

Blocks are Windows Firewall rules (`netsh advfirewall`) with automatic expiry. Default is **test mode**: the rule is
recorded as `SIMULATED` and nothing is changed on the system.

---

## B. Host intrusion detection (HIDS)

### B.1 Threat model

Infostealers (RedLine, Vidar, Lumma-style) read browser credential stores — `Login Data`, `Local State` (master
key), `Cookies`, `Web Data`, Firefox `key4.db` / `logins.json` — and wallets, then exit within seconds.

### B.2 Sensors

* **Process sensor** [`hids/process_monitor.py`]: psutil scan every 2 s (5 s in eco mode); records lifetime,
  executable path, parent.
* **Credential-file sensor** [`hids/file_monitor.py`]: Windows object-access auditing (Security event 4663) on the
  browser profile files; who-opened-what with the opener's process ID.
* **Simulator for data collection** [`hids/dataset/stealer_simulator.py`]: a safe program that mimics stealer
  behaviour (copies credential files to temp, then deletes them) to produce labelled attack runs.

### B.3 Anomaly model

Isolation Forest [`hids/dataset/train_model.py`], trained **only on normal runs** (one-class), so it does not depend
on having many stealer samples.

| Item | Value |
|------|-------|
| Features | `log_life` (log of process lifetime), `from_user_space`, `from_temp_or_downloads`, `parent_is_shell` |
| Scaling | StandardScaler |
| Trees | 400 |
| `contamination` | 0.02 |
| Threshold | set for a target false-positive rate of 2 % on normal training runs (≈ 0) |
| Training data | 1,956 normal process runs from 3 Windows hosts |
| Validation | leave-one-host-out (train on two hosts, test on the third) |

### B.4 Two detection paths

1. **Evidence path:** a credential-file read by a process that is not the owning browser goes to SOAR immediately
   (the stealer may be gone before its run is scored).
2. **Behaviour path:** a finished process run is scored by the Isolation Forest; anomalous runs go to SOAR as
   `Anomalous`. An `Anomalous` run that also read a credential file is upgraded to `Stealer`.

Process-only events from `C:\Windows` and `Program Files` are dropped (installed software is not "unusual").

### B.5 Host risk and response

[`soar/agents/host_agent.py`]

\[
R_{\text{host}} = \operatorname{clip}_{[1,\,10]}\big(7.5\,c + w_{\text{file}} + b_{\text{parent}} + 0.5\,a\big)
\]

* \(c\): model confidence; \(a\): anomaly score in [0, 1].
* \(w_{\text{file}}\): Login Data, key4.db, logins.json, wallet.dat 3.5; Local State 3.0; Cookies, Web Data 2.5.
* \(b_{\text{parent}}\) = 1.0 if started by cmd, PowerShell, wscript, cscript or mshta.
* Anomalous without file evidence: \(R = 2 + 4.5a\); Normal: 0.5.

Severity uses the same 8.5 / 7.0 / 4.0 cut-offs. **Automatic termination requires both** a recorded protected-file
access **and** \(R \ge 7.0\); a behaviour score alone only raises an alert, because developer tools, scripts and
installers can look anomalous. Termination re-checks that the PID still belongs to the reported executable name (a
recycled PID is not killed), refuses PID ≤ 4 and SentinelAI's own processes, and runs in test mode by default.

MITRE ATT&CK: T1555.003 (credentials from web browsers), T1539 (steal web session cookie), T1005 (data from local
system).

---

## C. False-positive handling: program reputation and user allow rules

**Problem observed in deployment.** Signed security software (McAfee's `uihost.exe`, `servicehost.exe`) reads
browser `Local State` / `Login Data` for its password-manager and web-protection features — exactly the stealer
pattern — and was reported as CRITICAL Stealer.

**Design (modelled on Microsoft Defender, CrowdStrike Falcon and SentinelOne):** file hash and code-signing
publisher are trusted, folder location alone is not; trusted software is still *detected* but not *remediated*;
the user can mark an alert as a false positive. [`hids/trust.py`]

Trust levels, evaluated per executable:

| Level | Condition | Effect |
|-------|-----------|--------|
| `allowed` | A user rule matches: file SHA-256, **or** publisher with a currently valid signature | Event suppressed, counted as "allowed by you" |
| `trusted_vendor` | Valid Authenticode signature **and** installed under Windows / Program Files | Classification `TrustedAccess`, risk capped at 3.5, LOW, alert only, never auto-stopped, at most once per 24 h |
| `unverified` | Everything else | Normal pipeline |

Guards against abuse:

* **Script hosts never earn trust** — PowerShell, cmd, wscript/cscript, mshta, rundll32, regsvr32, python, node,
  java, etc. are Microsoft-signed and live in System32, but they run whatever script they are given.
* **Platform publishers cannot be trusted wholesale** — "Microsoft Windows", "Microsoft Windows Publisher" and
  "Microsoft Corporation" sign hundreds of system binaries (including living-off-the-land binaries), so a request to
  trust them falls back to a file-hash rule.
* A publisher rule only applies while the signature is valid, so a tampered or re-signed file loses the trust.
* Signature checks use PowerShell `Get-AuthenticodeSignature` once per executable (a PowerShell call, so
  sub-second to about a second), then the result is cached together with the file's SHA-256.

User actions on an alert: **Stop this program now** (real termination even in test mode, identity-checked, recorded
as a follow-up), **Trust programs from <publisher>**, **Trust only this file**. Follow-ups go to a separate table so
hash-chained incident rows are never edited.

---

## D. Self-protection (tamper resistance)

[`config/integrity.py`, `config/security.py`, `soar/database/db_manager.py`, `soar/core/watchdog.py`,
`soar/core/self_protection.py`, `hids/tamper_monitor.py`]

| Mechanism | Method | Detects |
|-----------|--------|---------|
| Integrity manifest | SHA-256 of models, policies and code; manifest HMAC-SHA256-signed with a per-install 256-bit key; models are hashed **before** unpickling | Model poisoning, policy edits, code swaps |
| API authentication | Per-install random token (`secrets.token_urlsafe(32)`), file ACL-restricted with `icacls` | Other local programs driving the engine |
| Evidence chain | Each incident / host incident / audit row gets \(h_i = \mathrm{HMAC}_K(i \,\|\, \text{table} \,\|\, \text{key} \,\|\, H(\text{row}) \,\|\, h_{i-1})\); chain head copied to a signed anchor file outside the DB | Edited, deleted, injected rows; DB truncation or replacement |
| Heartbeat watchdog | Sensors heartbeat; a sensor silent for > 90 s is reported | Killed or hung sensors |
| Tamper sensor | Security log 1102 (log cleared), 1100 (logging stopped), 4719 (audit policy changed, e.g. 4663 removed); kill commands (taskkill, `Stop-Process`, …) aimed at SentinelAI | Defence evasion (T1562.001, T1070) |
| Unclean-shutdown detection | Run marker with `started_at`, `alive_at` (refreshed every 30 s) and `planned_stop` | Engine killed while protecting |

Schedule: quick checks every 30 s, full re-hash every 600 s, chain verification every 300 s, tamper alerts at most
once per 600 s per kind.

**Attributing a stop to a Windows shutdown.** A laptop shutdown also ends the engine without a planned stop, which
initially produced false "engine killed" alerts. On the next start, the Windows shutdown time \(t_s\) is read from
the System event log (event 1074 "shutdown initiated", 6006 "event log stopped") — the registry `ShutdownTime` is
not used as the primary source because it is stale under Fast Startup (hybrid shutdown). The stop is attributed to
Windows when

\[
t_{\text{started}} < t_s \quad\text{and}\quad t_{\text{alive}} \ge t_s - G,\qquad G = 2 \times 30\,\text{s} + 30\,\text{s} = 90\,\text{s},
\]

i.e. the engine was still alive within one grace window of the shutdown. Otherwise a tamper incident is raised.
The installer also clears the run marker when it stops the engine for an upgrade or uninstall.

---

## E. Explanation layer

* **MITRE ATT&CK mapping** for every incident (`policies.yaml → mitre_mappings`, host mappings in `host_agent.py`).
* **Plain-language reasons** attached by the agents ("`x.exe` opened Saved Passwords DB, which only Google Chrome
  should read"; "Publisher check: signed by McAfee, LLC and installed in Program Files").
* **AI briefing** [`soar/agents/llm_agent.py`]: Google Gemini if an API key is configured → local Ollama (llama3)
  → an offline rule-based expert system, so a briefing is always produced without network access.
* **Single translation layer** in the desktop app (`dashboard/src/lib/translate.ts`) converts every backend code
  to plain language; Expert mode shows the raw values.
