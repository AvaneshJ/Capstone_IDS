# SentinelAI — Research Paper Guide

**Purpose:** a ready-to-fill skeleton for the capstone research paper. It gives the paper's structure, a draft
abstract, the contribution claims we can defend, where each section's content already lives, the figures and
tables to produce, and a starting reference list.
**Format assumed:** IEEE conference style (two-column, 6–8 pages). Template: IEEE "conference-template-a4" on
Overleaf. Adjust if your supervisor wants a different format.

---

## 1. Title options

1. *SentinelAI: A Hybrid Network and Host Intrusion Detection System with Multi-Agent Automated Response and
   Tamper-Evident Evidence*
2. *From Benchmark to Desktop: Domain-Adapted Machine Learning Intrusion Detection with Explainable Automated
   Response*
3. *Bridging the Lab-to-Live Gap in ML-Based Intrusion Detection: A Hybrid NIDS/HIDS with SOAR for End Users*

---

## 2. Draft abstract (≈ 230 words — edit numbers once Tables V-3 to V-6 are filled)

> Machine-learning intrusion detection systems routinely report near-perfect accuracy on public benchmarks, yet
> such scores rarely survive deployment on real machines. We present SentinelAI, a hybrid network and host
> intrusion detection system for Windows that couples detection with automated, explainable response. The network
> component classifies bidirectional flows into seven classes with an XGBoost model trained on 77 CICFlowMeter
> features. We show that CSE-CIC-IDS2018 contains a destination-port shortcut and 43 % train–test duplication,
> remove the port from the feature set, and adapt the model with traffic captured in an isolated attack lab. A
> runtime out-of-distribution policy re-examines confident "benign" verdicts on authentication ports, and a
> Java-compatible feature bridge removes training–serving skew in live capture. The host component detects
> credential-stealing behaviour with an Isolation Forest trained only on normal process runs, combined with
> audited access to browser credential stores and a code-signing reputation layer that suppresses false alarms
> from signed vendor software without trusting script hosts. Eleven cooperating agents perform enrichment, MITRE
> ATT&CK mapping, risk scoring, firewall and process response, and natural-language briefings, while a
> self-protection layer provides an integrity-verified model store, an HMAC hash chain over all evidence, sensor
> heartbeats and tamper detection. Without the port feature, the model removes all 75 false alarms of a port
> baseline at equal recall; [ADD: held-out lab detection rate, HIDS detection/FPR]. SentinelAI ships as a single
> Windows installer with a plain-language desktop interface, demonstrating that research-grade detection can be
> delivered to non-expert users.

**Keywords:** intrusion detection, machine learning, XGBoost, Isolation Forest, SOAR, multi-agent systems,
infostealer detection, dataset bias, domain shift, explainability, tamper evidence.

---

## 3. Contributions (what the paper claims)

Keep each claim backed by a section and a result.

| # | Contribution | Evidence |
|---|--------------|----------|
| C1 | An analysis of shortcut learning in CSE-CIC-IDS2018 (port–label alignment, 43 % duplication) and a port-free 77-feature model that beats the port rule on false alarms | V-A, Tables V-1, V-2 |
| C2 | A lab-to-live pipeline: domain-adapted training (v3), a Java-compatible live feature bridge and a runtime OOD policy for over-confident benign verdicts | Methodology A.4–A.5, V-C, Cases 3–4 |
| C3 | A host detector for infostealers combining one-class anomaly detection with evidence of credential-store access, and a reputation layer resistant to living-off-the-land abuse | Methodology B, C; V-D; Case 1 |
| C4 | A multi-agent SOAR architecture with explainable, policy-driven, test-mode-by-default response | Architecture §5, Methodology A.7, E |
| C5 | A self-protection design for user-space security agents: verified model loading, HMAC evidence chain with external anchor, heartbeat watchdog, tamper sensor, and OS-shutdown attribution | Methodology D, Case 2 |
| C6 | A deployable end-user system (single installer, plain-language UI) and its engineering evaluation | Architecture §8–9, V-E |

If page limits are tight, lead with C1–C3 (the research) and summarise C4–C6 as "system contributions".

---

## 4. Paper outline and where the content is

| Section | Length (IEEE 2-col) | Content | Source doc |
|---------|--------------------:|---------|------------|
| Abstract | 200–250 words | §2 above | — |
| I. Introduction | 0.75 p | Problem: benchmark-vs-live gap, alert fatigue, end users lack SOC; research questions; contributions list | §3, §5 below |
| II. Related Work | 0.75 p | ML-NIDS on CIC datasets; dataset pitfalls; anomaly-based HIDS; SOAR / automated response; tamper-evident logging | §6 below |
| III. System Architecture | 1 p | Layered diagram, data flow, agent table | `System_Architecture.md` §2, §4, §5 |
| IV. Methodology | 1.5–2 p | A. NIDS (data, model, port rule, OOD, feature bridge, routing, risk); B. HIDS; C. Reputation; D. Self-protection | `Methodology_and_Algorithms.md` |
| V. Evaluation | 1.5 p | Setup, offline baseline, v3, held-out lab, HIDS, system metrics | `Evaluation_and_Results.md` V-A…V-E |
| VI. Discussion | 0.5 p | Case studies, lessons, threats to validity | `Evaluation_and_Results.md` V-F, VI |
| VII. Conclusion & Future Work | 0.25 p | Summary; correlation of host + network; kernel sensors; more attack classes; federated retraining | §7 below |
| References | — | 15–25 entries | §6 below |
| Appendix (optional) | — | 77-feature list, policy YAML excerpt | `features_list.md`, `soar/rules/policies.yaml` |

### Suggested research questions (for the Introduction)

* **RQ1:** How much of the reported accuracy on CSE-CIC-IDS2018 comes from dataset shortcuts, and does a
  port-free model still detect the attacks? (→ V-A)
* **RQ2:** Does a model trained on public benchmark traffic detect the same attacks on a live network, and how
  much do domain adaptation and a runtime OOD policy help? (→ V-C)
* **RQ3:** Can credential-stealing behaviour be detected on a host with a model trained only on normal activity,
  at a false-positive rate acceptable to end users? (→ V-D, Case 1)
* **RQ4:** Can a user-space security agent make its own disabling and evidence tampering detectable? (→ V-E, Case 2)

---

## 5. Figures and tables to produce

| # | Type | Content | How to make it |
|---|------|---------|----------------|
| Fig. 1 | Architecture | Six-layer diagram (sensors → routing → agents → store → API → app) | Redraw `System_Architecture.md` §2 in draw.io |
| Fig. 2 | Flow chart | Network path: flow → model → port rule → OOD → risk → decision → firewall | `System_Architecture.md` §4.1 |
| Fig. 3 | Flow chart | Host path with trust levels | `System_Architecture.md` §4.2 |
| Fig. 4 | Bar chart | Class distribution of the merged v3 dataset (log scale) | `pandas` value counts of `cic_lab_merged_clean.csv` |
| Fig. 5 | Heat map | v3 confusion matrix (normalised by row) | `train_xgb_v3.py` output → seaborn |
| Fig. 6 | Bar chart | Feature importance (top 15, gain) of v3 | `model.get_booster().get_score(importance_type="gain")` |
| Fig. 7 | Histogram | Init Fwd Win Byts: CIC SSH vs lab SSH (shows domain shift) | CIC vs lab CSVs |
| Fig. 8 | ROC / score histogram | HIDS anomaly scores, normal vs simulated stealer, with threshold | `train_model.py` pipeline `decision_function` |
| Fig. 9 | Diagram | Evidence hash chain + external anchor | Methodology D formula |
| Fig. 10 | Screenshots | Desktop app: Home, Alert detail with "Your decision" | Run the installed app |
| Table I | Comparison | SentinelAI vs Snort/Suricata, Wazuh, Zeek, commercial EDR (features) | §6.3 below |
| Table II | Parameters | XGBoost and Isolation Forest hyper-parameters | Methodology A.2, B.3 |
| Table III | Policy | Risk thresholds and actions | Methodology A.7 |
| Tables IV–VIII | Results | V-1 to V-8 | `Evaluation_and_Results.md` |

Fig. 6 snippet:

```python
import joblib, pandas as pd
m = joblib.load("models/sentinel_xgb_v3.pkl"); cols = joblib.load("models/feature_columns_v3.pkl")
gain = m.get_booster().get_score(importance_type="gain")
s = pd.Series({cols[int(k[1:])] if k.startswith("f") else k: v for k, v in gain.items()}).nlargest(15)
s.sort_values().plot.barh(figsize=(5, 4)).figure.savefig("fig6_importance.png", dpi=300, bbox_inches="tight")
```

---

## 6. Related work and references

### 6.1 Themes to cover (one paragraph each)

1. **ML-based NIDS on CIC datasets** — tree ensembles and deep models report > 99 % accuracy on CICIDS2017 /
   CSE-CIC-IDS2018. Position SentinelAI: we reproduce this, then show why it is not enough.
2. **Pitfalls in security ML** — dataset labelling errors, shortcut features, duplicated flows, closed-world
   evaluation. Our V-A and V-C directly address these.
3. **Anomaly-based host detection** — one-class models (Isolation Forest, autoencoders) for process behaviour;
   infostealer tradecraft (browser credential stores, MITRE T1555.003).
4. **SOAR and automated response** — playbooks, orchestration, human-in-the-loop; multi-agent designs.
5. **Tamper-evident logging and agent self-protection** — hash chains / forward-secure logs; EDR self-defence.
6. **Explainability for end users** — natural-language alert explanations, LLM-assisted triage.

### 6.2 Starting reference list

These are well-known works that fit the themes above. **Check every entry against Google Scholar / IEEE Xplore
before submission** (authors, year, venue, pages) and export BibTeX from there; do not cite anything you have not
opened.

1. I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward generating a new intrusion detection dataset and
   intrusion traffic characterization," *ICISSP*, 2018. — CICIDS2017 / CSE-CIC-IDS2018 methodology.
2. A. H. Lashkari, G. Draper-Gil, M. S. I. Mamun, A. A. Ghorbani, "Characterization of Tor traffic using time based
   features," *ICISSP*, 2017. — CICFlowMeter feature definitions.
3. T. Chen, C. Guestrin, "XGBoost: A scalable tree boosting system," *ACM KDD*, 2016.
4. F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation forest," *IEEE ICDM*, 2008.
5. R. Sommer, V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection,"
   *IEEE S&P*, 2010.
6. D. Arp et al., "Dos and don'ts of machine learning in computer security," *USENIX Security*, 2022.
7. G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an intrusion detection dataset: the CICIDS2017 case study,"
   *IEEE S&P Workshops (WTMC)*, 2021.
8. M. Ring, S. Wunderlich, D. Scheuring, D. Landes, A. Hotho, "A survey of network-based intrusion detection data
   sets," *Computers & Security*, 2019.
9. B. E. Strom et al., "MITRE ATT&CK: Design and philosophy," MITRE Technical Report, 2018.
10. C. Islam, M. A. Babar, S. Nepal, "A multi-vocal review of security orchestration," *ACM Computing Surveys*,
    2019.
11. B. Schneier, J. Kelsey, "Secure audit logs to support computer forensics," *ACM TISSEC*, 1999. — hash-chained
    logs.
12. S. A. Crosby, D. S. Wallach, "Efficient data structures for tamper-evident logging," *USENIX Security*, 2009.
13. M. Roesch, "Snort: Lightweight intrusion detection for networks," *USENIX LISA*, 1999. — signature baseline.
14. V. Paxson, "Bro: A system for detecting network intruders in real-time," *Computer Networks*, 1999. — Zeek.
15. Microsoft, "Microsoft Defender Antivirus exclusions / indicators of compromise (allow by file hash and
    certificate)," Microsoft Learn documentation. — basis for the hash > publisher > no-folder trust order.
16. V. Chandola, A. Banerjee, V. Kumar, "Anomaly detection: A survey," *ACM Computing Surveys*, 2009.

Add 3–5 recent (2022–2026) papers on ML-NIDS cross-dataset generalisation and LLM-assisted SOC triage from
Google Scholar to show the work is current.

### 6.3 Comparison table (Table I) — fill and verify

| Capability | Snort / Suricata | Zeek | Wazuh (HIDS/SIEM) | Commercial EDR | **SentinelAI** |
|------------|:---:|:---:|:---:|:---:|:---:|
| Signature-based network detection | ✓ | partial | — | — | — |
| ML flow classification | — | — | — | ✓ | ✓ |
| Host behaviour / credential theft | — | — | ✓ (rules) | ✓ | ✓ |
| Automated response | IPS mode | — | active response | ✓ | ✓ (test mode default) |
| Plain-language explanations / LLM | — | — | — | some | ✓ |
| Tamper-evident evidence chain | — | — | — | vendor-specific | ✓ |
| Target user | analysts | analysts | analysts | enterprises | end users / small teams |

---

## 7. Future work (for the conclusion)

* **Host–network correlation:** link a host incident (process X read credentials) with a network incident from the
  same process (outbound upload) into one attack story — the main open item in the roadmap.
* **More attack classes and data:** web attacks and infiltration (CSE-CIC-IDS2018 other days), modern traffic
  datasets, more lab scenarios.
* **Continual / federated learning:** retrain on user-confirmed false positives and true positives without
  sharing raw data.
* **Kernel-level sensors and self-defence:** ETW threat-intelligence provider, minifilter driver, Protected Process
  Light (requires signed drivers).
* **Cross-platform:** Linux host sensors (auditd/eBPF) and nftables response.

---

## 8. Writing checklist

* [ ] Fill 📝 tables in `Evaluation_and_Results.md` (V-3 to V-6, V-8) on the machine with `data/lab/` and the HIDS
      logs; rerun `pytest` and update the test count if it changed.
* [ ] Make every number in the abstract and conclusion match a table.
* [ ] Never quote the Phase 1 three-class 99.99 % as the shipped model's accuracy.
* [ ] Say "simulated stealer" for HIDS attack data; say "test mode (dry-run)" for response unless real blocking was
      used in the experiment.
* [ ] Anonymise host names and IPs other than the documented lab range.
* [ ] Every figure: readable at column width (≥ 8 pt fonts), 300 dpi, referenced in the text.
* [ ] Every reference opened and verified; BibTeX exported from the publisher.
* [ ] State the team's individual contributions if your department requires it (roles in
      `Project_Gameplan_Blueprint.md` §9).
* [ ] Run a plagiarism / AI-text check as required by your institution; paraphrase from these docs rather than
      pasting.
