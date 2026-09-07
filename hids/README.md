# SentinelAI HIDS (Phase 5)

Windows host monitoring stubs live here:

- `process_monitor.py` — psutil process inventory
- `file_monitor.py` — sensitive path heuristics (cookies / tokens)

The HIDS model (`hids_model.pkl`) will be added after a small labelled behavioural dataset exists.
Host events must feed the same SOAR bus as NIDS — do not bypass Decision / Firewall agents.
