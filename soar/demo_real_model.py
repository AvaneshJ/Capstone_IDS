"""
SOAR smoke demo with real multiclass XGBoost v2 on cic_multiclass_clean.csv rows.

From Capstone root:
  python soar/demo_real_model.py
"""
from __future__ import annotations

import os
import sys

# soar/ on path for core/agents; Capstone root for config/nids
_SOAR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_SOAR)
sys.path.insert(0, _SOAR)
sys.path.insert(0, _ROOT)

import pandas as pd

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _C:
        CYAN = GREEN = RED = YELLOW = WHITE = RESET_ALL = ""
    Fore = Style = _C()
    def init(*_a, **_k):
        pass

from config.paths import CLEAN_CSV
from core.orchestrator import SentinelOrchestrator
from nids.feature_extractor import csv_row_to_raw_features

# colorama optional

# One row per class if available
PREFERRED = {
    "Benign": None,
    "FTP-BruteForce": None,
    "SSH-Bruteforce": None,
}


def pick_rows(df: pd.DataFrame) -> list[int]:
    indices = []
    for label in PREFERRED:
        hits = df.index[df["Label"] == label].tolist()
        if hits:
            indices.append(int(hits[0]))
    if not indices:
        indices = [0, min(1000, len(df) - 1), min(5000, len(df) - 1)]
    return indices


def main() -> None:
    print(f"{Fore.CYAN}SentinelAI — real CIC XGBoost through SOAR orchestrator{Style.RESET_ALL}")
    print("Dataset: CSE-CIC-IDS2018-style multiclass (77 features, no Dst Port + hybrid port override)\n")

    orch = SentinelOrchestrator(dry_run_firewall=True, enable_desktop_alerts=False)
    orch.initialize()

    if not orch.detection_agent.is_ml_loaded:
        print(f"{Fore.RED}FAIL: Detection Agent did not load Phase-1 model{Style.RESET_ALL}")
        orch.shutdown()
        sys.exit(1)

    print(f"{Fore.GREEN}[+] ML loaded: {orch.detection_agent.adapter.model_path}{Style.RESET_ALL}")
    print(f"    Features: {len(orch.detection_agent.adapter.feature_names)}\n")

    df = pd.read_csv(CLEAN_CSV)
    for idx in pick_rows(df):
        row = df.iloc[idx]
        raw = csv_row_to_raw_features(row)
        flow = {
            "src_ip": "192.168.56.101",
            "dst_ip": "192.168.56.1",
            "src_port": 50000,
            "dst_port": 22 if row["Label"] == "SSH-Bruteforce" else (21 if "FTP" in str(row["Label"]) else 443),
            "protocol": int(row.get("Protocol", 6) or 6),
            "raw_features": raw,
        }
        incident = orch.process_flow(flow)
        true_y = row["Label"]
        pred = incident.detection.attack_type
        conf = incident.detection.confidence
        ok = str(true_y) == str(pred)
        color = Fore.GREEN if ok else Fore.RED
        print(
            f"row {idx:>7} | true={true_y:<16} | pred={color}{pred:<16}{Style.RESET_ALL} | "
            f"conf={conf*100:6.2f}% | risk={incident.risk.score}/10 | "
            f"MITRE={incident.threat.mitre_technique_id} | match={ok}"
        )

    orch.shutdown()
    print(f"\n{Fore.CYAN}Done.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
