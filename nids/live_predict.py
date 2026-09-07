"""
Live / offline NIDS prediction entrypoint.

Usage (from Capstone root):
  python -m nids.live_predict
  python -m nids.live_predict --row 1000
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from config.paths import CLEAN_CSV
from nids.feature_extractor import csv_row_to_raw_features
from soar.adapters.cic_xgb_adapter import CicXgbAdapter


def predict_csv_row(row_index: int = 0) -> dict:
    adapter = CicXgbAdapter()
    adapter.load()

    df = pd.read_csv(CLEAN_CSV)
    row = df.iloc[row_index]
    raw = csv_row_to_raw_features(row)
    label, confidence, probs = adapter.predict(raw)

    true_label = row.get("Label", "?")
    return {
        "row_index": row_index,
        "true_label": true_label,
        "predicted": label,
        "confidence": confidence,
        "probabilities": probs,
        "n_features": len(adapter.feature_names),
        "match": str(true_label) == str(label),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Predict one CIC clean CSV row with Phase-1 XGBoost")
    parser.add_argument("--row", type=int, default=0, help="Row index in cic_clean.csv")
    args = parser.parse_args()

    result = predict_csv_row(args.row)
    print(f"Features : {result['n_features']} (CSE-CIC-IDS2018-style, no Dst Port)")
    print(f"True     : {result['true_label']}")
    print(f"Predicted: {result['predicted']}")
    print(f"Confidence: {result['confidence'] * 100:.2f}%")
    print(f"Match    : {result['match']}")
    print("Probabilities:")
    for name, p in result["probabilities"].items():
        print(f"  {name}: {p:.4f}")


if __name__ == "__main__":
    main()
