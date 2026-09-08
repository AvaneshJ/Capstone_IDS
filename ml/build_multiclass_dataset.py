from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # Capstone root for config

import numpy as np
import pandas as pd
import joblib
from paths import DATA_RAW, DATA_PROCESSED, MODEL_FEATURES

# ---------------------------------------------------------------------------
# 1. Only the days we decided to keep (edit names if you deleted some)
# ---------------------------------------------------------------------------
SOURCE_FILES = [
    "cic.csv",  
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",     # Bot
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",     # DoS Hulk / SlowHTTPTest
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",   # DoS GoldenEye / Slowloris
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",  # DDoS HOIC / LOIC-UDP
]

OUT_CSV = DATA_PROCESSED / "cic_multiclass_clean.csv"

# ---------------------------------------------------------------------------
# 2. Collapse fine-grained CIC labels → 6 project classes
# ---------------------------------------------------------------------------
LABEL_MAP = {
    "Benign": "Benign",
    "FTP-BruteForce": "FTP-BruteForce",
    "SSH-Bruteforce": "SSH-Bruteforce",
    "Bot": "Botnet",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    # If you ever keep Tuesday LOIC-HTTP:
    # "DDoS attacks-LOIC-HTTP": "DDoS",
}


def clean_one(path: Path, feature_cols: list[str]) -> pd.DataFrame:
    print(f"\nLoading {path.name} ...")
    df = pd.read_csv(path, low_memory=False)
    print(f"  raw shape: {df.shape}")

    # Drop repeated header rows
    if "Label" in df.columns:
        df = df[df["Label"] != "Label"]

    # Same cleaning as preprocess.py
    df = df.replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df = df.dropna()
    print(f"  dropped NaN/inf rows: {before - len(df)}")

    if "Timestamp" in df.columns:
        df = df.drop(columns=["Timestamp"])

    # Remap labels; drop anything we don't want (web, infiltration, etc.)
    df["Label"] = df["Label"].map(LABEL_MAP)
    df = df.dropna(subset=["Label"])

    # Keep Phase-1 feature contract (77 cols) + Label — no Dst Port
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"{path.name} missing features: {missing[:10]}...")

    df = df[feature_cols + ["Label"]].copy()

    # Force numerics (CIC sometimes has bad strings after header glitches)
    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna()

    print(f"  kept shape: {df.shape}")
    print(df["Label"].value_counts().to_string())
    return df


def maybe_undersample_benign(df: pd.DataFrame, max_benign: int | None = 400_000, seed: int = 42) -> pd.DataFrame:
    """Optional: stop Benign from dominating the merge."""
    if max_benign is None:
        return df
    benign = df[df["Label"] == "Benign"]
    other = df[df["Label"] != "Benign"]
    if len(benign) <= max_benign:
        return df
    benign = benign.sample(n=max_benign, random_state=seed)
    out = pd.concat([benign, other], ignore_index=True)
    print(f"\nUndersampled Benign to {max_benign:,}. New shape: {out.shape}")
    return out


def main() -> None:
    feature_cols = list(joblib.load(MODEL_FEATURES))
    print(f"Using {len(feature_cols)} features from {MODEL_FEATURES}")
    assert len(feature_cols) == 77, "Expected Phase-1 77-feature contract"

    frames = []
    for name in SOURCE_FILES:
        path = DATA_RAW / name
        if not path.exists():
            print(f"SKIP missing file: {path}")
            continue
        frames.append(clean_one(path, feature_cols))

    if not frames:
        raise SystemExit("No source files found. Check SOURCE_FILES vs data/raw.")

    merged = pd.concat(frames, ignore_index=True)
    print("\n" + "=" * 60)
    print(f"Merged shape before benign cap: {merged.shape}")
    print(merged["Label"].value_counts())

    merged = maybe_undersample_benign(merged, max_benign=400_000)

    # Shuffle so classes aren't stacked by file order
    merged = merged.sample(frac=1.0, random_state=42).reset_index(drop=True)

    DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
    merged.to_csv(OUT_CSV, index=False)

    print("\n" + "=" * 60)
    print(f"Saved: {OUT_CSV}")
    print(f"Final shape: {merged.shape}")
    print("\nFinal class counts:")
    print(merged["Label"].value_counts())
    print("\nFinal class %:")
    print((merged["Label"].value_counts(normalize=True) * 100).round(2))


if __name__ == "__main__":
    main()