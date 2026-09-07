from pathlib import Path

# Prefer shared config; keep this module for existing ml/*.py imports
try:
    from config.paths import (  # noqa: F401
        ROOT,
        DATA_RAW,
        DATA_PROCESSED,
        MODELS_DIR,
        RAW_CSV,
        CLEAN_CSV,
        MODEL_XGB,
        MODEL_ENCODER,
        MODEL_FEATURES,
    )
except ImportError:
    ROOT = Path(__file__).resolve().parent.parent
    DATA_RAW = ROOT / "data" / "raw"
    DATA_PROCESSED = ROOT / "data" / "processed"
    MODELS_DIR = ROOT / "models"
    RAW_CSV = DATA_RAW / "cic.csv"
    CLEAN_CSV = DATA_PROCESSED / "cic_clean.csv"
    MODEL_XGB = MODELS_DIR / "sentinel_xgb.pkl"
    MODEL_ENCODER = MODELS_DIR / "label_encoder.pkl"
    MODEL_FEATURES = MODELS_DIR / "feature_columns.pkl"
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
