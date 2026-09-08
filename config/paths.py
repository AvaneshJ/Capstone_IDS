"""
SentinelAI — canonical filesystem paths (project root).
Import from anywhere: add Capstone root to sys.path, then `from config.paths import ...`.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
MODELS_DIR = ROOT / "models"
NIDS_DIR = ROOT / "nids"
HIDS_DIR = ROOT / "hids"
SOAR_DIR = ROOT / "soar"
DOCS_DIR = ROOT / "docs"
DASHBOARD_DIR = ROOT / "dashboard"

RAW_CSV = DATA_RAW / "cic.csv"
CLEAN_CSV = DATA_PROCESSED / "cic_multiclass_clean.csv"

MODEL_XGB = MODELS_DIR / "sentinel_xgb_v2.pkl"
MODEL_ENCODER = MODELS_DIR / "label_encoder_v2.pkl"
MODEL_FEATURES = MODELS_DIR / "feature_columns_v2.pkl"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
