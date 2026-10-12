"""
SentinelAI — canonical filesystem paths (project root).
Import from anywhere: add Capstone root to sys.path, then `from config.paths import ...`.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# PyInstaller build: ROOT is the read-only bundle (models, rules, schema) inside Program Files.
FROZEN = bool(getattr(sys, "frozen", False))

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

# Active package (lab-adapted). v2 artefacts remain on disk as frozen CIC baseline.
MODEL_XGB = MODELS_DIR / "sentinel_xgb_v3.pkl"
MODEL_ENCODER = MODELS_DIR / "label_encoder_v3.pkl"
MODEL_FEATURES = MODELS_DIR / "feature_columns_v3.pkl"

MODEL_XGB_V2 = MODELS_DIR / "sentinel_xgb_v2.pkl"
MODEL_ENCODER_V2 = MODELS_DIR / "label_encoder_v2.pkl"
MODEL_FEATURES_V2 = MODELS_DIR / "feature_columns_v2.pkl"

MERGED_CLEAN_CSV = DATA_PROCESSED / "cic_lab_merged_clean.csv"

# Old database location (inside the checkout); copied to the data folder on first run.
LEGACY_DB_PATH = SOAR_DIR / "database" / "sentinel.db"


def database_path() -> Path:
    """SENTINEL_DB_PATH, else sentinel.db in the per-machine data folder (survives reinstalls)."""
    override = os.environ.get("SENTINEL_DB_PATH", "").strip()
    if override:
        return Path(override)
    from config.security import data_dir

    return data_dir() / "sentinel.db"


def runtime_dir(name: str, source_default: Path) -> Path:
    """Writable output folder: the repo folder in a checkout, the data folder in an installed build."""
    if not FROZEN:
        return source_default
    from config.security import data_dir

    path = data_dir() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


HIDS_LOG_DIR = runtime_dir("hids_logs", HIDS_DIR / "logs")
REPORTS_DIR = runtime_dir("reports", SOAR_DIR / "reports")

if not FROZEN:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
