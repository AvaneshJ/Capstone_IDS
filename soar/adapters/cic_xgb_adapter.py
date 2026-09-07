"""
CIC XGBoost adapter — Phase-1 NIDS artefacts → Detection Agent.

Loads Capstone/models/:
  - sentinel_xgb.pkl
  - label_encoder.pkl
  - feature_columns.pkl  (77 CIC names, no Dst Port)

Does NOT require scaler.pkl (tree models).
Does NOT retrain to match the short sample-feature contract.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Capstone root on path for config.paths
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.paths import MODEL_ENCODER, MODEL_FEATURES, MODEL_XGB  # noqa: E402


class CicXgbAdapter:
    """Thin inference wrapper around the CSE-CIC-IDS2018-style 3-class XGBoost model."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        encoder_path: Optional[Path] = None,
        features_path: Optional[Path] = None,
    ) -> None:
        self.model_path = Path(model_path) if model_path else MODEL_XGB
        self.encoder_path = Path(encoder_path) if encoder_path else MODEL_ENCODER
        self.features_path = Path(features_path) if features_path else MODEL_FEATURES

        self.model: Any = None
        self.label_encoder: Any = None
        self.feature_names: List[str] = []
        self.is_loaded: bool = False

    def load(self) -> bool:
        import joblib

        missing = [p for p in (self.model_path, self.encoder_path, self.features_path) if not p.exists()]
        if missing:
            raise FileNotFoundError(
                "Missing Phase-1 model artefacts: " + ", ".join(str(p) for p in missing)
            )

        self.model = joblib.load(self.model_path)
        self.label_encoder = joblib.load(self.encoder_path)
        self.feature_names = list(joblib.load(self.features_path))
        if len(self.feature_names) != 77:
            raise ValueError(
                f"Expected 77 feature columns (no Dst Port); got {len(self.feature_names)}"
            )
        self.is_loaded = True
        return True

    def vectorize(self, raw_features: Dict[str, Any]) -> np.ndarray:
        """Build shape (1, 77) in training column order. Missing keys → 0.0."""
        if not self.is_loaded:
            self.load()

        vector: List[float] = []
        for name in self.feature_names:
            val = raw_features.get(name, 0.0)
            try:
                if val is None:
                    vector.append(0.0)
                else:
                    f = float(val)
                    if f != f or f in (float("inf"), float("-inf")):  # NaN / inf
                        vector.append(0.0)
                    else:
                        vector.append(f)
            except (TypeError, ValueError):
                vector.append(0.0)
        return np.asarray([vector], dtype=np.float32)

    def predict(self, raw_features: Dict[str, Any]) -> Tuple[str, float, Dict[str, float]]:
        """
        Returns (label_name, confidence, probability_dict).
        Labels: Benign | FTP-BruteForce | SSH-Bruteforce
        """
        if not self.is_loaded:
            self.load()

        X = self.vectorize(raw_features)
        pred_id = int(self.model.predict(X)[0])
        label = str(self.label_encoder.inverse_transform([pred_id])[0])

        probs = self.model.predict_proba(X)[0]
        classes = [str(c) for c in self.label_encoder.classes_]
        prob_dict = {name: round(float(p), 4) for name, p in zip(classes, probs)}
        confidence = float(max(probs))
        return label, confidence, prob_dict

    @staticmethod
    def is_benign(label: str) -> bool:
        return str(label).strip().lower() == "benign"
