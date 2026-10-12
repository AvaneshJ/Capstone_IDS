"""
CIC XGBoost adapter — Phase-1 NIDS artefacts → Detection Agent.

Loads Capstone/models/ via config.paths (active = v3 lab package):
  - sentinel_xgb_v3.pkl
  - label_encoder_v3.pkl
  - feature_columns_v3.pkl  (77 CIC names, no Dst Port)
  v2 CIC baseline files remain available as *_v2.pkl.

Does NOT require scaler.pkl (tree models).
Does NOT feed Dst Port into the model; optional dst_port only applies a post-hoc override
for DoS ↔ FTP/SSH confusion.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

# Capstone root on path for config.paths
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.integrity import load_verified
from config.paths import MODEL_ENCODER, MODEL_FEATURES, MODEL_XGB

_AMBIGUOUS_PORT_LABELS = frozenset({"DoS", "FTP-BruteForce", "SSH-Bruteforce"})


class CicXgbAdapter:
    """Thin inference wrapper around the CSE-CIC-IDS2018-style 6-class XGBoost model."""

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
        self._classes: List[str] = []
        self.is_loaded: bool = False

    def load(self) -> bool:
        missing = [p for p in (self.model_path, self.encoder_path, self.features_path) if not p.exists()]
        if missing:
            raise FileNotFoundError(
                "Missing Phase-1 model artefacts: " + ", ".join(str(p) for p in missing)
            )

        self.model = load_verified(self.model_path)
        self.label_encoder = load_verified(self.encoder_path)
        self.feature_names = list(load_verified(self.features_path))
        if len(self.feature_names) != 77:
            raise ValueError(
                f"Expected 77 feature columns (no Dst Port); got {len(self.feature_names)}"
            )
        # One row per call: a multi-threaded predict costs more in thread wake-ups than it saves.
        if hasattr(self.model, "set_params"):
            try:
                self.model.set_params(n_jobs=1)
            except Exception:
                pass
        self._classes = [str(c) for c in self.label_encoder.classes_]
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

    @staticmethod
    def apply_port_override(label: str, dst_port: Optional[Union[int, float, str]]) -> str:
        """
        Hybrid post-process: resolve DoS ↔ brute-force swaps using destination port.

        Port is never a model feature — only used when the ML label is already in the
        ambiguous DoS / FTP / SSH set. Benign and other attacks are left unchanged.
        """
        if dst_port is None or label not in _AMBIGUOUS_PORT_LABELS:
            return label
        try:
            port = int(float(dst_port))
        except (TypeError, ValueError):
            return label

        if port == 21 and label in {"DoS", "FTP-BruteForce"}:
            return "FTP-BruteForce"
        if port == 22 and label in {"DoS", "SSH-Bruteforce"}:
            return "SSH-Bruteforce"
        return label

    def predict(
        self,
        raw_features: Dict[str, Any],
        dst_port: Optional[Union[int, float, str]] = None,
    ) -> Tuple[str, float, Dict[str, float]]:
        """
        Returns (label_name, confidence, probability_dict).
        Labels: Benign | Botnet | DDoS | DoS | FTP-BruteForce | PortScan | SSH-Bruteforce (v3 CIC+lab)

        If dst_port is omitted, tries raw_features["Dst Port"] / ["dst_port"] for the
        hybrid override only (still excluded from the 77-dim vector).
        """
        if not self.is_loaded:
            self.load()

        X = self.vectorize(raw_features)
        # multi:softprob: predict() is argmax(predict_proba()), so one call gives both.
        probs = self.model.predict_proba(X)[0]
        pred_id = int(np.argmax(probs))
        classes = getattr(self, "_classes", None) or [str(c) for c in self.label_encoder.classes_]
        label = classes[pred_id]
        prob_dict = {name: round(float(p), 4) for name, p in zip(classes, probs)}
        confidence = float(probs[pred_id])

        if dst_port is None:
            dst_port = raw_features.get("Dst Port", raw_features.get("dst_port"))
        label = self.apply_port_override(label, dst_port)

        return label, confidence, prob_dict

    @staticmethod
    def is_benign(label: str) -> bool:
        return str(label).strip().lower() == "benign"
