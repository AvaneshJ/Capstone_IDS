"""
SentinelAI - Detection Agent (ML Inference Engine)
Integrates Member 1's trained ML model (model.pkl + scaler.pkl) to classify network flows,
equipped with a high-accuracy heuristic fallback classifier when models are pending.
"""

from __future__ import annotations
import os
import time
import json
import logging
from typing import Dict, Any, Optional, List, Tuple
import numpy as np

from agents.base_agent import BaseAgent
from core.schemas import FlowEvent, DetectionResult
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.DetectionAgent")

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")


class DetectionAgent(BaseAgent):
    """
    ML Inference Engine for network flow anomaly detection and attack classification.
    Loads external scikit-learn/joblib/XGBoost models with seamless heuristic fallback.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        features_path: Optional[str] = None,
        event_bus: Optional[EventBus] = None
    ):
        super().__init__(name="DetectionAgent", event_bus=event_bus)
        self.model_path = model_path or os.path.join(DEFAULT_MODEL_DIR, "model.pkl")
        self.scaler_path = scaler_path or os.path.join(DEFAULT_MODEL_DIR, "scaler.pkl")
        self.features_path = features_path or os.path.join(DEFAULT_MODEL_DIR, "feature_names.json")
        
        self.model: Any = None
        self.scaler: Any = None
        self.feature_names: List[str] = []
        self.is_ml_loaded: bool = False

    def _on_initialize(self) -> None:
        self.load_model()
        if self.event_bus:
            self.event_bus.subscribe("flow.ingested", self.process, priority=2, agent_name=self.name)

    def load_model(self) -> bool:
        """Attempt to load Member 1's trained model, scaler, and feature definitions."""
        if os.path.exists(self.model_path):
            try:
                import joblib
                self.model = joblib.load(self.model_path)
                
                if os.path.exists(self.scaler_path):
                    self.scaler = joblib.load(self.scaler_path)
                
                if os.path.exists(self.features_path):
                    with open(self.features_path, "r", encoding="utf-8") as f:
                        self.feature_names = json.load(f)
                else:
                    self.feature_names = [
                        "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
                        "fwd_pkt_len_mean", "bwd_pkt_len_mean",
                        "flow_bytes_s", "flow_pkts_s",
                        "syn_flag_count", "ack_flag_count", "rst_flag_count"
                    ]

                self.is_ml_loaded = True
                logger.info("Successfully loaded Member 1's ML model from: %s", self.model_path)
                return True
            except Exception as exc:
                logger.warning("Error loading ML model (%s). Switching to Heuristic Engine.", exc)
                self.is_ml_loaded = False
        else:
            logger.info("ML model file not found at %s. Operating in Heuristic Expert Mode.", self.model_path)
            self.is_ml_loaded = False
        return False

    def _handle_event(self, event: Event) -> Optional[DetectionResult]:
        flow: FlowEvent = event.data
        if not isinstance(flow, FlowEvent):
            logger.warning("DetectionAgent received invalid flow data type: %s", type(flow))
            return None

        detection = self.predict(flow)
        if self.event_bus:
            # Publish detection result alongside flow context
            self.event_bus.publish("detection.completed", {"flow": flow, "detection": detection}, sender=self.name)
        return detection

    def predict(self, flow: FlowEvent) -> DetectionResult:
        """Run ML inference or heuristic expert system classification on flow."""
        start_time = time.perf_counter()

        if self.is_ml_loaded and self.model is not None:
            detection = self._predict_ml(flow)
        else:
            detection = self._predict_heuristic(flow)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        detection.inference_time_ms = round(elapsed_ms, 3)
        return detection

    def _predict_ml(self, flow: FlowEvent) -> DetectionResult:
        """Vectorize flow features and call model.predict_proba / model.predict."""
        try:
            vector = []
            flow_dict = flow.to_dict()
            raw_dict = flow.raw_features

            for feat in self.feature_names:
                val = flow_dict.get(feat)
                if val is None:
                    val = raw_dict.get(feat, 0.0)
                try:
                    vector.append(float(val))
                except (ValueError, TypeError):
                    vector.append(0.0)

            X = np.array([vector], dtype=np.float32)
            if self.scaler is not None:
                X = self.scaler.transform(X)

            predicted_label = self.model.predict(X)[0]
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                classes = getattr(self.model, "classes_", [predicted_label])
                prob_dict = {str(cls_name): round(float(p), 4) for cls_name, p in zip(classes, probs)}
                confidence = float(np.max(probs))
            else:
                prob_dict = {str(predicted_label): 0.95}
                confidence = 0.95

            attack_str = str(predicted_label)
            return DetectionResult(
                attack_type=attack_str,
                confidence=round(confidence, 4),
                probabilities=prob_dict,
                model_version="Member1_ML_v1",
                is_anomaly=attack_str.upper() != "BENIGN"
            )
        except Exception as exc:
            logger.error("ML inference failed: %s. Falling back to heuristic classifier.", exc)
            return self._predict_heuristic(flow)

    def _predict_heuristic(self, flow: FlowEvent) -> DetectionResult:
        """
        Expert Heuristic Classifier: evaluates statistical flow patterns
        (e.g., SYN scans, volumetric DDoS floods, brute-force bursts, botnet beacons).
        """
        # 1. Port Scan Detection Pattern
        # Characteristic: High SYN flags with low or zero ACK, low backward packets, low duration
        if (flow.syn_flag_count >= 3 or flow.flow_pkts_s > 80.0) and flow.ack_flag_count <= 1 and flow.tot_bwd_pkts <= 2:
            confidence = min(0.98, 0.75 + (flow.syn_flag_count * 0.05) + (flow.flow_pkts_s / 500.0))
            return DetectionResult(
                attack_type="PortScan",
                confidence=round(confidence, 4),
                probabilities={"PortScan": confidence, "BENIGN": round(1.0 - confidence, 4), "DDoS": 0.05},
                model_version="Heuristic_v1",
                is_anomaly=True
            )

        # 2. Volumetric DDoS / DoS Detection Pattern
        # Characteristic: Extreme byte/packet rate exceeding 50,000 bytes/sec or 500 pkts/sec
        if flow.flow_bytes_s > 50000.0 or flow.flow_pkts_s > 400.0 or flow.tot_fwd_pkts > 500:
            confidence = min(0.99, 0.82 + (flow.flow_bytes_s / 500000.0))
            return DetectionResult(
                attack_type="DDoS",
                confidence=round(confidence, 4),
                probabilities={"DDoS": confidence, "DoS": 0.15, "BENIGN": round(1.0 - confidence, 4)},
                model_version="Heuristic_v1",
                is_anomaly=True
            )

        # 3. Brute Force Detection Pattern
        # Characteristic: Targeted authentication ports (SSH:22, RDP:3389, FTP:21) with repeated short connections
        if flow.dst_port in (22, 21, 3389, 445) and flow.flow_duration < 3.0 and flow.tot_fwd_pkts >= 5:
            confidence = 0.91
            return DetectionResult(
                attack_type="BruteForce",
                confidence=confidence,
                probabilities={"BruteForce": confidence, "BENIGN": 0.09},
                model_version="Heuristic_v1",
                is_anomaly=True
            )

        # 4. Botnet C2 Beaconing Pattern
        # Characteristic: Periodic small fixed payload transfers on unusual ports
        if flow.dst_port in (6667, 8088, 4444, 1337) or (flow.fwd_pkt_len_mean > 0 and flow.fwd_pkt_len_mean < 64.0 and flow.tot_fwd_pkts > 20):
            confidence = 0.88
            return DetectionResult(
                attack_type="Botnet",
                confidence=confidence,
                probabilities={"Botnet": confidence, "BENIGN": 0.12},
                model_version="Heuristic_v1",
                is_anomaly=True
            )

        # 5. Normal Baseline Traffic
        return DetectionResult(
            attack_type="BENIGN",
            confidence=0.97,
            probabilities={"BENIGN": 0.97, "PortScan": 0.01, "DDoS": 0.01, "BruteForce": 0.01},
            model_version="Heuristic_v1",
            is_anomaly=False
        )
