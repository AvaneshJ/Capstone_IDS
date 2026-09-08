"""
SentinelAI - Detection Agent (ML Inference Engine)

Prefer Phase-1 CIC XGBoost via CicXgbAdapter (77 features, no scaler).
Falls back to heuristics only if artefacts are missing.
"""

from __future__ import annotations
import os
import sys
import time
import logging
from typing import Dict, Any, Optional
import numpy as np

from agents.base_agent import BaseAgent
from core.schemas import FlowEvent, DetectionResult
from core.event_bus import EventBus, Event

logger = logging.getLogger("SentinelAI.DetectionAgent")

# Capstone root for config + adapters
_SOAR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROOT = os.path.dirname(_SOAR_DIR)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from adapters.cic_xgb_adapter import CicXgbAdapter  # noqa: E402


class DetectionAgent(BaseAgent):
    """ML inference for network flows — real CIC XGBoost when available."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        features_path: Optional[str] = None,
        event_bus: Optional[EventBus] = None,
    ):
        super().__init__(name="DetectionAgent", event_bus=event_bus)
        # Optional overrides kept for CLI compatibility; adapter uses Capstone/models by default
        self._model_override = model_path
        self.scaler_path = scaler_path
        self.features_path = features_path

        self.adapter: Optional[CicXgbAdapter] = None
        self.is_ml_loaded: bool = False

    def _on_initialize(self) -> None:
        self.load_model()
        if self.event_bus:
            self.event_bus.subscribe("flow.ingested", self.process, priority=2, agent_name=self.name)

    def load_model(self) -> bool:
        """Load Capstone Phase-1 artefacts through CicXgbAdapter."""
        try:
            kwargs: Dict[str, Any] = {}
            if self._model_override:
                kwargs["model_path"] = self._model_override
            if self.features_path and str(self.features_path).endswith(".pkl"):
                kwargs["features_path"] = self.features_path

            self.adapter = CicXgbAdapter(**kwargs)
            self.adapter.load()
            self.is_ml_loaded = True
            logger.info(
                "Loaded CIC XGBoost adapter (%d features) from %s",
                len(self.adapter.feature_names),
                self.adapter.model_path,
            )
            return True
        except Exception as exc:
            logger.warning(
                "CIC XGBoost adapter unavailable (%s). Heuristic fallback active.",
                exc,
            )
            self.adapter = None
            self.is_ml_loaded = False
            return False

    def _handle_event(self, event: Event) -> Optional[DetectionResult]:
        flow: FlowEvent = event.data
        if not isinstance(flow, FlowEvent):
            logger.warning("DetectionAgent received invalid flow data type: %s", type(flow))
            return None

        detection = self.predict(flow)
        if self.event_bus:
            self.event_bus.publish(
                "detection.completed",
                {"flow": flow, "detection": detection},
                sender=self.name,
            )
        return detection

    def predict(self, flow: FlowEvent) -> DetectionResult:
        start_time = time.perf_counter()

        if self.is_ml_loaded and self.adapter is not None:
            detection = self._predict_ml(flow)
        else:
            detection = self._predict_heuristic(flow)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        detection.inference_time_ms = round(elapsed_ms, 3)
        return detection

    def _predict_ml(self, flow: FlowEvent) -> DetectionResult:
        """Prefer raw_features (full 77 CIC dict); merge short FlowEvent fields as fallbacks."""
        try:
            assert self.adapter is not None
            raw = dict(flow.raw_features or {})

            # Allow short schema keys only as last-resort fillers (not a substitute for 77 cols)
            short_aliases = {
                "Flow Duration": flow.flow_duration,
                "Tot Fwd Pkts": flow.tot_fwd_pkts,
                "Tot Bwd Pkts": flow.tot_bwd_pkts,
                "Fwd Pkt Len Mean": flow.fwd_pkt_len_mean,
                "Bwd Pkt Len Mean": flow.bwd_pkt_len_mean,
                "Flow Byts/s": flow.flow_bytes_s,
                "Flow Pkts/s": flow.flow_pkts_s,
                "SYN Flag Cnt": flow.syn_flag_count,
                "ACK Flag Cnt": flow.ack_flag_count,
                "RST Flag Cnt": flow.rst_flag_count,
                "PSH Flag Cnt": flow.psh_flag_count,
                "FIN Flag Cnt": flow.fin_flag_count,
                "Protocol": flow.protocol,
            }
            for cic_name, val in short_aliases.items():
                raw.setdefault(cic_name, val)

            # Model uses 77 CIC cols only; dst_port is a hybrid post-hoc override.
            label, confidence, prob_dict = self.adapter.predict(raw, dst_port=flow.dst_port)
            return DetectionResult(
                attack_type=label,
                confidence=round(confidence, 4),
                probabilities=prob_dict,
                model_version="CIC_XGB_Phase1_v1_hybrid",
                is_anomaly=not CicXgbAdapter.is_benign(label),
            )
        except Exception as exc:
            logger.error("ML inference failed: %s. Falling back to heuristic.", exc)
            return self._predict_heuristic(flow)

    def _predict_heuristic(self, flow: FlowEvent) -> DetectionResult:
        """Expert fallback when Phase-1 artefacts are missing."""
        if (flow.syn_flag_count >= 3 or flow.flow_pkts_s > 80.0) and flow.ack_flag_count <= 1 and flow.tot_bwd_pkts <= 2:
            confidence = min(0.98, 0.75 + (flow.syn_flag_count * 0.05) + (flow.flow_pkts_s / 500.0))
            return DetectionResult(
                attack_type="PortScan",
                confidence=round(confidence, 4),
                probabilities={"PortScan": confidence, "Benign": round(1.0 - confidence, 4)},
                model_version="Heuristic_v1",
                is_anomaly=True,
            )

        if flow.flow_bytes_s > 50000.0 or flow.flow_pkts_s > 400.0 or flow.tot_fwd_pkts > 500:
            confidence = min(0.99, 0.82 + (flow.flow_bytes_s / 500000.0))
            return DetectionResult(
                attack_type="DDoS",
                confidence=round(confidence, 4),
                probabilities={"DDoS": confidence, "Benign": round(1.0 - confidence, 4)},
                model_version="Heuristic_v1",
                is_anomaly=True,
            )

        if flow.dst_port in (22, 21, 3389, 445) and flow.flow_duration < 3.0 and flow.tot_fwd_pkts >= 5:
            label = "SSH-Bruteforce" if flow.dst_port == 22 else (
                "FTP-BruteForce" if flow.dst_port == 21 else "BruteForce"
            )
            confidence = 0.91
            return DetectionResult(
                attack_type=label,
                confidence=confidence,
                probabilities={label: confidence, "Benign": 0.09},
                model_version="Heuristic_v1",
                is_anomaly=True,
            )

        return DetectionResult(
            attack_type="Benign",
            confidence=0.97,
            probabilities={"Benign": 0.97},
            model_version="Heuristic_v1",
            is_anomaly=False,
        )
