"""
Feature bridge: raw flow stats → 77 CIC columns (Phase-1 contract).

Live exporters (CICFlowMeter / custom Scapy aggregator) should call
`to_cic_raw_features()` so Detection Agent / CicXgbAdapter get the right keys.

This MVP:
- Accepts a dict with CIC names or common aliases
- Fills missing columns with 0.0
- Never invents Dst Port (model trained without it)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config.paths import MODEL_FEATURES

# Common exporter / short-schema → CIC name
ALIASES: Dict[str, str] = {
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Tot Fwd Pkts",
    "tot_bwd_pkts": "Tot Bwd Pkts",
    "fwd_pkt_len_mean": "Fwd Pkt Len Mean",
    "bwd_pkt_len_mean": "Bwd Pkt Len Mean",
    "flow_bytes_s": "Flow Byts/s",
    "flow_byts_s": "Flow Byts/s",
    "flow_pkts_s": "Flow Pkts/s",
    "syn_flag_count": "SYN Flag Cnt",
    "ack_flag_count": "ACK Flag Cnt",
    "rst_flag_count": "RST Flag Cnt",
    "psh_flag_count": "PSH Flag Cnt",
    "fin_flag_count": "FIN Flag Cnt",
    "protocol": "Protocol",
}


def load_feature_names() -> list:
    import joblib

    return list(joblib.load(MODEL_FEATURES))


def normalize_keys(partial: Mapping[str, Any]) -> Dict[str, Any]:
    """Rename known aliases to CIC names; leave already-correct names alone."""
    out: Dict[str, Any] = {}
    for key, val in partial.items():
        if key in ("Label", "Dst Port", "dst_port", "Timestamp"):
            continue  # excluded from Phase-1 model
        cic = ALIASES.get(key, key)
        out[cic] = val
    return out


def to_cic_raw_features(
    partial: Mapping[str, Any], feature_names: Optional[List[str]] = None
) -> Dict[str, float]:
    """
    Build a complete 77-key dict in training order.
    Missing features → 0.0 (document gaps in lab notes; do not silently claim 1:1 CICFlowMeter parity).
    """
    names = feature_names or load_feature_names()
    normalized = normalize_keys(partial)
    raw: Dict[str, float] = {}
    for name in names:
        val = normalized.get(name, 0.0)
        try:
            f = float(val) if val is not None else 0.0
            if f != f or f in (float("inf"), float("-inf")):
                f = 0.0
        except (TypeError, ValueError):
            f = 0.0
        raw[name] = f
    return raw


def csv_row_to_raw_features(row: Mapping[str, Any]) -> Dict[str, float]:
    """Convert one cic_clean.csv-style row (Series/dict) into adapter raw_features."""
    data = dict(row)
    data.pop("Label", None)
    data.pop("Dst Port", None)
    return to_cic_raw_features(data)
