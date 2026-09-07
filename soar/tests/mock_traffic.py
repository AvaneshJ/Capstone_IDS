"""
Synthetic / lab flow generators for demos.

Short-schema fields feed heuristics; attach `raw_features` (77 CIC keys) when
testing the real Phase-1 XGBoost via CicXgbAdapter.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict, List, Optional


def _base_flow(**overrides: Any) -> Dict[str, Any]:
    flow = {
        "src_ip": "192.168.56.101",
        "dst_ip": "192.168.56.1",
        "src_port": random.randint(40000, 60000),
        "dst_port": 443,
        "protocol": 6,
        "flow_duration": 0.45,
        "tot_fwd_pkts": 8,
        "tot_bwd_pkts": 7,
        "fwd_pkt_len_mean": 120.0,
        "bwd_pkt_len_mean": 400.0,
        "flow_bytes_s": 3500.0,
        "flow_pkts_s": 30.0,
        "syn_flag_count": 1,
        "ack_flag_count": 6,
        "rst_flag_count": 0,
        "psh_flag_count": 2,
        "fin_flag_count": 1,
        "timestamp": time.time(),
        "raw_features": {},
    }
    flow.update(overrides)
    return flow


def generate_benign_flow(src_ip: str = "192.168.1.100", dst_port: int = 443) -> Dict[str, Any]:
    return _base_flow(src_ip=src_ip, dst_port=dst_port, flow_pkts_s=20.0, syn_flag_count=1)


def generate_port_scan_flow(src_ip: str = "192.168.56.101", dst_port: int = 22) -> Dict[str, Any]:
    return _base_flow(
        src_ip=src_ip,
        dst_port=dst_port,
        flow_duration=0.05,
        tot_fwd_pkts=12,
        tot_bwd_pkts=0,
        flow_pkts_s=200.0,
        syn_flag_count=12,
        ack_flag_count=0,
        fin_flag_count=0,
    )


def generate_ddos_flow(src_ip: str = "192.168.56.50") -> Dict[str, Any]:
    return _base_flow(
        src_ip=src_ip,
        dst_port=80,
        tot_fwd_pkts=800,
        flow_bytes_s=120000.0,
        flow_pkts_s=600.0,
    )


def generate_brute_force_flow(
    src_ip: str = "192.168.56.101",
    dst_port: int = 22,
) -> Dict[str, Any]:
    return _base_flow(
        src_ip=src_ip,
        dst_port=dst_port,
        flow_duration=1.2,
        tot_fwd_pkts=18,
        tot_bwd_pkts=4,
        flow_pkts_s=15.0,
        syn_flag_count=2,
        ack_flag_count=10,
    )


def attach_cic_raw_features(flow: Dict[str, Any], raw_features: Dict[str, Any]) -> Dict[str, Any]:
    """Attach full 77-column CIC dict so Detection Agent uses real XGBoost."""
    enriched = dict(flow)
    enriched["raw_features"] = raw_features
    return enriched


def generate_scenario_traffic() -> List[Dict[str, Any]]:
    return [
        generate_benign_flow(),
        generate_benign_flow(src_ip="192.168.1.101", dst_port=80),
        generate_port_scan_flow(),
        generate_brute_force_flow(dst_port=22),
        generate_brute_force_flow(dst_port=21),
        generate_ddos_flow(),
    ]
