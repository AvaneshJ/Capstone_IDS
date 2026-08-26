"""
SentinelAI - Mock Traffic Generator (Member 2 Contract Bridge)
Generates high-fidelity synthetic network flow dictionaries for normal baseline traffic
and realistic cyberattack scenarios (SYN Port Scan, Volumetric DDoS, SSH Brute Force, Mirai Botnet).
"""

import time
import random
from typing import Dict, List, Any, Generator


def generate_benign_flow(
    src_ip: str = "192.168.1.105",
    dst_ip: str = "142.250.190.46",  # Google Web Server
    dst_port: int = 443
) -> Dict[str, Any]:
    """Generate typical HTTPS / Web browsing baseline traffic flow."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(49152, 65535),
        "dst_port": dst_port,
        "protocol": 6,  # TCP
        "flow_duration": round(random.uniform(1.5, 12.0), 3),
        "tot_fwd_pkts": random.randint(8, 30),
        "tot_bwd_pkts": random.randint(10, 45),
        "fwd_pkt_len_mean": round(random.uniform(200.0, 850.0), 2),
        "bwd_pkt_len_mean": round(random.uniform(500.0, 1400.0), 2),
        "flow_bytes_s": round(random.uniform(2000.0, 18000.0), 2),
        "flow_pkts_s": round(random.uniform(10.0, 45.0), 2),
        "syn_flag_count": 1,
        "ack_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": random.randint(2, 6),
        "fin_flag_count": 1,
        "timestamp": time.time()
    }


def generate_port_scan_flow(
    src_ip: str = "192.168.1.50",
    dst_ip: str = "192.168.1.10",
    target_port: int = 80
) -> Dict[str, Any]:
    """Generate fast SYN Port Scan probing flow across sequential ports."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(40000, 60000),
        "dst_port": target_port,
        "protocol": 6,  # TCP
        "flow_duration": round(random.uniform(0.01, 0.25), 4),
        "tot_fwd_pkts": random.randint(2, 6),
        "tot_bwd_pkts": 0,  # No response / dropped
        "fwd_pkt_len_mean": round(random.uniform(0.0, 44.0), 2),
        "bwd_pkt_len_mean": 0.0,
        "flow_bytes_s": round(random.uniform(1200.0, 4500.0), 2),
        "flow_pkts_s": round(random.uniform(120.0, 350.0), 2),
        "syn_flag_count": random.randint(3, 8),
        "ack_flag_count": 0,
        "rst_flag_count": random.randint(0, 1),
        "psh_flag_count": 0,
        "fin_flag_count": 0,
        "timestamp": time.time()
    }


def generate_ddos_flow(
    src_ip: str = "10.0.5.99",
    dst_ip: str = "192.168.1.10",
    target_port: int = 80
) -> Dict[str, Any]:
    """Generate overwhelming volumetric DDoS packet flood."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": target_port,
        "protocol": 6,  # TCP
        "flow_duration": round(random.uniform(0.5, 4.0), 3),
        "tot_fwd_pkts": random.randint(500, 3000),
        "tot_bwd_pkts": random.randint(0, 5),
        "fwd_pkt_len_mean": round(random.uniform(800.0, 1450.0), 2),
        "bwd_pkt_len_mean": round(random.uniform(0.0, 40.0), 2),
        "flow_bytes_s": round(random.uniform(150000.0, 2500000.0), 2),
        "flow_pkts_s": round(random.uniform(1000.0, 15000.0), 2),
        "syn_flag_count": random.randint(20, 100),
        "ack_flag_count": 0,
        "rst_flag_count": 0,
        "psh_flag_count": random.randint(10, 50),
        "fin_flag_count": 0,
        "timestamp": time.time()
    }


def generate_brute_force_flow(
    src_ip: str = "172.16.0.45",
    dst_ip: str = "192.168.1.10",
    target_port: int = 22  # SSH
) -> Dict[str, Any]:
    """Generate repeated authentication dictionary attack bursts on SSH/RDP."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(30000, 50000),
        "dst_port": target_port,
        "protocol": 6,  # TCP
        "flow_duration": round(random.uniform(0.8, 2.5), 3),
        "tot_fwd_pkts": random.randint(12, 35),
        "tot_bwd_pkts": random.randint(8, 20),
        "fwd_pkt_len_mean": round(random.uniform(80.0, 180.0), 2),
        "bwd_pkt_len_mean": round(random.uniform(60.0, 120.0), 2),
        "flow_bytes_s": round(random.uniform(4000.0, 15000.0), 2),
        "flow_pkts_s": round(random.uniform(30.0, 90.0), 2),
        "syn_flag_count": 2,
        "ack_flag_count": 2,
        "rst_flag_count": 1,
        "psh_flag_count": 4,
        "fin_flag_count": 1,
        "timestamp": time.time()
    }


def generate_botnet_flow(
    src_ip: str = "198.51.100.23",
    dst_ip: str = "192.168.1.10",
    target_port: int = 6667  # IRC / C2 Channel
) -> Dict[str, Any]:
    """Generate periodic C2 command-and-control beaconing packets."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 5000),
        "dst_port": target_port,
        "protocol": 6,
        "flow_duration": round(random.uniform(10.0, 45.0), 2),
        "tot_fwd_pkts": random.randint(25, 80),
        "tot_bwd_pkts": random.randint(25, 80),
        "fwd_pkt_len_mean": 48.0,  # Fixed uniform payload
        "bwd_pkt_len_mean": 48.0,
        "flow_bytes_s": round(random.uniform(800.0, 3000.0), 2),
        "flow_pkts_s": round(random.uniform(4.0, 15.0), 2),
        "syn_flag_count": 1,
        "ack_flag_count": 1,
        "rst_flag_count": 0,
        "psh_flag_count": 5,
        "fin_flag_count": 0,
        "timestamp": time.time()
    }


def generate_scenario_traffic() -> List[Dict[str, Any]]:
    """
    Generate a curated sequence of flows for demonstrations:
    1. Normal baseline browsing (5 flows)
    2. Rapid Port Scan sweep from 192.168.1.50 (10 flows)
    3. Volumetric DDoS attack from 10.0.5.99 (5 flows)
    4. Post-mitigation verification (2 flows)
    """
    flows = []
    
    # 1. Benign baseline
    for _ in range(5):
        flows.append(generate_benign_flow())

    # 2. Port Scan attack
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    for port in scan_ports[:10]:
        flows.append(generate_port_scan_flow(src_ip="192.168.1.50", target_port=port))

    # 3. Volumetric DDoS
    for _ in range(5):
        flows.append(generate_ddos_flow(src_ip="10.0.5.99", target_port=80))

    # 4. SSH Brute Force
    for _ in range(4):
        flows.append(generate_brute_force_flow(src_ip="172.16.0.45", target_port=22))

    return flows


if __name__ == "__main__":
    print("[*] Generating 5 sample synthetic flows...")
    sample_flows = generate_scenario_traffic()[:5]
    for i, f in enumerate(sample_flows, 1):
        print(f"[{i}] {f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']} | pkts/s={f['flow_pkts_s']} | bytes/s={f['flow_bytes_s']}")
