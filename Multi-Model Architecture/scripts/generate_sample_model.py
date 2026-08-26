"""
SentinelAI - Sample Model Generator (Member 1 ML Contract Bridge)
Generates model.pkl, scaler.pkl, and feature_names.json using scikit-learn
trained on synthetic network flow telemetry for immediate testing.
"""

import os
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")


def generate_sample_model():
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    feature_names = [
        "flow_duration",
        "tot_fwd_pkts",
        "tot_bwd_pkts",
        "fwd_pkt_len_mean",
        "bwd_pkt_len_mean",
        "flow_bytes_s",
        "flow_pkts_s",
        "syn_flag_count",
        "ack_flag_count",
        "rst_flag_count"
    ]

    # Generate synthetic samples:
    # 0: BENIGN, 1: PortScan, 2: DDoS, 3: BruteForce, 4: Botnet
    X = []
    y = []

    # 1. BENIGN samples (100 samples)
    for _ in range(100):
        dur = np.random.uniform(1.0, 30.0)
        fwd_p = np.random.randint(5, 50)
        bwd_p = np.random.randint(5, 50)
        fwd_len = np.random.uniform(100, 1400)
        bwd_len = np.random.uniform(200, 1400)
        bytes_s = np.random.uniform(1000, 20000)
        pkts_s = np.random.uniform(5, 50)
        syn = np.random.randint(1, 2)
        ack = np.random.randint(1, 2)
        rst = 0
        X.append([dur, fwd_p, bwd_p, fwd_len, bwd_len, bytes_s, pkts_s, syn, ack, rst])
        y.append("BENIGN")

    # 2. PortScan samples (100 samples)
    for _ in range(100):
        dur = np.random.uniform(0.01, 0.5)
        fwd_p = np.random.randint(1, 5)
        bwd_p = np.random.randint(0, 1)
        fwd_len = np.random.uniform(0, 64)
        bwd_len = 0.0
        bytes_s = np.random.uniform(500, 5000)
        pkts_s = np.random.uniform(80, 500)
        syn = np.random.randint(3, 10)
        ack = 0
        rst = np.random.randint(0, 2)
        X.append([dur, fwd_p, bwd_p, fwd_len, bwd_len, bytes_s, pkts_s, syn, ack, rst])
        y.append("PortScan")

    # 3. DDoS samples (100 samples)
    for _ in range(100):
        dur = np.random.uniform(0.1, 5.0)
        fwd_p = np.random.randint(200, 2000)
        bwd_p = np.random.randint(0, 10)
        fwd_len = np.random.uniform(500, 1400)
        bwd_len = np.random.uniform(0, 100)
        bytes_s = np.random.uniform(80000, 5000000)
        pkts_s = np.random.uniform(500, 20000)
        syn = np.random.randint(10, 50)
        ack = np.random.randint(0, 5)
        rst = 0
        X.append([dur, fwd_p, bwd_p, fwd_len, bwd_len, bytes_s, pkts_s, syn, ack, rst])
        y.append("DDoS")

    # 4. BruteForce samples (100 samples)
    for _ in range(100):
        dur = np.random.uniform(0.5, 3.0)
        fwd_p = np.random.randint(10, 30)
        bwd_p = np.random.randint(5, 15)
        fwd_len = np.random.uniform(50, 200)
        bwd_len = np.random.uniform(50, 200)
        bytes_s = np.random.uniform(2000, 15000)
        pkts_s = np.random.uniform(20, 80)
        syn = np.random.randint(2, 5)
        ack = np.random.randint(2, 5)
        rst = np.random.randint(1, 3)
        X.append([dur, fwd_p, bwd_p, fwd_len, bwd_len, bytes_s, pkts_s, syn, ack, rst])
        y.append("BruteForce")

    # 5. Botnet samples (100 samples)
    for _ in range(100):
        dur = np.random.uniform(5.0, 60.0)
        fwd_p = np.random.randint(20, 100)
        bwd_p = np.random.randint(20, 100)
        fwd_len = np.random.uniform(32, 64)
        bwd_len = np.random.uniform(32, 64)
        bytes_s = np.random.uniform(500, 4000)
        pkts_s = np.random.uniform(5, 20)
        syn = 1
        ack = 1
        rst = 0
        X.append([dur, fwd_p, bwd_p, fwd_len, bwd_len, bytes_s, pkts_s, syn, ack, rst])
        y.append("Botnet")

    X = np.array(X, dtype=np.float32)
    y = np.array(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42)
    clf.fit(X_scaled, y)

    # Save artifacts
    model_path = os.path.join(MODELS_DIR, "model.pkl")
    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    features_path = os.path.join(MODELS_DIR, "feature_names.json")

    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    print(f"[+] Successfully generated sample ML artifacts:")
    print(f"    - Model:   {model_path}")
    print(f"    - Scaler:  {scaler_path}")
    print(f"    - Features:{features_path}")


if __name__ == "__main__":
    generate_sample_model()
