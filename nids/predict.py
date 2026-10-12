import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from config.integrity import load_verified
from config.paths import MODEL_ENCODER, MODEL_XGB

model = load_verified(MODEL_XGB)
le = load_verified(MODEL_ENCODER)

df = pd.read_csv("data/lab/ssh_attacks.csv")

COLUMN_MAP = {
    "Total Fwd Packet":"Tot Fwd Pkts",
    "Total Bwd packets":"Tot Bwd Pkts",
    "Total Length of Fwd Packet":"TotLen Fwd Pkts",
    "Total Length of Bwd Packet":"TotLen Bwd Pkts",
    "Fwd Packet Length Max":"Fwd Pkt Len Max",
    "Fwd Packet Length Min":"Fwd Pkt Len Min",
    "Fwd Packet Length Mean":"Fwd Pkt Len Mean",
    "Fwd Packet Length Std":"Fwd Pkt Len Std",
    "Bwd Packet Length Max":"Bwd Pkt Len Max",
    "Bwd Packet Length Min":"Bwd Pkt Len Min",
    "Bwd Packet Length Mean":"Bwd Pkt Len Mean",
    "Bwd Packet Length Std":"Bwd Pkt Len Std",
    "Flow Bytes/s":"Flow Byts/s",
    "Flow Packets/s":"Flow Pkts/s",
    "Fwd IAT Total":"Fwd IAT Tot",
    "Bwd IAT Total":"Bwd IAT Tot",
    "Fwd Header Length":"Fwd Header Len",
    "Bwd Header Length":"Bwd Header Len",
    "Fwd Packets/s":"Fwd Pkts/s",
    "Bwd Packets/s":"Bwd Pkts/s",
    "Packet Length Min":"Pkt Len Min",
    "Packet Length Max":"Pkt Len Max",
    "Packet Length Mean":"Pkt Len Mean",
    "Packet Length Std":"Pkt Len Std",
    "Packet Length Variance":"Pkt Len Var",
    "FIN Flag Count":"FIN Flag Cnt",
    "SYN Flag Count":"SYN Flag Cnt",
    "RST Flag Count":"RST Flag Cnt",
    "PSH Flag Count":"PSH Flag Cnt",
    "ACK Flag Count":"ACK Flag Cnt",
    "URG Flag Count":"URG Flag Cnt",
    "CWR Flag Count":"CWE Flag Count",
    "ECE Flag Count":"ECE Flag Cnt",
    "Average Packet Size":"Pkt Size Avg",
    "Fwd Segment Size Avg":"Fwd Seg Size Avg",
    "Bwd Segment Size Avg":"Bwd Seg Size Avg",
    "Fwd Bytes/Bulk Avg":"Fwd Byts/b Avg",
    "Fwd Packet/Bulk Avg":"Fwd Pkts/b Avg",
    "Fwd Bulk Rate Avg":"Fwd Blk Rate Avg",
    "Bwd Bytes/Bulk Avg":"Bwd Byts/b Avg",
    "Bwd Packet/Bulk Avg":"Bwd Pkts/b Avg",
    "Bwd Bulk Rate Avg":"Bwd Blk Rate Avg",
    "Subflow Fwd Packets":"Subflow Fwd Pkts",
    "Subflow Fwd Bytes":"Subflow Fwd Byts",
    "Subflow Bwd Packets":"Subflow Bwd Pkts",
    "Subflow Bwd Bytes":"Subflow Bwd Byts",
    "FWD Init Win Bytes":"Init Fwd Win Byts",
    "Bwd Init Win Bytes":"Init Bwd Win Byts",
}

df = df.rename(columns=COLUMN_MAP)

drop_cols = [
    "Flow ID","Src IP","Dst IP","Timestamp",
    "Label","Src Port","Dst Port"
]

X = df.drop(columns=[c for c in drop_cols if c in df.columns])

# Exact order used during training
X = X[model.feature_names_in_]
print("Expected features:", len(model.feature_names_in_))
print("Input features:", len(X.columns))
print((X.columns == model.feature_names_in_).all())

proba = model.predict_proba(X)

labels = le.inverse_transform(range(len(le.classes_)))

for i, p in enumerate(proba):
    print(f"\nFlow {i+1}")
    for lbl, score in zip(labels, p):
        print(f"{lbl:18} {score:.3f}")

pred = model.predict(X).astype(int)
df["Prediction"] = le.inverse_transform(pred)

print(df[["Src IP","Dst IP","Dst Port","Prediction"]])