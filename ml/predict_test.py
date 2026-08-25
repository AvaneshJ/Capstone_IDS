from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd 
import joblib
from paths import CLEAN_CSV, MODEL_XGB, MODEL_ENCODER, MODEL_FEATURES

model=joblib.load(MODEL_XGB)
le=joblib.load(MODEL_ENCODER)
features=joblib.load(MODEL_FEATURES)

print("Classes:", list(le.classes_))
print("n_Features:", len(features))

df=pd.read_csv(CLEAN_CSV)
row=df.iloc[[0]]
row=row.drop(columns=["Label","Dst Port"], errors="ignore")
row=row[features]

pred_id=model.predict(row)[0]
pred_name=le.inverse_transform([pred_id])[0]
proba=model.predict_proba(row)[0]
confidence=float(proba.max())

print("True label:", df.iloc[0]["Label"])   # only because this test row came from the CSV
print("Predicted:", pred_name)
print("Confidence:", round(confidence * 100, 2), "%")
print("All class probabilities:")
for name, p in zip(le.classes_, proba):
    print(f"  {name}: {p:.4f}")