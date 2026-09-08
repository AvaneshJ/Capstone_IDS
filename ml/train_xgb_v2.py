from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
from paths import CLEAN_CSV, MODELS_DIR
from sklearn.utils.class_weight import compute_sample_weight

MODEL_XGB = MODELS_DIR / "sentinel_xgb_v2.pkl"
MODEL_ENCODER = MODELS_DIR / "label_encoder_v2.pkl"
MODEL_FEATURES = MODELS_DIR / "feature_columns_v2.pkl"



LABELS = [0, 1, 2, 3, 4, 5]

df = pd.read_csv(CLEAN_CSV)

y = df["Label"]
le = LabelEncoder()
y_encoded = le.fit_transform(y)

X = df.drop(columns=["Label", "Dst Port"],errors="ignore")
print("X shape (no Dst Port):", X.shape)
print("Classes:", list(le.classes_))

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)
sample_weight = compute_sample_weight(class_weight="balanced", y=y_train)

xgb = XGBClassifier(random_state=42,n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, eval_metric="mlogloss")
xgb.fit(X_train, y_train, sample_weight=sample_weight)

train_keys = pd.util.hash_pandas_object(X_train, index=False)
test_keys = pd.util.hash_pandas_object(X_test, index=False)
seen_in_train = test_keys.isin(set(train_keys))

X_test_unseen = X_test.loc[~seen_in_train]
y_test_unseen = y_test[~seen_in_train.to_numpy()]
y_pred_unseen = xgb.predict(X_test_unseen)

print("\n========== EXPERIMENT B (no Dst Port, unseen test) ==========")
print("Overlapping test rows:", int(seen_in_train.sum()), "/", len(X_test))
print("Unseen test size:", X_test_unseen.shape)
print("Unseen class counts:")
print(pd.Series(y_test_unseen).value_counts().sort_index())
print("Accuracy:", accuracy_score(y_test_unseen, y_pred_unseen))
print("Confusion Matrix:\n", confusion_matrix(y_test_unseen, y_pred_unseen, labels=LABELS))
print(classification_report(
    y_test_unseen, y_pred_unseen,
    labels=LABELS, target_names=le.classes_, zero_division=0
))

y_pred = xgb.predict(X_test)

print("\n========== EXPERIMENT A (no Dst Port, full test) ==========")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred, labels=LABELS))
print(classification_report(
    y_test, y_pred,
    labels=LABELS, target_names=le.classes_, zero_division=0
))

joblib.dump(xgb, MODEL_XGB)
joblib.dump(le, MODEL_ENCODER)
joblib.dump(list(X.columns), MODEL_FEATURES)

print("Saved:")
print(MODEL_XGB)
print(MODEL_ENCODER)
print(MODEL_FEATURES)
print("n_features:", len(X.columns))
