from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from paths import CLEAN_CSV

LABELS = [0, 1, 2]

df = pd.read_csv(CLEAN_CSV)

y = df["Label"]
le = LabelEncoder()
y_encoded = le.fit_transform(y)

X = df.drop(columns=["Label", "Dst Port"])
print("X shape (no Dst Port):", X.shape)
print("Classes:", list(le.classes_))

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

dt = DecisionTreeClassifier(random_state=42)
dt.fit(X_train, y_train)

train_keys = pd.util.hash_pandas_object(X_train, index=False)
test_keys = pd.util.hash_pandas_object(X_test, index=False)
seen_in_train = test_keys.isin(set(train_keys))

X_test_unseen = X_test.loc[~seen_in_train]
y_test_unseen = y_test[~seen_in_train.to_numpy()]
y_pred_unseen = dt.predict(X_test_unseen)

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

y_pred = dt.predict(X_test)

print("\n========== EXPERIMENT A (no Dst Port, full test) ==========")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred, labels=LABELS))
print(classification_report(
    y_test, y_pred,
    labels=LABELS, target_names=le.classes_, zero_division=0
))

ports = df.loc[X_test.index, "Dst Port"].to_numpy()
y_pred_port = np.full(len(ports), le.transform(["Benign"])[0])
y_pred_port[ports == 21] = le.transform(["FTP-BruteForce"])[0]
y_pred_port[ports == 22] = le.transform(["SSH-Bruteforce"])[0]

print("\n========== EXPERIMENT C (port rule, full test) ==========")
print("Accuracy:", accuracy_score(y_test, y_pred_port))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_port, labels=LABELS))
print(classification_report(
    y_test, y_pred_port,
    labels=LABELS, target_names=le.classes_, zero_division=0
))
