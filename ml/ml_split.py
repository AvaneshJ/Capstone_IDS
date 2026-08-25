from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from paths import CLEAN_CSV

df = pd.read_csv(CLEAN_CSV)
print("Shape:", df.shape)

x = df.drop(columns=["Label"])
y = df["Label"]

print("X:", x.shape, "| y:", y.shape)
print("\nOriginal Labels:\n", y.value_counts())

le = LabelEncoder()
y_encoded = le.fit_transform(y)

print("\nClasses:", list(le.classes_))
print("Encoded counts:\n", pd.Series(y_encoded).value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    x, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print("\nX_train:", X_train.shape, "| X_test:", X_test.shape)
print("\nTrain %:\n", pd.Series(y_train).value_counts(normalize=True).sort_index() * 100)
print("\nTest %:\n", pd.Series(y_test).value_counts(normalize=True).sort_index() * 100)
