from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from paths import CLEAN_CSV

df = pd.read_csv(CLEAN_CSV)

print("=" * 60)
print("CHECK 1: Dst Port vs Label")
print("=" * 60)
print(pd.crosstab(df["Dst Port"], df["Label"]).sort_values("Benign", ascending=False).head(10))

print("\nPort 21 / 22 breakdown:")
for p in [21, 22]:
    sub = df[df["Dst Port"] == p]["Label"].value_counts()
    print(f"\nDst Port {p} (total {len(df[df['Dst Port']==p])}):")
    print(sub)

print("\nLabel counts where Dst Port NOT in (21,22):")
print(df[~df["Dst Port"].isin([21, 22])]["Label"].value_counts())

print("\n" + "=" * 60)
print("CHECK 2: duplicate rows shared between train and test")
print("=" * 60)

X = df.drop(columns=["Label"])
y = LabelEncoder().fit_transform(df["Label"])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

train_keys = pd.util.hash_pandas_object(X_train, index=False)
test_keys = pd.util.hash_pandas_object(X_test, index=False)

overlap = test_keys.isin(set(train_keys))
print(f"Test rows whose feature vector also appears in train: {overlap.sum()} / {len(test_keys)}")
print(f"Percentage: {overlap.mean() * 100:.2f}%")

print("\nOverlap by true class:")
print(pd.Series(y_test)[overlap.values].value_counts().sort_index())
print("\nTotal per class in test:")
print(pd.Series(y_test).value_counts().sort_index())
