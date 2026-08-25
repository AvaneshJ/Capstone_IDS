from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
import numpy as np
from paths import RAW_CSV, CLEAN_CSV

df = pd.read_csv(RAW_CSV)

print("=" * 60)
print("PREPROCESSING STARTED")
print("=" * 60)

print(f"Original Shape : {df.shape}")

df = df.replace([np.inf, -np.inf], np.nan)

rows_with_nan = df[df.isnull().any(axis=1)].shape[0]

print(f"\nRows containing NaN : {rows_with_nan}")
print(f"Percentage : {(rows_with_nan/len(df))*100:.4f}%")

df = df.dropna()

print(f"\nShape after removing NaN rows : {df.shape}")

df = df.drop(columns=["Timestamp"])

print(f"\nShape after removing Timestamp : {df.shape}")

print("\nRemaining Missing Values")
print(df.isnull().sum().sum())

print("\nRemaining Infinite Values")
print(np.isinf(df.select_dtypes(include=[np.number])).sum().sum())

print("\nFinal Shape")
print(df.shape)

CLEAN_CSV.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(CLEAN_CSV, index=False)

print(f"\nClean dataset saved as {CLEAN_CSV}")

print("\nFinal Class Distribution")
print(df["Label"].value_counts())

print("\nFinal Class Distribution (%)")
print((df["Label"].value_counts(normalize=True) * 100).round(2))

print("\nPREPROCESSING COMPLETED")
