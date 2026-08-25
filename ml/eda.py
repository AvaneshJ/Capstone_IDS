from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
import numpy as np
from paths import RAW_CSV

df = pd.read_csv(RAW_CSV)

print("=" * 60)
print("DATASET INFORMATION")
print("=" * 60)

print("\nShape:")
print(df.shape)

print("\nColumn Names:")
print(df.columns.tolist())

print("\nData Types:")
print(df.dtypes)

print("\nMemory Usage:")
print(df.memory_usage(deep=True).sum() / (1024**2), "MB")

print("\n" + "=" * 60)
print("MISSING VALUES")
print("=" * 60)

print(df.isnull().sum())

print("\n" + "=" * 60)
print("INFINITE VALUES")
print("=" * 60)

numeric_df = df.select_dtypes(include=[np.number])

print(np.isinf(numeric_df).sum())

print("\n" + "=" * 60)
print("DUPLICATE ROWS")
print("=" * 60)

duplicates = df.duplicated().sum()

print("Duplicate Rows:", duplicates)
print("Duplicate Percentage:",
      duplicates / len(df) * 100)

print("\n" + "=" * 60)
print("TARGET DISTRIBUTION")
print("=" * 60)

print(df["Label"].value_counts())

print("\nPercentage:")

print(df["Label"].value_counts(normalize=True) * 100)

print("\n" + "=" * 60)
print("STATISTICAL SUMMARY")
print("=" * 60)

print(df.describe())
