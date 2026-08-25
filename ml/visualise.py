from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
import matplotlib.pyplot as plt
from paths import CLEAN_CSV

df = pd.read_csv(CLEAN_CSV)

label = df["Label"].value_counts(normalize=True) * 100

plt.figure(figsize=(8, 5))
plt.bar(label.index, label.values)

plt.title("Distribution of Network Traffic Classes")
plt.xlabel("Traffic Class")
plt.ylabel("Percentage (%)")

for i, value in enumerate(label.values):
    plt.text(i, value, f"{value:.2f}%", ha="center", va="bottom")

plt.tight_layout()
plt.show()
