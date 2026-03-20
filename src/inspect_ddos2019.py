import pandas as pd

DATA_PATH = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

print("Inspecting CIC-DDoS2019 dataset (safe sample)...")

df = pd.read_csv(DATA_PATH, nrows=50_000)


df.columns = df.columns.str.strip()

print("\nSample shape:", df.shape)

print("\nColumn names:")
print(df.columns.tolist())

print("\nLabel distribution (sample):")
print(df["Label"].value_counts())

print("\nFirst 5 rows:")
print(df.head())
