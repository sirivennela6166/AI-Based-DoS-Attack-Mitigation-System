import pandas as pd

DATA_PATH = "data/cicids2017_cleaned.csv"

print("Inspecting dataset safely (using sample)...")

# Load only a sample to avoid memory issues
df_sample = pd.read_csv(DATA_PATH, nrows=50_000)

print("\nSample shape:", df_sample.shape)

print("\nColumn names:")
print(df_sample.columns.tolist())

print("\nAttack Type distribution (sample):")
print(df_sample['Attack Type'].value_counts())

print("\nFirst 5 rows:")
print(df_sample.head())

