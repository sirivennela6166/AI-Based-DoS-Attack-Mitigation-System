import pandas as pd

INPUT_PATH = "data/cicids2017_cleaned.csv"
OUTPUT_PATH = "data/dos_binary_dataset.csv"

CHUNK_SIZE = 100_000

dos_keywords = ["DoS", "DDoS", "Hulk", "Slowloris", "GoldenEye"]

filtered_chunks = []

print("Filtering dataset (Normal vs DoS)...")

for chunk in pd.read_csv(INPUT_PATH, chunksize=CHUNK_SIZE):
    # Keep Normal traffic
    normal = chunk[chunk["Attack Type"] == "Normal Traffic"]

    # Keep only DoS-related attacks
    dos = chunk[chunk["Attack Type"].str.contains(
        "|".join(dos_keywords),
        case=False,
        na=False
    )]

    filtered = pd.concat([normal, dos])

    if not filtered.empty:
        filtered_chunks.append(filtered)

print("Concatenating filtered data...")
final_df = pd.concat(filtered_chunks)

print("Final dataset shape:", final_df.shape)
print("Label distribution:")
print(final_df["Attack Type"].value_counts())

print("Saving filtered dataset...")
final_df.to_csv(OUTPUT_PATH, index=False)

print("Done. Saved to:", OUTPUT_PATH)
