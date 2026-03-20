import pandas as pd

INPUT_PATH = "data/dos_binary_dataset.csv"
OUTPUT_PATH = "data/ml_ready_dataset.csv"

CHUNK_SIZE = 200_000

# Selected features (DoS-relevant & lightweight)
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Packet Length Std",
    "ACK Flag Count",
    "PSH Flag Count",
    "Average Packet Size"
]

processed_chunks = []

print("Preparing ML-ready dataset...")

for chunk in pd.read_csv(INPUT_PATH, chunksize=CHUNK_SIZE):
    # Keep only required columns + label
    chunk = chunk[FEATURES + ["Attack Type"]]

    # Binary label encoding
    chunk["label"] = chunk["Attack Type"].apply(
        lambda x: 0 if x == "Normal Traffic" else 1
    )

    # Drop original label column
    chunk = chunk.drop(columns=["Attack Type"])

    processed_chunks.append(chunk)

print("Concatenating processed chunks...")
final_df = pd.concat(processed_chunks)

print("Final ML dataset shape:", final_df.shape)
print("Label distribution:")
print(final_df["label"].value_counts())

print("Saving ML-ready dataset...")
final_df.to_csv(OUTPUT_PATH, index=False)

print("Done. Saved to:", OUTPUT_PATH)
