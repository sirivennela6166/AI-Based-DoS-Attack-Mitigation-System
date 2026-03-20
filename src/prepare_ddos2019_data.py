import pandas as pd

INPUT_PATH = "data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
OUTPUT_PATH = "data/ml_ready_ddos2019.csv"

CHUNK_SIZE = 100_000

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

print("Preparing ML-ready CIC-DDoS2019 dataset...")

for chunk in pd.read_csv(INPUT_PATH, chunksize=CHUNK_SIZE):
    # Normalize column names
    chunk.columns = chunk.columns.str.strip()

    # Keep required features + label
    chunk = chunk[FEATURES + ["Label"]]

    # Binary encoding
    chunk["label"] = chunk["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    chunk = chunk.drop(columns=["Label"])
    processed_chunks.append(chunk)

final_df = pd.concat(processed_chunks)

print("Final dataset shape:", final_df.shape)
print("Label distribution:")
print(final_df["label"].value_counts())

final_df.to_csv(OUTPUT_PATH, index=False)
print("Saved to:", OUTPUT_PATH)
