import pandas as pd
import numpy as np
import joblib
import subprocess
from datetime import datetime

# =======================
# CONFIGURATION
# =======================

MODEL_PATH = "models/rf_dos_model.pkl"
DATA_PATH = "data/ml_ready_dataset.csv"   # CICIDS2017
LOG_PATH = "logs/ai_mitigation_log.csv"

CONFIDENCE_THRESHOLD = 0.6
ATTACK_THRESHOLD = 5

ATTACKER_IP = "192.168.100.50"

# =======================
# LOAD MODEL
# =======================

print("Loading AI model...")
model = joblib.load(MODEL_PATH)

# =======================
# LOAD DATA
# =======================

print("Loading CICIDS2017 dataset...")
df = pd.read_csv(DATA_PATH)

# Separate benign and attack flows
benign_df = df[df["label"] == 0].sample(n=2000, random_state=42)
attack_df = df[df["label"] == 1].sample(n=500, random_state=42)

# Combine them
demo_df = pd.concat([benign_df, attack_df]).reset_index(drop=True)

X = demo_df.drop(columns=["label"])
y = demo_df["label"]

# Clean data
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# =======================
# RUN DETECTION
# =======================

print("Running AI detection...")
predictions = model.predict(X)
probabilities = model.predict_proba(X)

attack_counter = {}
blocked_ips = set()
logs = []

for i in range(len(predictions)):

    pred = predictions[i]
    confidence = probabilities[i][1]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Assign IP
    if y.iloc[i] == 1:
        source_ip = ATTACKER_IP
    else:
        source_ip = f"192.168.1.{i % 200 + 1}"

    action = "NO_ACTION"

    if pred == 1 and confidence >= CONFIDENCE_THRESHOLD:

        attack_counter[source_ip] = attack_counter.get(source_ip, 0) + 1

        if attack_counter[source_ip] >= ATTACK_THRESHOLD:

            action = "HARD_BLOCK"

            if source_ip not in blocked_ips:
                print(f"[MITIGATION] Blocking IP {source_ip} "
                      f"(detections={attack_counter[source_ip]})")

                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

                blocked_ips.add(source_ip)

        else:
            action = "SOFT_MITIGATION"

    logs.append({
        "timestamp": timestamp,
        "flow_id": i,
        "source_ip": source_ip,
        "actual_label": int(y.iloc[i]),
        "prediction": int(pred),
        "confidence": round(confidence, 3),
        "detections_from_ip": attack_counter.get(source_ip, 0),
        "action": action
    })

log_df = pd.DataFrame(logs)
log_df.to_csv(LOG_PATH, index=False)

print("AI-based mitigation complete.")
print(f"Blocked IPs: {blocked_ips}")

