import pyshark
import pandas as pd
import numpy as np
import joblib
import subprocess
import time
from collections import defaultdict
import warnings

warnings.filterwarnings("ignore")

INTERFACE = "enp0s3"
WINDOW_TIME = 5

# 🔥 Threshold for guaranteed demo detection
PACKET_RATE_THRESHOLD = 50   # packets per second

print("Loading AI model...")
model = joblib.load("models/rf_dos_model.pkl")
FEATURE_NAMES = list(model.feature_names_in_)

print("Starting live packet capture on", INTERFACE)

capture = pyshark.LiveCapture(interface=INTERFACE)

ip_stats = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "ack_count": 0,
    "psh_count": 0,
    "packet_sizes": [],
    "start_time": time.time()
})

blocked_ips = set()

def block_ip(ip):
    if ip not in blocked_ips:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        blocked_ips.add(ip)
        print(f"\n🚨 [MITIGATION] Blocking IP {ip}\n")

window_start = time.time()

try:
    for packet in capture.sniff_continuously():

        if 'IP' not in packet:
            continue

        src_ip = packet.ip.src
        length = int(packet.length)

        stats = ip_stats[src_ip]
        stats["packet_count"] += 1
        stats["byte_count"] += length
        stats["packet_sizes"].append(length)

        if 'TCP' in packet:
            if hasattr(packet.tcp, "flags_ack") and packet.tcp.flags_ack == "1":
                stats["ack_count"] += 1
            if hasattr(packet.tcp, "flags_push") and packet.tcp.flags_push == "1":
                stats["psh_count"] += 1

        if time.time() - window_start >= WINDOW_TIME:

            print("\n==============================")
            print("Evaluating traffic window...")
            print("==============================")

            for ip, stats in ip_stats.items():

                duration = time.time() - stats["start_time"]
                if duration <= 0:
                    continue

                packet_rate = stats["packet_count"] / duration
                byte_rate = stats["byte_count"] / duration

                packet_mean = np.mean(stats["packet_sizes"]) if stats["packet_sizes"] else 0
                packet_std = np.std(stats["packet_sizes"]) if stats["packet_sizes"] else 0

                # 🔥 HARD THRESHOLD CHECK
                if packet_rate > PACKET_RATE_THRESHOLD:
                    print(f"[THRESHOLD ATTACK] {ip} (rate={packet_rate:.2f} pps)")
                    block_ip(ip)
                    continue

                # ML CHECK
                feature_values = {
                    'Flow Duration': duration,
                    'Total Fwd Packets': stats["packet_count"],
                    'Total Length of Fwd Packets': stats["byte_count"],
                    'Flow Bytes/s': byte_rate,
                    'Flow Packets/s': packet_rate,
                    'Fwd Packet Length Mean': packet_mean,
                    'Bwd Packet Length Mean': 0,
                    'Packet Length Mean': packet_mean,
                    'Packet Length Std': packet_std,
                    'ACK Flag Count': stats["ack_count"],
                    'PSH Flag Count': stats["psh_count"],
                    'Average Packet Size': packet_mean
                }

                feature_df = pd.DataFrame([feature_values], columns=FEATURE_NAMES)

                pred = model.predict(feature_df)[0]
                confidence = model.predict_proba(feature_df)[0][1]

                if pred == 1:
                    print(f"[AI ATTACK] {ip} (confidence={confidence:.2f})")
                    block_ip(ip)
                else:
                    print(f"[NORMAL] {ip} allowed")

            ip_stats.clear()
            window_start = time.time()

except KeyboardInterrupt:
    print("\nStopping live detection...")

print("\nBlocked IPs:", blocked_ips)

