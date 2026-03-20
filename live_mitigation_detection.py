import pyshark
import time
import subprocess
from collections import defaultdict

# ============================
# CONFIGURATION
# ============================
INTERFACE = "enp0s3" 
WINDOW_SIZE = 5 
THRESHOLD = 50 

# YOUR SPECIFIC IPs
UBUNTU_IP = "192.168.0.240"
KALI_IP = "192.168.0.152"
WINDOWS_IP = "192.168.0.156"

# 1. WHITELIST: Ubuntu will NEVER block itself
WHITELIST = {UBUNTU_IP, "127.0.0.1", "192.168.0.1"}

print(f"🚀 PROTECTION ACTIVE FOR: {UBUNTU_IP}")
print(f"Ignoring (Safe): {WHITELIST}")

# ============================
# DETECTION LOGIC
# ============================
packet_counts = defaultdict(int)
blocked_ips = set()
start_time = time.time()

# This tells the network card to ignore all traffic from the Ubuntu IP itself
capture = pyshark.LiveCapture(interface=INTERFACE, display_filter="ip and ip.src != 192.168.0.240")
try:
    for packet in capture.sniff_continuously():
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # 2. DESTINATION FILTER: Only count traffic coming TO Ubuntu
            # This prevents Ubuntu from counting its own outgoing packets as an attack
            if dst_ip != UBUNTU_IP:
                continue
                
            # 3. SOURCE FILTER: Ignore if the traffic is from a Whitelisted IP
            if src_ip in WHITELIST:
                continue
                
            packet_counts[src_ip] += 1
            
        if time.time() - start_time >= WINDOW_SIZE:
            print("\n" + "="*30)
            print(f"Evaluating Traffic Window ({time.strftime('%H:%M:%S')})")
            print("="*30)
            
            for ip, count in packet_counts.items():
                rate = count / WINDOW_SIZE
                
                if rate > THRESHOLD:
                    print(f"🚨 [THRESHOLD ATTACK] {ip} (rate={rate:.2f} pps)")
                    if ip not in blocked_ips:
                        print(f"🛡️ [MITIGATION] Blocking Attacker IP: {ip}")
                        # Use -I INPUT 1 to ensure it overrides all other rules 
                        subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
                        blocked_ips.add(ip)
                else:
                    if ip not in blocked_ips:
                        print(f"✅ [NORMAL] {ip} allowed")
            
            packet_counts.clear()
            start_time = time.time()

except KeyboardInterrupt:
    print("\nStopping live detection...")
