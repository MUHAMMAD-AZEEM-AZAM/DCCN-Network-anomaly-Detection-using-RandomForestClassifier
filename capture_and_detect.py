import subprocess
import pandas as pd
import numpy as np
import joblib
from pathlib import Path

# ================== CONFIG ==================
TSHARK_PATH = r"D:\Azeem\softwares\InstalledSoftware\Wireshark\tshark.exe"
PCAP_FILE = "live.pcap"
OUTPUT_PACKET_CSV = "packets.csv"
OUTPUT_FLOW_CSV = "live_flows.csv"
# ============================================

print("[1] Checking files...")

if not Path(TSHARK_PATH).exists():
    raise FileNotFoundError("tshark.exe not found. Check TSHARK_PATH.")

if not Path(PCAP_FILE).exists():
    raise FileNotFoundError("live.pcap not found.")

print("[2] Extracting packet-level data via TShark...")

with open(OUTPUT_PACKET_CSV, "w", encoding="utf-8") as f:
    subprocess.run(
        [
            TSHARK_PATH,
            "-r", PCAP_FILE,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ip.proto",
            "-e", "frame.len",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-E", "separator=,",
            "-E", "occurrence=f",
            "-E", "quote=d"
        ],
        stdout=f,
        check=True
    )

print("[3] Reading packet CSV...")

df = pd.read_csv(
    OUTPUT_PACKET_CSV,
    header=None,
    names=["timestamp", "src_ip", "dst_ip", "protocol", "packet_len", "tcp_src_port", "udp_src_port"]
)

# drop invalid rows
df = df.dropna(subset=["timestamp", "src_ip", "dst_ip", "protocol", "packet_len"])

df["timestamp"] = df["timestamp"].astype(float)
df["packet_len"] = df["packet_len"].astype(int)
df["protocol"] = df["protocol"].astype(int)

print("[4] Aggregating into flows with model features...")

# Create bidirectional flow key (normalize src/dst order)
def create_flow_key(row):
    src_dst = tuple(sorted([row["src_ip"], row["dst_ip"]]))
    return src_dst + (row["protocol"],)

df["flow_key"] = df.apply(create_flow_key, axis=1)

# Determine packet direction (forward vs backward)
# Forward: packets going from the first IP to the second IP (alphabetically)
def is_forward_packet(row):
    ips = tuple(sorted([row["src_ip"], row["dst_ip"]]))
    return row["src_ip"] == ips[0]

df["is_forward"] = df.apply(is_forward_packet, axis=1)

# Aggregate flows
flows_list = []

for flow_key, group in df.groupby("flow_key"):
    src_ip_sorted, dst_ip_sorted, protocol = flow_key
    
    fwd_packets = group[group["is_forward"] == True]
    bwd_packets = group[group["is_forward"] == False]
    
    total_fwd_packets = len(fwd_packets)
    total_bwd_packets = len(bwd_packets)
    
    start_time = group["timestamp"].min()
    end_time = group["timestamp"].max()
    flow_duration = max(end_time - start_time, 0.000001)
    
    total_bytes = group["packet_len"].sum()
    
    # Calculate feature: Flow Duration (in seconds)
    flow_duration_sec = flow_duration
    
    # Calculate feature: Total Fwd Packets
    total_fwd_packets_feat = total_fwd_packets
    
    # Calculate feature: Total Backward Packets
    total_bwd_packets_feat = total_bwd_packets
    
    # Calculate feature: Flow Bytes/s
    flow_bytes_per_sec = total_bytes / flow_duration if flow_duration > 0 else 0
    
    # Calculate feature: Flow Packets/s
    total_packets = total_fwd_packets + total_bwd_packets
    flow_packets_per_sec = total_packets / flow_duration if flow_duration > 0 else 0
    
    # Calculate feature: Fwd Packet Length Mean
    fwd_packet_length_mean = fwd_packets["packet_len"].mean() if len(fwd_packets) > 0 else 0
    
    # Calculate feature: Bwd Packet Length Mean
    bwd_packet_length_mean = bwd_packets["packet_len"].mean() if len(bwd_packets) > 0 else 0
    
    flow_dict = {
        "Flow Duration": flow_duration_sec,
        "Total Fwd Packets": total_fwd_packets_feat,
        "Total Backward Packets": total_bwd_packets_feat,
        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_packets_per_sec,
        "Fwd Packet Length Mean": fwd_packet_length_mean,
        "Bwd Packet Length Mean": bwd_packet_length_mean
    }
    
    flows_list.append(flow_dict)

flows = pd.DataFrame(flows_list)

# Handle infinite and NaN values
flows = flows.replace([np.inf, -np.inf], 0)
flows = flows.fillna(0)

print("[5] Saving flow-level CSV...")

flows.to_csv(OUTPUT_FLOW_CSV, index=False)

print("[6] Loading ML model for anomaly detection...")

# Load the trained model
model_path = "portscan_rf_model.pkl"
if not Path(model_path).exists():
    print(f"[!] Model file not found: {model_path}")
else:
    try:
        model = joblib.load(model_path)
        
        print("[7] Running anomaly detection...")
        
        # Predict on the flows
        predictions = model.predict(flows)
        
        # Add predictions to dataframe
        flows["Anomaly_Prediction"] = predictions
        flows["Is_Anomaly"] = flows["Anomaly_Prediction"].astype(bool)
        
        # Save with predictions
        flows.to_csv(OUTPUT_FLOW_CSV, index=False)
        
        # Summary statistics
        benign_count = (flows["Anomaly_Prediction"] == 0).sum()
        anomaly_count = (flows["Anomaly_Prediction"] == 1).sum()
        
        print("\n===== DETECTION RESULTS =====")
        print(f"Total packets processed: {len(df)}")
        print(f"Total flows generated: {len(flows)}")
        print(f"Benign flows: {benign_count}")
        print(f"Anomalous flows: {anomaly_count}")
        
        if anomaly_count > 0:
            print("\n[!] ANOMALIES DETECTED:")
            anomalies = flows[flows["Anomaly_Prediction"] == 1]
            print(anomalies[["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s"]])
        
        print(f"\nSaved to: {OUTPUT_FLOW_CSV}")
        print("=============================")
        
    except Exception as e:
        print(f"[!] Error loading or running model: {e}")
        print("\n===== SUCCESS =====")
        print(f"Total packets processed: {len(df)}")
        print(f"Total flows generated: {len(flows)}")
        print(f"Saved to: {OUTPUT_FLOW_CSV}")
        print("===================")

