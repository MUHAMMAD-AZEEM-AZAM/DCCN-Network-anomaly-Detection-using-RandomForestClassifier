import subprocess
import time
import sys
from pathlib import Path

# ================== CONFIG ==================
TSHARK_PATH = r"D:\Azeem\softwares\InstalledSoftware\Wireshark\tshark.exe"
PCAP_OUTPUT = "live.pcap"
CAPTURE_SECONDS = 60
# ============================================

print("[+] Checking TShark installation...")

if not Path(TSHARK_PATH).exists():
    print("[!] ERROR: tshark.exe not found at:", TSHARK_PATH)
    print("[!] Please install Wireshark from: https://www.wireshark.org/download/")
    sys.exit(1)

print(f"[+] Starting live traffic capture for {CAPTURE_SECONDS} seconds...")
print(f"[+] Output file: {PCAP_OUTPUT}")

try:
    # Capture packets using TShark
    # -i 5: Wi-Fi interface (or use 12 for Ethernet)
    # -a duration:60: capture for 60 seconds
    # -w: write to file
    subprocess.run(
        [
            TSHARK_PATH,
            "-i", "5",  # Interface 5 = Wi-Fi (change to 12 for Ethernet)
            "-a", f"duration:{CAPTURE_SECONDS}",
            "-w", PCAP_OUTPUT
        ],
        check=True
    )
    
    print(f"[+] Capture complete!")
    print(f"[+] PCAP file saved: {PCAP_OUTPUT}")
    
except subprocess.CalledProcessError as e:
    print(f"[!] Capture failed with error code: {e.returncode}")
    print("[!] Make sure you have Wireshark installed and you're capturing on a valid interface")
    sys.exit(1)
except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
