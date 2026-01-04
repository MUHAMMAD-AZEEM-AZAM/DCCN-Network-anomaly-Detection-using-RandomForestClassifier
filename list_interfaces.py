import subprocess
import sys
from pathlib import Path

# ================== CONFIG ==================
TSHARK_PATH = r"D:\Azeem\softwares\InstalledSoftware\Wireshark\tshark.exe"
# ============================================

print("[+] Listing available network interfaces...\n")

if not Path(TSHARK_PATH).exists():
    print("[!] ERROR: tshark.exe not found at:", TSHARK_PATH)
    sys.exit(1)

try:
    # List interfaces
    result = subprocess.run(
        [TSHARK_PATH, "-D"],
        capture_output=True,
        text=True,
        check=True
    )
    
    print(result.stdout)
    print("\nUse the interface number with capture_live_traffic.py")
    
except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
