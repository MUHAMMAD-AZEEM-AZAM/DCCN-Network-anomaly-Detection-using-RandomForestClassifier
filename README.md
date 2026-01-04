# DCCN Network Anomaly Detection
Real-time ML-based anomaly detection

## Setup
pip install -r requirements.txt
Install TShark

## Usage
python list_interfaces.py
python capture_live_traffic.py
python capture_and_detect.py

## Output
live_flows.csv with predictions (0=Benign, 1=Anomalous)