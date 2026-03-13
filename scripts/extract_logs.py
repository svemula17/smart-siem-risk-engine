import os
import csv
import json
import uuid
import random
from pathlib import Path

# Paths
CI_DATASET_DIR = "Data Set/Ci-dataset"
ZEEK_DATASET_DIR = "Data Set/Zeek-dataset"
OUTPUT_DIR = "data/raw_alerts"

def get_severity(label):
    label = label.upper()
    if label == "BENIGN" or label == "FALSE":
        return 0
    return random.randint(1, 3)

def process_ci_dataset(filepath, num_samples=200):
    samples = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        if len(rows) > num_samples:
            sampled_rows = random.sample(rows, num_samples)
        else:
            sampled_rows = rows
            
        for row in sampled_rows:
            label = row.get(' Label', row.get('Label', 'BENIGN')).strip()
            src_ip = row.get(' Source IP', row.get('Source IP', '0.0.0.0')).strip()
            dest_ip = row.get(' Destination IP', row.get('Destination IP', '0.0.0.0')).strip()
            timestamp = row.get(' Timestamp', row.get('Timestamp', '2017-07-07T09:00:00')).strip()
            
            category = "MALICIOUS" if label != "BENIGN" else "BENIGN"
            
            alert = {
                "id": str(uuid.uuid4()),
                "group": "NETWORK",
                "type": "ids_alert",
                "message": f"ISCX Alert: {label}",
                "source": "iscx",
                "status": "new",
                "start_time": timestamp,
                "end_time": timestamp,
                "raw_severity": get_severity(label),
                "ground_truth_label": category,
                "entity_ids": {
                    "ip": [src_ip],
                    "ips": [src_ip, dest_ip],
                    "user": [],
                    "host": []
                },
                "metadata": {
                    "mitre_info": [],
                    "suricata_logs": [{
                        "category": category,
                        "severity": get_severity(label),
                        "signature": f"ISCX {label}",
                        "signature_id": "0",
                        "mitre_ids": []
                    }],
                    "threat": {
                        "indicator": [{
                            "name": f"ISCX {label}",
                            "type": category,
                            "ip": src_ip
                        }]
                    }
                }
            }
            samples.append(alert)
    return samples

def process_zeek_dataset(filepath, num_samples=200):
    samples = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        if len(rows) > num_samples:
            sampled_rows = random.sample(rows, num_samples)
        else:
            sampled_rows = rows
            
        for row in sampled_rows:
            is_malicious = row.get('label_binary', 'False').strip().lower() == 'true'
            tactic = row.get('label_tactic', 'None').strip()
            technique = row.get('label_technique', 'None').strip()
            
            src_ip = row.get('src_ip_zeek', '0.0.0.0').strip()
            dest_ip = row.get('dest_ip_zeek', '0.0.0.0').strip()
            timestamp = row.get('datetime', '2024-01-01T00:00:00Z').strip()
            
            category = "MALICIOUS" if is_malicious else "BENIGN"
            mitre_ids = [technique] if technique != 'none' else []
            
            mitre_info = [{"mitre_id": technique, "technique": tactic}] if technique != 'none' else []
            
            alert = {
                "id": str(uuid.uuid4()),
                "group": "NETWORK",
                "type": "zeek_alert",
                "message": f"Zeek Alert: {tactic}",
                "source": "zeek",
                "status": "new",
                "start_time": timestamp,
                "end_time": timestamp,
                "raw_severity": get_severity(str(is_malicious)),
                "ground_truth_label": category,
                "entity_ids": {
                    "ip": [src_ip],
                    "ips": [src_ip, dest_ip],
                    "user": [],
                    "host": []
                },
                "metadata": {
                    "mitre_info": mitre_info,
                    "suricata_logs": [{
                        "category": category,
                        "severity": get_severity(str(is_malicious)),
                        "signature": f"Zeek {tactic}",
                        "signature_id": "0",
                        "mitre_ids": mitre_ids
                    }],
                    "threat": {
                        "indicator": [{
                            "name": f"Zeek {tactic}",
                            "type": category,
                            "ip": src_ip
                        }]
                    }
                }
            }
            samples.append(alert)
    return samples

def main():
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    # clear existing files to stay clean
    for p in Path(OUTPUT_DIR).glob("*.json"):
        p.unlink()

    all_alerts = []
    
    # Zeek
    zeek_dir = Path(ZEEK_DATASET_DIR)
    if zeek_dir.exists():
        for csv_file in zeek_dir.glob("*.csv"):
            print(f"Processing {csv_file.name} ...")
            alerts = process_zeek_dataset(csv_file, 200)
            all_alerts.extend(alerts)
            
    # CI Dataset
    ci_dir = Path(CI_DATASET_DIR)
    if ci_dir.exists():
        for csv_file in ci_dir.glob("*.csv"):
            print(f"Processing {csv_file.name} ...")
            alerts = process_ci_dataset(csv_file, 200)
            all_alerts.extend(alerts)

    for alert in all_alerts:
        out_path = Path(OUTPUT_DIR) / f"{alert['id']}.json"
        with out_path.open('w') as f:
            json.dump(alert, f, indent=2)

    print(f"Extraction complete! Saved {len(all_alerts)} alerts to {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
