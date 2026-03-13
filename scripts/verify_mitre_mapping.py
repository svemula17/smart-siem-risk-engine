import json
import logging
from sys import stdout

from app.ingestion.loader import load_all_raw_alerts
from app.normalization.mapper import normalize_alert

RAW_ALERTS_DIR = "data/raw_alerts"

def main():
    print("="*60)
    print("🚀 INITIALIZING SMART SIEM TTP MAPPING VERIFICATION 🚀")
    print("="*60)
    
    print("\n[+] Loading Raw Alerts from ingestion pipeline...")
    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)
    print(f"[+] Loaded {len(alerts)} alerts.")

    mapped_alerts = []
    total_evaluated = 0
    correct_mappings = 0

    print("\n[+] Running pure code logic to map MITRE Info...\n")

    for raw in alerts:
        # Ground Truth from datatset extraction (which we stored in mitre_info for validation)
        ground_truth_ttps = set(info.mitre_id for info in raw.metadata.mitre_info if info.mitre_id)
        
        # PURE CODE LOGIC: Let the normalization engine extract the data
        normalized = normalize_alert(raw)
        extracted_ttps = set(normalized.mitre_ids)

        is_correct = ground_truth_ttps == extracted_ttps
        
        total_evaluated += 1
        if is_correct:
            correct_mappings += 1

        # Generate the minimal mapped alert you requested
        mapped_alert = {
            "alert_id": raw.id,
            "signature": normalized.signature,
            "mapped_mitre_ttps": list(extracted_ttps),
            "ground_truth_ttps": list(ground_truth_ttps),
            "verification_status": "MATCH" if is_correct else "MISMATCH"
        }
        mapped_alerts.append(mapped_alert)

    # Show off a sample of the purely mapped alerts
    print("-" * 60)
    print("SAMPLE OF MAPPED ALERTS (MITRE ONLY)")
    print("-" * 60)
    # Print the first 10 that specifically had actual TTPs (ignoring completely benign ones for the showcase)
    showcase_alerts = [m for m in mapped_alerts if m["ground_truth_ttps"]][:10]
    
    if not showcase_alerts:
        showcase_alerts = mapped_alerts[:10]

    for sample in showcase_alerts:
        print(json.dumps(sample, indent=2))

    # Show off the engine accuracy
    accuracy = (correct_mappings / total_evaluated) * 100 if total_evaluated > 0 else 0
    
    print("\n" + "="*60)
    print("🏆 SIEM MITRE MAPPING ACCURACY REPORT 🏆")
    print("="*60)
    print(f"Total Alerts Processed:       {total_evaluated}")
    print(f"Correctly Mapped TTPs:        {correct_mappings}")
    print(f"Incorrect/Missed Mappings:    {total_evaluated - correct_mappings}")
    print(f"Engine TTP Mapping Accuracy:  {accuracy:.2f}%")
    print("="*60)

    if accuracy == 100.0:
        print("\n✅ Verification SUCCESS: The SIEM Machine pure code logic is perfectly mapping all raw sources!")

if __name__ == "__main__":
    main()
