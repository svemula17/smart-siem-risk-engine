import os
import sys

# Ensure imports work when run from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.evaluation.metrics import GROUND_TRUTH_TO_RISK_BAND
from app.ingestion.loader import load_all_raw_alerts
from app.normalization.mapper import normalize_alert
from app.scoring.ml_model import ml_engine

RAW_ALERTS_DIR = "data/raw_alerts"

def main():
    print("🤖 Booting ML Training Pipeline...")
    alerts = load_all_raw_alerts(RAW_ALERTS_DIR)

    texts = []
    labels = []

    print(f"Loaded {len(alerts)} raw alerts for training...")

    for raw in alerts:
        normalized = normalize_alert(raw)

        # We need text and a strict Risk Band label (CRITICAL, HIGH, MEDIUM, LOW)
        text = normalized.title
        ground_truth = normalized.ground_truth_label.upper()
        risk_band_label = GROUND_TRUTH_TO_RISK_BAND.get(ground_truth, "UNKNOWN")

        if text and risk_band_label != "UNKNOWN":
            texts.append(text)
            labels.append(risk_band_label)

    if not texts:
        print("❌ No valid training data found!")
        return

    print(f"Training RandomForestClassifier on {len(texts)} samples using TF-IDF...")
    ml_engine.train(texts, labels)

    print("✅ Model Trained and saved to disk successfully!")
    print(f"Test Prediction on 'Directory Traversal Attempt': {ml_engine.predict('Directory Traversal Attempt')}")

if __name__ == "__main__":
    main()
