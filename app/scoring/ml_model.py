import os

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

MODEL_DIR = "app/scoring/models"
MODEL_PATH = os.path.join(MODEL_DIR, "risk_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")

class RiskMLModel:
    def __init__(self):
        self.vectorizer = None
        self.model = None

        if not os.path.exists(MODEL_DIR):
            os.makedirs(MODEL_DIR)

        self.load()

    def train(self, texts: list[str], labels: list[str]):
        """Trains the Random Forest model on the provided data."""
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words="english")
        X = self.vectorizer.fit_transform(texts)

        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, labels)

        self.save()

    def predict(self, text: str) -> str:
        """Predicts the Risk Band (CRITICAL, HIGH, MEDIUM, LOW) for a given text."""
        if not self.model or not self.vectorizer:
            return "UNKNOWN" # Fallback if model isn't trained

        X = self.vectorizer.transform([text])
        prediction = self.model.predict(X)
        return prediction[0]

    def save(self):
        if self.model and self.vectorizer:
            joblib.dump(self.model, MODEL_PATH)
            joblib.dump(self.vectorizer, VECTORIZER_PATH)

    def load(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.vectorizer = joblib.load(VECTORIZER_PATH)

# Global instance
ml_engine = RiskMLModel()
