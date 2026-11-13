from pathlib import Path
import joblib
import numpy as np
from features import url_feature_vector
from language import detect_language

MODEL_DIR = Path(__file__).resolve().parent / "models"

class ModelService:
    def __init__(self):
        self.text_model = None
        self.url_model = None
        self._load()

    def _load(self):
        t = MODEL_DIR / "text_model.joblib"
        u = MODEL_DIR / "url_model.joblib"
        if t.exists():
            try: self.text_model = joblib.load(t)
            except Exception: self.text_model = None
        if u.exists():
            try: self.url_model = joblib.load(u)
            except Exception: self.url_model = None

    def text_predict(self, text: str):
        lang = detect_language(text)
        if self.text_model is None:
            return None, "not_trained", lang
        try:
            proba = self.text_model.predict_proba([text])[0]
            classes = list(self.text_model.classes_)
            idx = int(np.argmax(proba))
            return float(proba[idx]), str(classes[idx]), lang
        except Exception:
            return None, "model_error", lang

    def url_predict(self, url: str):
        if self.url_model is None:
            return None, "not_trained"
        try:
            p = self.url_model.predict_proba(url_feature_vector(url))[0]
            classes = list(self.url_model.classes_)
            # Label 1 means phishing in the provided training convention.
            ix = classes.index(1) if 1 in classes else int(np.argmax(p))
            return float(p[ix]), "trained"
        except Exception:
            return None, "model_error"

model_service = ModelService()
