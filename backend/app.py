from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from extract_features import extract_features
import pandas as pd
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Phishing URL Detector")

# Разрешаем фронту делать запросы к API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # для разработки
    allow_methods=["*"],
    allow_headers=["*"]
)

# Монтируем фронт в отдельный путь
app.mount("/static", StaticFiles(directory="../frontend", html=True), name="frontend")

# Загружаем модель
model = joblib.load("../model/phishing_detector.pkl")

class URLItem(BaseModel):
    url: str

@app.post("/predict")
def predict(item: URLItem):
    try:
        features = extract_features(item.url)
        X = pd.DataFrame([features])
        pred = model.predict(X)[0]
        proba = float(model.predict_proba(X).max())
        return {
            "url": str(item.url),
            "prediction": str(pred),
            "confidence": proba
        }
    except Exception as e:
        return {
            "url": str(item.url),
            "prediction": "не определен",
            "confidence": float('nan'),
            "error": str(e)
        }