# backend/app.py
from fastapi import FastAPI, Request
from pydantic import BaseModel
import joblib
import os
from extract_features import extract_features
import pandas as pd
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI(title="Phishing URL Detector")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Так — правильно:
@app.get("/")
async def serve_frontend():
    return FileResponse("../frontend/index.html")

app.mount("/static", StaticFiles(directory="../frontend"), name="static")

# Попробуем загрузить CatBoost, иначе fallback на joblib
MODEL_PATH_CB = os.path.abspath("../model/phishing_detector.cbm")
MODEL_PATH_PKL = os.path.abspath("../model/phishing_detector.pkl")

if os.path.exists(MODEL_PATH_CB):
    from catboost import CatBoostClassifier
    model = CatBoostClassifier()
    model.load_model(MODEL_PATH_CB)
    print("✅ CatBoost модель загружена")
elif os.path.exists(MODEL_PATH_PKL):
    model = joblib.load(MODEL_PATH_PKL)
    print("✅ Joblib модель загружена")
else:
    raise RuntimeError("Модель не найдена ни в .cbm, ни в .pkl")

class URLItem(BaseModel):
    url: str

@app.post("/predict")
def predict(item: URLItem):
    url = None  # гарантируем наличие переменной для обработки ошибок
    try:
        url = str(getattr(item, "url", "")).strip()
        if not url:
            raise ValueError("URL не может быть пустым")

        features = extract_features(url, include_html=False)
        X = pd.DataFrame([features])

        # CatBoost и sklearn одинаково работают с .predict() и .predict_proba()
        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0][pred]

        label = "phishing" if pred == 1 else "legitimate"

        return {
            "url": url,
            "prediction": label,
            "confidence": float(proba),
            "is_phishing": bool(pred == 1)
        }
    except Exception as e:
        safe_url = url if url is not None else str(getattr(item, "url", ""))
        return {
            "url": safe_url,
            "prediction": "error",
            "confidence": 0.0,
            "is_phishing": None,
            "error": str(e)
        }