# src/predict.py
import joblib
import pandas as pd
from extract_features import extract_features

model = joblib.load("phishing_model.pkl")

url = input("Введите URL: ")

features = extract_features(url)
df = pd.DataFrame([features])

pred = model.predict(df)[0]
proba = model.predict_proba(df)[0][pred]

label = "phishing" if pred == 1 else "legitimate"

print(f"Результат: {label} ({proba:.2f})")