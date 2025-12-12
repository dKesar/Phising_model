# src/test_urls.py
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from extract_features import extract_features
import pandas as pd
import joblib
from catboost import CatBoostClassifier

# 🔹 Загрузка модели
MODEL_PATH = "../model/phishing_detector.cbm"
if os.path.exists(MODEL_PATH):
    model = CatBoostClassifier()
    model.load_model(MODEL_PATH)
    print("✅ CatBoost модель загружена")
else:
    MODEL_PATH = "../model/phishing_detector.pkl"
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("✅ Joblib модель загружена")
    else:
        raise RuntimeError("Модель не найдена")

print("\n🔍 Тест модели с include_html=True (медленно, но точнее)\n")
print("="*80)

# 🔹 5 легитимных и 5 фишинговых URL (реальные 2024–2025)
TEST_URLS = [
    # Легитимные
    ("https://google.com", "legitimate"),
    ("https://github.com", "legitimate"),
    ("https://stackoverflow.com", "legitimate"),
    ("https://bankofamerica.com", "legitimate"),
    ("https://microsoft.com", "legitimate"),
    
    # Фишинговые (проверенные, безопасные — без полезной нагрузки)
    ("https://accounts-google.secure-login.cc", "phishing"),
    ("https://paypal-secure.verifyaccount.info", "phishing"),
    ("https://appleid-update.signin-apple.tk", "phishing"),
    ("https://microsoft365-login.onedrive-share.ga", "phishing"),
    ("https://amazon-security.verify-order.ml", "phishing")
]

results = []
for url, true_label in TEST_URLS:
    try:
        print(f"🌐 Загрузка и парсинг: {url[:50]:<50}", end="", flush=True)
        feats = extract_features(url, include_html=True)  # ← HTML включён!
        X = pd.DataFrame([feats])
        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0][pred]
        label = "phishing" if pred == 1 else "legitimate"
        correct = label == true_label
        results.append((url, true_label, label, proba, correct))
        status = "✅" if correct else "❌"
        print(f" → {status} {label} ({proba:.2f})")
    except Exception as e:
        print(f" → ⚠️ Ошибка: {e}")

# 🔹 Итог
correct_count = sum(r[4] for r in results)
total = len(results)
accuracy = correct_count / total if total > 0 else 0

print("="*80)
print(f"🎯 Точность на тестовых URL (с HTML): {correct_count}/{total} = {accuracy:.1%}")
print("\n💡 Вывод:")
if accuracy >= 0.9:
    print("   → HTML-признаки ДАЮТ эффект: точность ≥90%")
elif correct_count > 6:
    print("   → Есть улучшение по сравнению с baseline (~60%)")
else:
    print("   → HTML не дал ожидаемого роста — возможно, сайт не загрузился или признаки слабые")