# src/train_model.py
import sys
import os
# Добавляем backend в пути Python
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
from extract_features import extract_features  # Теперь будет найден
from catboost import CatBoostClassifier
import warnings
import urllib3
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)


DATA_PATH = "../data/kaggle/web_page_phishing.csv"
print("🔍 Загрузка датасета...")
df = pd.read_csv(DATA_PATH)

# Берём ТОЛЬКО url и status
print(f"Исходный размер: {len(df)} строк")
df = df[["url", "status"]].dropna().drop_duplicates(subset=["url"])
print(f"После очистки: {len(df)} строк")

# Метки
df["label"] = df["status"].astype(str).str.lower().apply(lambda x: 1 if "phish" in x else 0)

# Извлечение фич
print("⚙️ Извлечение признаков из URL (расширенный набор)...")
rows = []
for i, (url, label) in enumerate(zip(df["url"], df["label"])):
    if i % 1000 == 0:
        print(f"  → {i}/{len(df)}")
    try:
        feats = extract_features(str(url), include_html=False) # ← быстро!
        feats["label"] = label
        rows.append(feats)
    except Exception as e:
        print(f"⚠️ Ошибка на {url}: {e}")

df_features = pd.DataFrame(rows)
print(f"✅ Получено {len(df_features)} объектов с {len(df_features.columns)-1} признаками")

# Разделение
X = df_features.drop(columns=["label"])
y = df_features["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# CatBoost — не требует масштабирования, обрабатывает NaN
print("🧠 Обучение CatBoost...")
model = CatBoostClassifier(
    iterations=500,
    learning_rate=0.05,
    depth=6,
    random_seed=42,
    verbose=50,  # каждые 50 итераций — лог
    eval_metric="F1",
    auto_class_weights="Balanced"
)

model.fit(X_train, y_train, eval_set=(X_test, y_test), use_best_model=True)

# Оценка
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n" + "="*50)
print("📊 ФИНАЛЬНЫЕ РЕЗУЛЬТАТЫ (CatBoost + 70+ фич):")
print(f"✅ Accuracy: {acc:.4f}")
print(f"✅ F1-score: {f1:.4f}")
print("="*50)

print("\nПодробно:")
print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

# Сохранение
os.makedirs("../model", exist_ok=True)
model.save_model("../model/phishing_detector.cbm")  # CatBoost native format
joblib.dump(model, "../model/phishing_detector.pkl")  # fallback
with open("../model/feature_names.txt", "w") as f:
    f.write("\n".join(X.columns))
print("✅ Модель сохранена в ../model/")