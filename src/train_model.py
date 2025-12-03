# src/train_model.py
import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from extract_features import extract_features  # твой модуль для фич

# Загружаем датасет
df = pd.read_csv("/Users/quasar/Documents/phishing-detector/data/kaggle/web_page_phishing.csv")
print("=== Загружен датасет ===")
print(df.head())

# Проверка столбцов
print("Колонки:", df.columns)

# Создаём датафрейм с извлечёнными фичами
rows = []
for url, label in zip(df["url"], df["status"]):  # здесь 'status', а не 'label'
    features = extract_features(url)
    features["label"] = 1 if label == "phishing" else 0
    rows.append(features)

df2 = pd.DataFrame(rows)
print("=== Преобразование завершено ===")
print(df2.head())

# Разделяем признаки и метки
X = df2.drop(columns=["label"])
y = df2["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Обучаем модель
model = RandomForestClassifier(n_estimators=400, random_state=42)
model.fit(X_train, y_train)

# Проверяем точность
print("=== Результаты ===")
print("Accuracy:", model.score(X_test, y_test))

# Создаём папку model, если её нет
os.makedirs("model", exist_ok=True)

# Сохраняем модель
joblib.dump(model, "model/phishing_detector.pkl")
print("Модель сохранена в model/phishing_detector.pkl")