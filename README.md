# 🛡️ PhishNet – URL-Only Phishing Detection System



> **Модель бинарной классификации фишинговых URL без загрузки страницы.**  
> ✅ Точность: **90.4%** | ⚡ Предсказание: **< 10 мс** | 🧠 Только URL → 72 инженерных признака  
> Обучено на [Web Page Phishing Detection Dataset (Kaggle)](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)  
> (maked by dKesar - (github) | @wllmr0 - tg)

![PhishNet Demo](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi)
![CatBoost](https://img.shields.io/badge/CatBoost-FF6F00?style=flat)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)

---

## 🎯 Цель
Создать **безопасную, быструю и интерпретируемую** систему обнаружения фишинга, которая:
- **Не открывает фишинговые страницы** (анализ только URL),
- Работает в реальном времени (встраивается в почту, браузеры, SOC),
- Объясняет своё решение (через признаки: `brand_substring=1`, `suspicious_tld=1` и т.д.).

---

## 🌐 Демо

```bash
cd backend
uvicorn app:app --reload
```

---

<img width="917" height="192" alt="image" src="https://github.com/user-attachments/assets/e1e04277-ff63-41f8-b086-9f6b3596e5d5" />

---

## 🔧 Установка

```bash
git clone https://github.com/quasar/phishing-detector.git
cd phishing-detector
pip install -r requirements.txt
```

---

## 🧠 Обучение модели

```bash
cd src
python train_model.py
# → model/phishing_detector.cbm (и .pkl)
```

---

## 📜 **Лицензия**
MIT – свободно используй, модифицируй, внедряй.

