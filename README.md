# Phishing URL Detection — Neural Network Risk Scorer  

A full-stack web application that detects phishing URLs using a **TensorFlow regression model**, outputting a continuous 0–100% risk score rather than a binary label — enabling nuanced threat triage across single URLs and bulk CSV uploads.

---

## Highlights

- Trained a **Keras regression neural network** on 48 URL-derived features from `Phishing_Legitimate_full.csv`, predicting phishing likelihood as a continuous risk score instead of a binary classifier — allowing threshold tuning for different security tolerances
- Built a **feature preprocessing pipeline** with Scikit-learn scalers saved alongside the model (`saved_model/`) ensuring identical transformations at inference time as during training
- Implemented **JWT authentication** with SQLite-backed user management — signup, login, and protected prediction routes via Flask
- Developed **batch prediction** support — users upload a CSV, all URLs are scored in bulk, and results are returned with per-row risk percentages
- Built an **analytics dashboard** with Chart.js visualizations showing feature importance rankings and model training history (loss curves across epochs)

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML Model | TensorFlow, Keras (regression) |
| Feature Engineering | Scikit-learn, Pandas (48 features) |
| Backend | Flask, Python 3.11 |
| Auth | JWT + SQLite |
| Frontend | HTML, CSS, JavaScript |
| Visualization | Chart.js |

---

## Model Design

- **Input:** 48 URL features (lexical, domain, path, query characteristics)
- **Architecture:** Dense neural network with regression output (sigmoid → 0–1 scaled to 0–100%)
- **Training:** Up to 20 epochs with early stopping, scaler fitted on training data
- **Outputs saved:** `saved_model/model.h5` + `saved_model/scaler.pkl`

---

## Setup

```bash
pip install -r requirements.txt

# Train the model (required before running the app)
python train_model.py
# → Loads Phishing_Legitimate_full.csv
# → Trains for up to 20 epochs
# → Saves model + scaler to saved_model/

# Run the app
python app.py
# http://localhost:5000
```

---

## Features

- **Single URL prediction** — enter URL features manually, get instant risk score
- **Batch prediction** — upload CSV, receive per-row phishing probability
- **Analytics page** — feature importance chart + training loss history
- **Auth-protected dashboard** — JWT login required to access predictions

---

## Project Structure

```
├── train_model.py           # Training pipeline — data load, fit, save
├── app.py                   # Flask server — routes, auth, prediction API
├── saved_model/
│   ├── model.h5             # Trained Keras regression model
│   └── scaler.pkl           # Fitted Scikit-learn feature scaler
├── Phishing_Legitimate_full.csv   # Training dataset (48 features)
└── templates/               # Frontend — dashboard, predict, analytics
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/signup` | Register user |
| `POST` | `/api/auth/login` | Login, returns JWT |
| `POST` | `/api/predict` | Score a single URL feature vector |
| `POST` | `/api/predict/batch` | Upload CSV, returns risk scores per row |
| `GET` | `/api/analytics` | Feature importance + training history |
