"""
Phishing Detection Model
=========================
TensorFlow/Keras regression model for phishing risk prediction.
Handles training, saving, loading, and inference.
"""

import os
import json
import numpy as np
import pandas as pd
import joblib
import logging
from config import Config

# Suppress TF warnings for cleaner output
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report

logger = logging.getLogger(__name__)

# ─── Global model cache ───
_model = None
_scaler = None


def load_dataset():
    """
    Load and prepare the phishing dataset.
    Returns: (X, y, feature_names)
    """
    df = pd.read_csv(Config.DATASET_PATH)

    # Drop the 'id' column — not a feature
    if 'id' in df.columns:
        df = df.drop('id', axis=1)

    # Handle any missing values (fill with median)
    df = df.fillna(df.median(numeric_only=True))

    # Separate features and target
    feature_cols = [c for c in df.columns if c != Config.TARGET_COLUMN]
    X = df[feature_cols].values.astype(np.float32)
    y = df[Config.TARGET_COLUMN].values.astype(np.float32)

    return X, y, feature_cols


def build_model(input_dim):
    """
    Build the Keras Sequential regression model.
    Architecture: Dense(128) → Dropout → Dense(64) → Dropout → Dense(32) → Dense(1, sigmoid)
    """
    model = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        keras.layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
        keras.layers.BatchNormalization(),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(64, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
        keras.layers.BatchNormalization(),
        keras.layers.Dropout(0.2),
        keras.layers.Dense(32, activation='relu'),
        keras.layers.Dropout(0.1),
        keras.layers.Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', keras.metrics.AUC(name='auc')]
    )

    return model


def train_model():
    """
    Train the phishing detection model.
    - 80/20 train-test split with random seed
    - 20 epochs max with early stopping (patience=5)
    - Saves best model, scaler, training history, and feature importance

    Returns: dict with training results
    """
    logger.info("Loading dataset...")
    X, y, feature_names = load_dataset()

    # Train-test split with reproducible seed
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=Config.TEST_SPLIT, random_state=Config.RANDOM_SEED, stratify=y
    )

    # Normalize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Build model
    model = build_model(X_train_scaled.shape[1])
    logger.info(f"Model built with {model.count_params()} parameters")

    # Callbacks
    os.makedirs(Config.MODEL_DIR, exist_ok=True)

    early_stopping = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=Config.EARLY_STOPPING_PATIENCE,
        restore_best_weights=True,
        verbose=1
    )

    # Train
    logger.info(f"Training for up to {Config.EPOCHS} epochs...")
    history = model.fit(
        X_train_scaled, y_train,
        epochs=Config.EPOCHS,
        batch_size=Config.BATCH_SIZE,
        validation_split=Config.VALIDATION_SPLIT,
        callbacks=[early_stopping],
        verbose=1
    )

    # Evaluate on test set
    test_loss, test_accuracy, test_auc = model.evaluate(X_test_scaled, y_test, verbose=0)

    # Predictions for detailed metrics
    y_pred_proba = model.predict(X_test_scaled, verbose=0).flatten()
    y_pred = (y_pred_proba >= 0.5).astype(int)

    # Save model
    model.save(Config.MODEL_PATH)
    logger.info(f"Model saved to {Config.MODEL_PATH}")

    # Save scaler
    joblib.dump(scaler, Config.SCALER_PATH)
    logger.info(f"Scaler saved to {Config.SCALER_PATH}")

    # Save training history
    history_data = {
        'loss': [float(v) for v in history.history['loss']],
        'val_loss': [float(v) for v in history.history['val_loss']],
        'accuracy': [float(v) for v in history.history['accuracy']],
        'val_accuracy': [float(v) for v in history.history['val_accuracy']],
        'auc': [float(v) for v in history.history['auc']],
        'val_auc': [float(v) for v in history.history['val_auc']],
        'epochs_trained': len(history.history['loss']),
    }
    with open(Config.HISTORY_PATH, 'w') as f:
        json.dump(history_data, f, indent=2)

    # Compute feature importance via permutation
    importance = compute_feature_importance(model, X_test_scaled, y_test, feature_names)
    with open(Config.IMPORTANCE_PATH, 'w') as f:
        json.dump(importance, f, indent=2)

    # Clear the cached model so it reloads
    global _model, _scaler
    _model = None
    _scaler = None

    results = {
        'test_accuracy': float(test_accuracy),
        'test_auc': float(test_auc),
        'test_loss': float(test_loss),
        'epochs_trained': len(history.history['loss']),
        'classification_report': classification_report(y_test, y_pred, output_dict=True),
    }

    logger.info(f"Training complete — Accuracy: {test_accuracy:.4f}, AUC: {test_auc:.4f}")
    return results


def compute_feature_importance(model, X_test, y_test, feature_names, n_repeats=5):
    """
    Compute permutation-based feature importance.
    Shuffles each feature and measures accuracy drop.
    """
    baseline_loss, baseline_acc, _ = model.evaluate(X_test, y_test, verbose=0)
    importances = {}

    for i, feat in enumerate(feature_names):
        scores = []
        for _ in range(n_repeats):
            X_permuted = X_test.copy()
            np.random.shuffle(X_permuted[:, i])
            _, perm_acc, _ = model.evaluate(X_permuted, y_test, verbose=0)
            scores.append(baseline_acc - perm_acc)
        importances[feat] = float(np.mean(scores))

    # Sort descending by importance
    importances = dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
    return importances


def get_model():
    """Load and cache the trained model."""
    global _model
    if _model is None:
        if not os.path.exists(Config.MODEL_PATH):
            raise FileNotFoundError("Model not trained yet. Run train_model.py first.")
        _model = keras.models.load_model(Config.MODEL_PATH)
    return _model


def get_scaler():
    """Load and cache the fitted scaler."""
    global _scaler
    if _scaler is None:
        if not os.path.exists(Config.SCALER_PATH):
            raise FileNotFoundError("Scaler not found. Run train_model.py first.")
        _scaler = joblib.load(Config.SCALER_PATH)
    return _scaler


def predict(features_dict):
    """
    Predict phishing risk for a single sample.

    Args:
        features_dict: dict mapping feature names → values

    Returns:
        dict with 'score' (0-1 probability), 'status', 'label'
    """
    model = get_model()
    scaler = get_scaler()

    # Build input array in correct feature order
    _, _, feature_names = load_dataset()
    input_arr = np.array([[float(features_dict.get(f, 0)) for f in feature_names]], dtype=np.float32)

    # Scale and predict
    input_scaled = scaler.transform(input_arr)
    score = float(model.predict(input_scaled, verbose=0)[0][0])

    # Classify
    if score >= 0.7:
        status = 'Phishing'
        label = 'danger'
    elif score >= 0.4:
        status = 'Suspicious'
        label = 'warning'
    else:
        status = 'Legitimate'
        label = 'safe'

    return {
        'score': round(score, 4),
        'percentage': round(score * 100, 2),
        'status': status,
        'label': label
    }


def predict_batch(df):
    """
    Predict phishing risk for a batch of samples (DataFrame).
    Returns: DataFrame with added score, status, label columns.
    """
    model = get_model()
    scaler = get_scaler()
    _, _, feature_names = load_dataset()

    # Ensure columns exist, fill missing with 0
    for col in feature_names:
        if col not in df.columns:
            df[col] = 0

    X = df[feature_names].values.astype(np.float32)
    X_scaled = scaler.transform(X)
    scores = model.predict(X_scaled, verbose=0).flatten()

    df['phishing_score'] = [round(float(s), 4) for s in scores]
    df['phishing_percentage'] = [round(float(s) * 100, 2) for s in scores]
    df['status'] = ['Phishing' if s >= 0.7 else ('Suspicious' if s >= 0.4 else 'Legitimate') for s in scores]

    return df


def get_analytics_data():
    """
    Return dataset analytics: stats, feature importance, class distribution, training history.
    """
    analytics = {}

    # Dataset stats
    X, y, feature_names = load_dataset()
    analytics['dataset'] = {
        'total_samples': int(len(y)),
        'phishing_count': int(np.sum(y == 1)),
        'legitimate_count': int(np.sum(y == 0)),
        'num_features': len(feature_names),
        'feature_names': feature_names,
    }

    # Feature importance
    if os.path.exists(Config.IMPORTANCE_PATH):
        with open(Config.IMPORTANCE_PATH, 'r') as f:
            analytics['feature_importance'] = json.load(f)

    # Training history
    if os.path.exists(Config.HISTORY_PATH):
        with open(Config.HISTORY_PATH, 'r') as f:
            analytics['training_history'] = json.load(f)

    # Basic feature stats
    df = pd.read_csv(Config.DATASET_PATH)
    if 'id' in df.columns:
        df = df.drop('id', axis=1)
    stats = df.describe().to_dict()
    # Convert numpy types for JSON serialization
    analytics['feature_stats'] = {
        k: {kk: float(vv) for kk, vv in v.items()}
        for k, v in stats.items()
    }

    return analytics
