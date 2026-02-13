"""
Standalone Training Script
==========================
Run this script to train the phishing detection model.

Usage:
    python train_model.py

This will:
- Load Phishing_Legitimate_full.csv
- Train a TensorFlow/Keras model for up to 20 epochs
- Use early stopping (patience=5) based on validation loss
- Save the best model to saved_model/phishing_model.h5
- Save the scaler to saved_model/scaler.pkl
- Save training history and feature importance as JSON
"""

import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

from models.phishing_model import train_model


def main():
    print("=" * 60)
    print("  Phishing Detection Model — Training Pipeline")
    print("=" * 60)
    print()

    results = train_model()

    print()
    print("=" * 60)
    print("  Training Complete!")
    print("=" * 60)
    print(f"  Epochs trained:  {results['epochs_trained']}")
    print(f"  Test Accuracy:   {results['test_accuracy']:.4f}")
    print(f"  Test AUC:        {results['test_auc']:.4f}")
    print(f"  Test Loss:       {results['test_loss']:.4f}")
    print("=" * 60)
    print()
    print("Model saved to: saved_model/phishing_model.h5")
    print("Scaler saved to: saved_model/scaler.pkl")
    print()

    # Print classification report
    report = results.get('classification_report', {})
    if report:
        print("Classification Report:")
        print("-" * 40)
        for label, metrics in report.items():
            if isinstance(metrics, dict):
                name = 'Legitimate' if label == '0' else ('Phishing' if label == '1' else label)
                print(f"  {name:>12}: precision={metrics.get('precision', 0):.3f}  "
                      f"recall={metrics.get('recall', 0):.3f}  f1={metrics.get('f1-score', 0):.3f}")


if __name__ == '__main__':
    main()
