"""
Prediction Routes
=================
Endpoints for single and batch phishing risk prediction, plus model download.
"""

import io
import os
import logging
import pandas as pd
from flask import Blueprint, request, jsonify, send_file
from config import Config
from routes.auth_routes import token_required
from models.phishing_model import predict, predict_batch, get_model

predict_bp = Blueprint('predict', __name__)
logger = logging.getLogger(__name__)


@predict_bp.route('/api/predict', methods=['POST'])
@token_required
def predict_single(current_user):
    """
    Predict phishing risk for a single URL feature set.
    Expects JSON body with feature name → value mappings.
    """
    try:
        data = request.get_json()
        if not data or 'features' not in data:
            return jsonify({'error': 'Request body must contain a "features" object'}), 400

        features = data['features']
        result = predict(features)

        logger.info(f"Prediction for user {current_user['username']}: score={result['score']}")

        return jsonify({
            'success': True,
            'prediction': result
        }), 200

    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500


@predict_bp.route('/api/batch-predict', methods=['POST'])
@token_required
def predict_batch_endpoint(current_user):
    """
    Predict phishing risk for a batch of samples from CSV upload.
    Returns JSON with predictions for each row.
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded. Use "file" form field.'}), 400

        file = request.files['file']
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'Only CSV files are accepted'}), 400

        # Read CSV
        df = pd.read_csv(file)
        if len(df) > 10000:
            return jsonify({'error': 'Maximum 10,000 rows allowed per batch'}), 400

        # Run batch prediction
        result_df = predict_batch(df)

        # Return as JSON
        results = result_df[['phishing_score', 'phishing_percentage', 'status']].to_dict(orient='records')

        logger.info(f"Batch prediction for user {current_user['username']}: {len(results)} samples")

        return jsonify({
            'success': True,
            'count': len(results),
            'predictions': results,
            'summary': {
                'total': len(results),
                'phishing': sum(1 for r in results if r['status'] == 'Phishing'),
                'suspicious': sum(1 for r in results if r['status'] == 'Suspicious'),
                'legitimate': sum(1 for r in results if r['status'] == 'Legitimate'),
                'avg_score': round(sum(r['phishing_score'] for r in results) / len(results), 4)
            }
        }), 200

    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 503
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        return jsonify({'error': f'Batch prediction failed: {str(e)}'}), 500


@predict_bp.route('/api/download-model', methods=['GET'])
@token_required
def download_model(current_user):
    """Download the trained model file (.h5)."""
    if not os.path.exists(Config.MODEL_PATH):
        return jsonify({'error': 'Model not available. Train the model first.'}), 404

    return send_file(
        Config.MODEL_PATH,
        as_attachment=True,
        download_name='phishing_model.h5',
        mimetype='application/octet-stream'
    )
