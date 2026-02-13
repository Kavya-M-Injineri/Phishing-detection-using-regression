"""
Analytics Routes
================
Endpoints for dataset insights, feature importance, and training history.
"""

import logging
from flask import Blueprint, jsonify
from routes.auth_routes import token_required, admin_required
from models.phishing_model import get_analytics_data, train_model

analytics_bp = Blueprint('analytics', __name__)
logger = logging.getLogger(__name__)


@analytics_bp.route('/api/analytics', methods=['GET'])
@token_required
def get_analytics(current_user):
    """
    Return dataset statistics, feature importance, training history,
    and feature distribution data for the analytics dashboard.
    """
    try:
        data = get_analytics_data()
        return jsonify({'success': True, 'analytics': data}), 200
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return jsonify({'error': f'Failed to load analytics: {str(e)}'}), 500


@analytics_bp.route('/api/train', methods=['POST'])
@token_required
def trigger_training(current_user):
    """
    Trigger model training. Restricted to admin users.
    Regular users can still use the train_model.py script.
    """
    # Allow admin or if no role restriction needed
    if current_user.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required to train model'}), 403

    try:
        logger.info(f"Training triggered by admin: {current_user['username']}")
        results = train_model()
        return jsonify({
            'success': True,
            'message': 'Model trained successfully',
            'results': results
        }), 200
    except Exception as e:
        logger.error(f"Training error: {e}")
        return jsonify({'error': f'Training failed: {str(e)}'}), 500
