"""
Phishing Detection Web Application
====================================
Flask app entry point. Serves the REST API and HTML frontend.

Usage:
    python app.py

The server will start at http://localhost:5000
"""

import os
import sys
import logging
from flask import Flask, render_template, send_from_directory
from flask_cors import CORS
from config import Config
from models.user_model import init_db
from routes.auth_routes import auth_bp
from routes.predict_routes import predict_bp
from routes.analytics_routes import analytics_bp

# ─── Logging ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def create_app():
    """Application factory — creates and configures the Flask app."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Enable CORS
    CORS(app)

    # Initialize database
    init_db()
    logger.info("Database initialized")

    # ─── Register API blueprints ───
    app.register_blueprint(auth_bp)
    app.register_blueprint(predict_bp)
    app.register_blueprint(analytics_bp)

    # ─── Page routes (serve HTML templates) ───
    @app.route('/')
    def index():
        return render_template('login.html')

    @app.route('/login')
    def login_page():
        return render_template('login.html')

    @app.route('/signup')
    def signup_page():
        return render_template('signup.html')

    @app.route('/dashboard')
    def dashboard_page():
        return render_template('dashboard.html')

    @app.route('/predict')
    def predict_page():
        return render_template('predict.html')

    @app.route('/results')
    def results_page():
        return render_template('results.html')

    @app.route('/analytics')
    def analytics_page():
        return render_template('analytics.html')

    @app.route('/about')
    def about_page():
        return render_template('about.html')

    # ─── Health check ───
    @app.route('/api/health')
    def health():
        model_ready = os.path.exists(Config.MODEL_PATH)
        return {
            'status': 'healthy',
            'model_ready': model_ready,
            'dataset': os.path.exists(Config.DATASET_PATH)
        }

    # ─── Error handlers ───
    @app.errorhandler(404)
    def not_found(e):
        return {'error': 'Endpoint not found'}, 404

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Internal server error: {e}")
        return {'error': 'Internal server error'}, 500

    return app


# ─── Entry Point ──────────────────────────────────────
if __name__ == '__main__':
    app = create_app()

    # Check if model exists
    if not os.path.exists(Config.MODEL_PATH):
        logger.warning("⚠️  Model not found! Run 'python train_model.py' to train the model before using predictions.")

    logger.info("🚀 Starting Phishing Detection Server at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
