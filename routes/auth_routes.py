"""
Authentication Routes
=====================
JWT-based signup, login, and token verification endpoints.
"""

import jwt
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify
from config import Config
from models.user_model import create_user, find_user_by_username, find_user_by_id, verify_password

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


def generate_token(user_id, username, role):
    """Generate a JWT token with 24-hour expiry."""
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=Config.JWT_EXPIRY_HOURS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')


def token_required(f):
    """Decorator to protect routes with JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check Authorization header
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        # Also check query params (for file downloads)
        if not token:
            token = request.args.get('token')

        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401

        try:
            payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
            current_user = find_user_by_id(payload['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to restrict access to admin users only."""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# ─── Endpoints ────────────────────────────────────────

@auth_bp.route('/api/signup', methods=['POST'])
def signup():
    """Register a new user."""
    data = request.get_json()

    # Validate required fields
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Username, email, and password are required'}), 400

    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if '@' not in email:
        return jsonify({'error': 'Invalid email address'}), 400

    # Create user
    success, message, user_id = create_user(username, email, password)

    if not success:
        return jsonify({'error': message}), 409

    # Generate token
    token = generate_token(user_id, username, 'user')
    logger.info(f"New user registered: {username}")

    return jsonify({
        'message': 'User created successfully',
        'token': token,
        'user': {
            'id': user_id,
            'username': username,
            'email': email,
            'role': 'user'
        }
    }), 201


@auth_bp.route('/api/login', methods=['POST'])
def login():
    """Authenticate a user and return JWT token."""
    data = request.get_json()

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Find user
    user = find_user_by_username(username)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    # Verify password
    if not verify_password(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate token
    token = generate_token(user['id'], user['username'], user['role'])
    logger.info(f"User logged in: {username}")

    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
    }), 200


@auth_bp.route('/api/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Return the current authenticated user's info."""
    return jsonify({
        'user': {
            'id': current_user['id'],
            'username': current_user['username'],
            'email': current_user['email'],
            'role': current_user['role'],
            'created_at': current_user['created_at']
        }
    }), 200
