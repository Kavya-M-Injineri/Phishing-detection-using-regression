"""
User Model
==========
SQLite-backed user management with password hashing for JWT authentication.
"""

import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config


def get_db_connection():
    """Create and return a database connection."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with the users table."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def create_user(username, email, password, role='user'):
    """
    Create a new user with hashed password.
    Returns: (success: bool, message: str, user_id: int or None)
    """
    conn = get_db_connection()
    try:
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        cursor = conn.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            (username, email, password_hash, role)
        )
        conn.commit()
        return True, 'User created successfully', cursor.lastrowid
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return False, 'Username already exists', None
        elif 'email' in str(e):
            return False, 'Email already exists', None
        return False, 'User already exists', None
    finally:
        conn.close()


def find_user_by_username(username):
    """Find a user by username. Returns dict or None."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(user) if user else None


def find_user_by_id(user_id):
    """Find a user by ID. Returns dict or None."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def verify_password(stored_hash, password):
    """Verify a password against its hash."""
    return check_password_hash(stored_hash, password)
