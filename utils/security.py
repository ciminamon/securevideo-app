import os
os.makedirs('logs', exist_ok=True)

from functools import wraps
from flask import session, redirect, url_for, flash, request
import logging
from datetime import datetime
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from config import Config
import mimetypes
import re

# Configure logging
logging.basicConfig(
    filename='logs/security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_db():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logging.warning(f"Unauthorized access attempt to {request.path} from IP {request.remote_addr}")
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def verify_user_access(video_id):
    """Verify if the current user has access to a specific video"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM videos WHERE id = ?', (video_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result or result[0] != session.get('user_id'):
        logging.warning(f"Unauthorized video access attempt - Video ID: {video_id}, User ID: {session.get('user_id')}")
        return False
    return True

def hash_password(password):
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed):
    """Verify a password against its hash"""
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def log_security_event(event_type, details):
    """Log security-related events"""
    logging.info(f"Security Event - Type: {event_type}, Details: {details}")

def validate_file_upload(file):
    """Validate file upload for security"""
    if not file:
        return False, "No file provided"
    # Check file extension
    if '.' not in file.filename:
        return False, "Invalid file format"
    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in Config.ALLOWED_EXTENSIONS:
        return False, "File type not allowed"
    # Check file size
    file.seek(0, 2)  # Move to end
    size = file.tell()
    file.seek(0)
    if size > Config.MAX_CONTENT_LENGTH:
        return False, "File too large"
    # Check MIME type (optional, basic check)
    mime, _ = mimetypes.guess_type(file.filename)
    if mime and not mime.startswith('video'):
        return False, "File is not a valid video type"
    return True, "File valid"

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    # At least 8 chars, one uppercase, one lowercase, one number, one special char
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\"\\|,.<>\/?]).{8,}$'
    return re.match(pattern, password) is not None 