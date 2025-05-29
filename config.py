import os
from datetime import timedelta

class Config:
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32))
    DEBUG = False
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net/npm/chart.js; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;"
        )
    }
    
    # File upload settings
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}
    
    # Database settings
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'database/users.db')
    
    # Email settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')
    
    # SendGrid settings
    SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
    
    # External URL for email links
    EXTERNAL_URL = os.getenv('EXTERNAL_URL', 'http://127.0.0.1:5000')
    
    # File storage paths
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads')
    ENCRYPTED_FOLDER = os.getenv('ENCRYPTED_FOLDER', 'static/encrypted')
    ENCRYPTED_KEY_FOLDER = os.getenv('ENCRYPTED_KEY_FOLDER', 'static/encrypted_keys')
    DECRYPTED_FOLDER = os.getenv('DECRYPTED_FOLDER', 'static/decrypted') 