from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import hashlib
from Crypto.Cipher import AES as CryptoAES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from flask import send_from_directory
import secrets
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail, Content
from dotenv import load_dotenv
from datetime import datetime, timedelta
import random
import time
import psutil
from models.performance_metrics import init_performance_db, save_metrics, get_performance_stats
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils.security import login_required, verify_user_access, hash_password, verify_password, log_security_event, validate_file_upload, validate_email, validate_password
from config import Config
import qrcode
from io import BytesIO
import json
import io
from flask_mail import Mail as FlaskMail, Message
from flask_wtf import CSRFProtect
import bcrypt


# 🔐 Import encryption modules (ensure AES.py and ECC.py are in crypto_module folder)
from crypto_module.ECC_module.ECC import ECC
#from crypto_module.AES_module import AES

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# Initialize security extensions
talisman = Talisman(app, 
    force_https=True,  # Enable for production
    strict_transport_security=True,  # Enable for production
    session_cookie_secure=True,      # Enable for production
    content_security_policy=Config.SECURITY_HEADERS['Content-Security-Policy']
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize Flask-Mail
mail = FlaskMail(app)

# File upload settings
UPLOAD_FOLDER = Config.UPLOAD_FOLDER
ENCRYPTED_FOLDER = Config.ENCRYPTED_FOLDER
ENCRYPTED_KEY_FOLDER = Config.ENCRYPTED_KEY_FOLDER
DECRYPTED_FOLDER = Config.DECRYPTED_FOLDER

# Ensure all required directories exist
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, ENCRYPTED_KEY_FOLDER, DECRYPTED_FOLDER, 'logs']:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = Config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = Config.MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = Config.MAIL_DEFAULT_SENDER

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Ensure the database directory exists before any DB connection
os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)

# Database connection function
def get_db():
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database
def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verification_token TEXT,
            failed_login_attempts INTEGER DEFAULT 0,
            last_failed_login TIMESTAMP,
            account_locked_until TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            key_filename TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'encrypted',
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            share_token TEXT,
            token_created_time TIMESTAMP,
            otp TEXT,
            otp_generated_time TIMESTAMP,
            otp_attempts INTEGER DEFAULT 0,
            encrypted_aes_key TEXT,
            private_key TEXT,
            original_sha256_hash TEXT,
            receiver_email TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()
init_performance_db()

# === File upload settings ===
UPLOAD_FOLDER = 'static/uploads'
ENCRYPTED_FOLDER = 'static/encrypted'
ENCRYPTED_KEY_FOLDER = 'static/encrypted_keys'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}

# Ensure folders exist
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, ENCRYPTED_KEY_FOLDER]:
    os.makedirs(folder, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'afeefahzaini@gmail.com'
app.config['MAIL_PASSWORD'] = 'ukyj fegz ujei epcb'  # The 16-char app password
app.config['MAIL_DEFAULT_SENDER'] = 'your_gmail_address@gmail.com'

mail = FlaskMail(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# =====================
# ROUTES
# =====================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        if not name or len(name) < 2 or len(name) > 100:
            flash('Name must be between 2 and 100 characters.', 'danger')
            return render_template('register.html')
        if not validate_email(email):
            flash('Invalid email address.', 'danger')
            return render_template('register.html')
        if not validate_password(password):
            flash('Password does not meet requirements.', 'danger')
            return render_template('register.html')
        # Use bcrypt for password hashing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        verification_token = secrets.token_urlsafe(32)

        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (name, email, password, verified, verification_token) VALUES (?, ?, ?, 0, ?)',
                (name, email, hashed_password, verification_token)
            )
            conn.commit()
            # Send verification email
            verify_url = f"http://127.0.0.1:5000/verify-email?token={verification_token}"
            msg = Message(
                subject="Verify your email",
                recipients=[email],
                html=f"""
                    <p>Thank you for registering!</p>
                    <p>Click the link below to verify your email address:</p>
                    <a href="{verify_url}">{verify_url}</a>
                """
            )
            mail.send(msg)
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        cursor = conn.execute('SELECT id, name, password, verified, failed_login_attempts, account_locked_until FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        if user:
            if user['account_locked_until'] and datetime.now() < datetime.fromisoformat(user['account_locked_until']):
                log_security_event('login_attempt_locked', f"Locked account attempt: {email} from IP {request.remote_addr}")
                flash('Account is temporarily locked. Please try again later.', 'danger')
                return redirect(url_for('login'))
            if verify_password(password, user['password']):
                if user['verified'] == 1:
                    conn.execute('UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?', (user['id'],))
                    conn.commit()
                    session['user_id'] = user['id']
                    session['user_name'] = user['name']
                    session.permanent = True
                    log_security_event('login_success', f"User {email} logged in from IP {request.remote_addr}")
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Please verify your email before logging in.', 'warning')
            else:
                failed_attempts = user['failed_login_attempts'] + 1
                if failed_attempts >= 5:
                    lock_until = datetime.now() + timedelta(minutes=15)
                    conn.execute('UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?',
                               (failed_attempts, lock_until.isoformat(), user['id']))
                    log_security_event('account_locked', f"Account locked for {email} due to multiple failed attempts from IP {request.remote_addr}")
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                else:
                    conn.execute('UPDATE users SET failed_login_attempts = ? WHERE id = ?', (failed_attempts, user['id']))
                    log_security_event('login_failed', f"Failed login for {email} from IP {request.remote_addr}")
                    flash('Invalid email or password.', 'danger')
                conn.commit()
        else:
            log_security_event('login_failed', f"Failed login for {email} from IP {request.remote_addr}")
            flash('Invalid email or password.', 'danger')
        conn.close()
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.execute('''
        SELECT id, original_filename, encrypted_filename, key_filename, sha256_hash, status, upload_time
        FROM videos
        WHERE user_id = ?
    ''', (session['user_id'],))
    videos = cursor.fetchall()
    conn.close()

    # Pop private key from session if present
    private_key = session.pop('private_key', None)

    return render_template('dashboard.html', user_name=session.get('user_name'), videos=videos, private_key=private_key)

@app.route('/logout')
def logout():
    log_security_event('logout', f"User {session.get('user_name')} (ID: {session.get('user_id')}) logged out from IP {request.remote_addr}")
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    if 'video_file' not in request.files:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('dashboard'))
    file = request.files['video_file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('dashboard'))
    valid, msg = validate_file_upload(file)
    if not valid:
        flash(msg, 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Start performance monitoring
        start_time = time.time()
        initial_cpu = psutil.cpu_percent()
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # Convert to MB

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # Get file size in MB
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)

        # === Calculate original file hash ===
        original_sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                original_sha256_hash.update(block)
        original_file_hash = original_sha256_hash.hexdigest()

        # === AES Encryption using PyCryptodome ===
        key = get_random_bytes(32)
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC)
        iv = cipher.iv

        encrypted_filename = f'encrypted_{filename}'
        encrypted_filepath = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

        with open(filepath, 'rb') as fin:
            plaintext = fin.read()

        ciphertext = cipher.encrypt(pad(plaintext, CryptoAES.block_size))

        with open(encrypted_filepath, 'wb') as fout:
            fout.write(iv + ciphertext)

        # === ECC Encryption of AES key ===
        ecc = ECC()
        private_key = ecc.k
        public_key = ecc.gen_pubKey(private_key)
        aes_key_str = base64.b64encode(key).decode()
        C1, C2 = ecc.encryption(public_key, aes_key_str)
        
        # Format encrypted key components
        encrypted_aes_key = f"{C1[0]},{C1[1]},{C2}"

        # Save keys and calculate hash
        key_filename = f'key_{filename}.txt'
        with open(os.path.join(ENCRYPTED_KEY_FOLDER, key_filename), 'w') as f:
            f.write(f"{C1[0]},{C1[1]},{C2}")

        sha256_hash = hashlib.sha256()
        with open(encrypted_filepath, 'rb') as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(block)
        file_hash = sha256_hash.hexdigest()

        # End performance monitoring
        end_time = time.time()
        final_cpu = psutil.cpu_percent()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024

        # Calculate metrics
        encryption_time_ms = (end_time - start_time) * 1000
        cpu_usage_percent = (initial_cpu + final_cpu) / 2
        memory_usage_mb = final_memory - initial_memory

        # Insert into database with encrypted key components and original file hash
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO videos (
                user_id, original_filename, encrypted_filename, 
                key_filename, sha256_hash, status, encrypted_aes_key, 
                private_key, original_sha256_hash
            )
            VALUES (?, ?, ?, ?, ?, 'encrypted', ?, ?, ?)
        ''', (
            session['user_id'], filename, encrypted_filename, 
            key_filename, file_hash, encrypted_aes_key, 
            str(private_key), original_file_hash
        ))
        video_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Store private key in session for one-time download
        session['private_key'] = str(private_key)
        log_security_event('file_upload', f"User {session.get('user_name')} (ID: {session.get('user_id')}) uploaded file: {filename}")
        flash(f'File encrypted successfully in {encryption_time_ms:.0f}ms', 'success')

        save_metrics(
            session['user_id'],
            video_id,
            file_size_mb,
            encryption_time_ms,
            cpu_usage_percent,
            memory_usage_mb,
            'encryption'
        )

        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'Encryption failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    log_security_event('file_download', f"User {session.get('user_name')} (ID: {session.get('user_id')}) downloaded file: {filename}")
    return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)

@app.route('/secure-access/<token>', methods=['GET', 'POST'])
def secure_access(token):
    conn = get_db()
    cursor = conn.cursor()

    # Validate token and retrieve row
    cursor.execute('''
        SELECT id, encrypted_filename, otp, otp_generated_time, otp_attempts, token_created_time, receiver_email
        FROM videos WHERE share_token = ?
    ''', (token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return "Invalid or expired link.", 404

    video_id, encrypted_filename, otp_saved, otp_time, attempts, token_created, receiver_email = row

    # Expire token after 24 hours
    if not token_created:
        token_created = datetime.now()
        cursor.execute("UPDATE videos SET token_created_time = ? WHERE id = ?", (token_created, video_id))
        conn.commit()
    elif datetime.now() > datetime.strptime(token_created, '%Y-%m-%d %H:%M:%S.%f') + timedelta(hours=24):
        conn.close()
        return "This secure link has expired. Please request a new one."

    # If GET, send OTP to receiver_email and show OTP form
    if request.method == 'GET':
        otp = str(random.randint(100000, 999999))
        now = datetime.now()
        cursor.execute("UPDATE videos SET otp = ?, otp_generated_time = ?, otp_attempts = 0 WHERE id = ?",
                       (otp, now, video_id))
        conn.commit()
        try:
            sg = SendGridAPIClient(Config.SENDGRID_API_KEY)
            message = SendGridMail(
                'afeefahzaini@gmail.com',
                receiver_email,
                'Your OTP for Secure Access',
                Content('text/html', f"<p>Your OTP is: <strong>{otp}</strong>. It will expire in 5 minutes.</p>")
            )
            sg.send(message)
            flash("OTP sent to your email.", "info")
        except Exception as e:
            flash("Failed to send OTP email.", "danger")
        conn.close()
        return render_template("verify_otp.html", token=token, recipient_email=receiver_email)

    # If POST, handle OTP verification or resend
    if request.method == 'POST':
        if 'resend' in request.form:
            otp = str(random.randint(100000, 999999))
            now = datetime.now()
            cursor.execute("UPDATE videos SET otp = ?, otp_generated_time = ?, otp_attempts = 0 WHERE id = ?",
                           (otp, now, video_id))
            conn.commit()
            try:
                sg = SendGridAPIClient(Config.SENDGRID_API_KEY)
                message = SendGridMail(
                    'afeefahzaini@gmail.com',
                    receiver_email,
                    'Your new OTP for Secure Access',
                    Content('text/html', f"<p>Your new OTP is: <strong>{otp}</strong>. It will expire in 5 minutes.</p>")
                )
                sg.send(message)
                flash("New OTP sent successfully.", "info")
            except Exception as e:
                flash("Failed to resend OTP.", "danger")
            conn.close()
            return render_template("verify_otp.html", token=token)
        elif 'otp' in request.form:
            entered_otp = request.form['otp']
            if not otp_saved or not otp_time:
                flash("OTP not generated yet.", "danger")
                return render_template("verify_otp.html", token=token)
            otp_time_dt = datetime.strptime(otp_time, '%Y-%m-%d %H:%M:%S.%f')
            if datetime.now() > otp_time_dt + timedelta(minutes=5):
                flash("OTP expired. Please click resend.", "danger")
                return render_template("verify_otp.html", token=token)
            if attempts >= 5:
                flash("Too many incorrect attempts. Try resending OTP.", "danger")
                return render_template("verify_otp.html", token=token)
            if entered_otp == otp_saved:
                cursor.execute("UPDATE videos SET otp_attempts = 0 WHERE id = ?", (video_id,))
                conn.commit()
                conn.close()
                return send_from_directory(ENCRYPTED_FOLDER, encrypted_filename, as_attachment=True)
            else:
                cursor.execute("UPDATE videos SET otp_attempts = otp_attempts + 1 WHERE id = ?", (video_id,))
                conn.commit()
                flash("Invalid OTP. Please try again.", "danger")
                return render_template("verify_otp.html", token=token)
    conn.close()
    return render_template("verify_otp.html", token=token)

@app.route('/share/<int:video_id>', methods=['POST'])
def share_video(video_id):
    if 'user_id' not in session:
        flash("Please log in.", "danger")
        return redirect(url_for('login'))
    recipient_email = request.form['recipient_email'].strip()
    if not validate_email(recipient_email):
        flash('Invalid recipient email address.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT encrypted_filename FROM videos WHERE id = ? AND user_id = ?", (video_id, session['user_id']))
    row = cursor.fetchone()
    if not row:
        conn.close()
        flash("Video not found or unauthorized.", "danger")
        return redirect(url_for('dashboard'))

    encrypted_filename = row[0]
    share_token = secrets.token_urlsafe(16)

    cursor.execute("UPDATE videos SET share_token = ?, receiver_email = ? WHERE id = ?", (share_token, recipient_email, video_id))
    conn.commit()
    conn.close()

    share_link = f"http://127.0.0.1:5000/secure-access/{share_token}"  # Replace with real domain later

    # Send via SendGrid
    message = SendGridMail(
        'afeefahzaini@gmail.com',
        recipient_email,
        'You have received a secure encrypted video',
        Content('text/html', f"""
            <p>Hello,</p>
            <p>You have received a secure video. Click the link below to access it:</p>
            <a href="{share_link}">{share_link}</a>
            <p>This link is private and may expire within 24 hours.</p>
        """)
    )

    try:
        sg = SendGridAPIClient(Config.SENDGRID_API_KEY)
        sg.send(message)
        log_security_event('share_video', f"User {session.get('user_name')} (ID: {session.get('user_id')}) shared video ID {video_id} with {recipient_email}")
        flash("Secure share link sent successfully.", "success")
    except Exception as e:
        print("SendGrid error:", e.body if hasattr(e, 'body') else str(e))  # << this line logs actual error
        flash("Failed to send email. Check API key or logs.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/download-key-bundle/<filename>')
def download_key_bundle(filename):
    if 'user_id' not in session:
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Please log in to download keys'
        }), 401

    # Check if the user has access to this file
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id FROM videos 
        WHERE user_id = ? AND (original_filename = ? OR encrypted_filename = ?)
    ''', (session['user_id'], filename, f'encrypted_{filename}'))
    video = cursor.fetchone()
    conn.close()

    if not video:
        return jsonify({
            'error': 'Unauthorized',
            'message': 'You do not have access to these keys'
        }), 403

    # Check if bundle already exists in cache directory
    cache_dir = os.path.join('static', 'key_bundles')
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f'key_bundle_{filename}.json')
    
    # If cached bundle exists and is recent (less than 1 hour old), serve it
    if os.path.exists(cache_file):
        file_age = datetime.now().timestamp() - os.path.getmtime(cache_file)
        if file_age < 3600:  # 1 hour cache
            return send_file(
                cache_file,
                as_attachment=True,
                download_name=f'key_bundle_{filename}.json',
                mimetype='application/json'
            )

    # If not cached or cache expired, generate new bundle
    private_path = os.path.join(ENCRYPTED_KEY_FOLDER, f'private_{filename}.txt')
    encrypted_key_path = os.path.join(ENCRYPTED_KEY_FOLDER, f'key_{filename}.txt')

    if not os.path.exists(private_path) or not os.path.exists(encrypted_key_path):
        return jsonify({
            'error': 'Key files not found',
            'message': 'The required key files are missing or inaccessible'
        }), 404

    try:
        with open(private_path, 'r') as f1, open(encrypted_key_path, 'r') as f2:
            private_key = f1.read().strip()
            encrypted_key = f2.read().strip()

        # Create bundle content with enhanced metadata
        bundle = {
            "filename": filename,
            "ecc_private_key": private_key,
            "ecc_encrypted_aes_key": encrypted_key,
            "generated_at": datetime.now().isoformat(),
            "generated_for": session.get('user_name', 'unknown'),
            "instructions": "Use these keys in the decrypt page to decrypt your video file. Keep these keys secure and never share them."
        }

        # Save to cache
        with open(cache_file, 'w') as f:
            json.dump(bundle, f, indent=2)

        log_security_event('key_bundle_download', f"User {session.get('user_name')} (ID: {session.get('user_id')}) downloaded key bundle for: {filename}")
        return send_file(
            cache_file,
            as_attachment=True,
            download_name=f'key_bundle_{filename}.json',
            mimetype='application/json'
        )

    except Exception as e:
        return jsonify({
            'error': 'Bundle generation failed',
            'message': str(e)
        }), 500

@app.route('/qr/bundle/<filename>')
def generate_bundle_qr(filename):
    if 'user_id' not in session:
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Please log in to generate QR code'
        }), 401

    try:
        # Generate a temporary access token
        temp_token = secrets.token_urlsafe(32)
        
        # Store the token with an expiration time (15 minutes)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE videos 
            SET temp_access_token = ?,
                token_expiry = ? 
            WHERE user_id = ? AND (original_filename = ? OR encrypted_filename = ?)
        ''', (temp_token, 
              (datetime.now() + timedelta(minutes=15)).isoformat(),
              session['user_id'], 
              filename, 
              f'encrypted_{filename}'))
        conn.commit()
        conn.close()

        # Use the configured external URL with the temporary token
        download_url = f"{Config.EXTERNAL_URL}/secure-bundle/{temp_token}"
        
        # Generate QR code with error correction
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(download_url)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to buffer
        buffer = io.BytesIO()
        qr_img.save(buffer, format="PNG", optimize=True, quality=95)
        buffer.seek(0)
        
        # Cache control headers for better performance
        response = send_file(buffer, mimetype='image/png')
        response.headers['Cache-Control'] = 'public, max-age=300'  # Cache for 5 minutes
        return response
        
    except Exception as e:
        return jsonify({
            'error': 'QR generation failed',
            'message': str(e)
        }), 500

@app.route('/secure-bundle/<token>')
def secure_bundle_access(token):
    # Validate the temporary access token
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT original_filename, token_expiry 
        FROM videos 
        WHERE temp_access_token = ?
    ''', (token,))
    result = cursor.fetchone()
    conn.close()

    if not result or datetime.now() > datetime.fromisoformat(result[1]):
        return jsonify({
            'error': 'Invalid or expired token',
            'message': 'This QR code has expired. Please generate a new one.'
        }), 401

    filename = result[0]
    return download_key_bundle(filename)

@app.route('/key/<filename>')
def download_key_file(filename):
    return send_from_directory(ENCRYPTED_KEY_FOLDER, filename, as_attachment=True)

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'encrypted_video' not in request.files:
            flash('Please upload an encrypted video file.', 'danger')
            return redirect(url_for('decrypt'))

        encrypted_file = request.files['encrypted_video']
        private_key = request.form.get('private_key')
        
        if not private_key:
            flash('Please enter your private key.', 'danger')
            return redirect(url_for('decrypt'))

        if encrypted_file.filename == '':
            flash('No video file selected.', 'danger')
            return redirect(url_for('decrypt'))

        try:
            filename = secure_filename(encrypted_file.filename)
            base_filename = filename.replace('encrypted_', '')
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT encrypted_aes_key 
                FROM videos 
                WHERE original_filename = ? OR encrypted_filename = ?
            ''', (base_filename, filename))
            result = cursor.fetchone()
            conn.close()

            if not result or not result[0]:
                flash('Encrypted AES key not found for this video. Please ensure the file was encrypted using this system.', 'danger')
                return redirect(url_for('decrypt'))

            encrypted_key_parts = result[0].split(',')
            C1 = (int(encrypted_key_parts[0]), int(encrypted_key_parts[1]))
            C2 = int(encrypted_key_parts[2])

            ecc = ECC()
            try:
                aes_key_str = ecc.decryption(C1, C2, int(private_key))
                aes_key = base64.b64decode(aes_key_str)
            except Exception as e:
                flash('Failed to decrypt: Invalid private key.', 'danger')
                return redirect(url_for('decrypt'))

            enc_filename = secure_filename(encrypted_file.filename)
            enc_path = os.path.join('static/encrypted', enc_filename)
            encrypted_file.save(enc_path)

            try:
                with open(enc_path, 'rb') as f:
                    iv = f.read(16)
                    ciphertext = f.read()
                cipher = CryptoAES.new(aes_key, CryptoAES.MODE_CBC, iv=iv)
                decrypted_data = unpad(cipher.decrypt(ciphertext), CryptoAES.block_size)

                # Save decrypted video as a temp file for verification
                session_id = session.get('user_id', 'anon')
                temp_decrypted_filename = f'temp_{session_id}_{base_filename}'
                temp_decrypted_path = os.path.join('static/decrypted', temp_decrypted_filename)
                with open(temp_decrypted_path, 'wb') as out:
                    out.write(decrypted_data)

                # Store info in session for verification
                session['temp_decrypted_file'] = temp_decrypted_filename
                session['temp_decrypted_original'] = base_filename

                # Clean up temporary encrypted file with retry loop for Windows
                for _ in range(5):
                    try:
                        os.remove(enc_path)
                        break
                    except PermissionError:
                        time.sleep(0.1)

                # Instead of redirecting, show success and button to verify
                return render_template('decrypt.html', show_verify_button=True)

            except ValueError as ve:
                flash('Decryption failed: Invalid padding or corrupted data.', 'danger')
                return redirect(url_for('decrypt'))
            except Exception as e:
                flash(f'Decryption failed: {str(e)}', 'danger')
                return redirect(url_for('decrypt'))

        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('decrypt'))

    return render_template('decrypt.html')

@app.route('/verify', methods=['GET'])
def verify_integrity():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    temp_decrypted_filename = session.get('temp_decrypted_file')
    base_filename = session.get('temp_decrypted_original')
    if not temp_decrypted_filename or not base_filename:
        flash('No decrypted file found for verification. Please decrypt a file first.', 'danger')
        return redirect(url_for('decrypt'))

    temp_decrypted_path = os.path.join('static/decrypted', temp_decrypted_filename)
    if not os.path.exists(temp_decrypted_path):
        flash('Decrypted file missing. Please try decrypting again.', 'danger')
        return redirect(url_for('decrypt'))

    # Get original hash from database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT original_sha256_hash FROM videos WHERE original_filename = ? AND user_id = ?
    ''', (base_filename, session['user_id']))
    result = cursor.fetchone()
    conn.close()

    if not result:
        flash('Original file hash not found in database. Make sure this is a file that was encrypted through our system.', 'danger')
        return render_template('verify.html')

    original_hash = result[0]

    # Calculate SHA-256 hash of decrypted data
    with open(temp_decrypted_path, 'rb') as f:
        decrypted_data = f.read()
    sha256_hash = hashlib.sha256()
    sha256_hash.update(decrypted_data)
    calculated_hash = sha256_hash.hexdigest()

    verification_result = {
        'original_hash': original_hash,
        'calculated_hash': calculated_hash,
        'match': original_hash == calculated_hash
    }

    show_download = verification_result['match']

    return render_template('verify.html', verification_result=verification_result, show_download=show_download)

@app.route('/download-decrypted-temp')
def download_decrypted_temp():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    temp_decrypted_filename = session.get('temp_decrypted_file')
    base_filename = session.get('temp_decrypted_original')
    if not temp_decrypted_filename or not base_filename:
        flash('No decrypted file found.', 'danger')
        return redirect(url_for('decrypt'))
    temp_decrypted_path = os.path.join('static/decrypted', temp_decrypted_filename)
    if not os.path.exists(temp_decrypted_path):
        flash('Decrypted file missing.', 'danger')
        return redirect(url_for('decrypt'))
    log_security_event('decrypted_file_download', f"User {session.get('user_name')} (ID: {session.get('user_id')}) downloaded decrypted file: {base_filename}")
    response = send_from_directory('static/decrypted', temp_decrypted_filename, as_attachment=True, download_name=f'decrypted_{base_filename}')
    try:
        os.remove(temp_decrypted_path)
    except Exception:
        pass
    session.pop('temp_decrypted_file', None)
    session.pop('temp_decrypted_original', None)
    return response

@app.route('/performance')
def performance_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Get performance statistics for the current user
    stats_by_size, recent_metrics = get_performance_stats(user_id=session['user_id'])

    # Prepare data for charts
    size_ranges = []
    encryption_times = []
    cpu_usage = []
    memory_usage = []
    
    total_time = 0
    total_cpu = 0
    total_memory = 0
    count = 0

    for stat in stats_by_size:
        if stat[5] == 'encryption':  # Only show encryption stats in the main charts
            size_ranges.append(stat[0])
            encryption_times.append(float(stat[1]))
            cpu_usage.append(float(stat[2]))
            memory_usage.append(float(stat[3]))
            total_time += float(stat[1]) * stat[4]
            total_cpu += float(stat[2]) * stat[4]
            total_memory += float(stat[3]) * stat[4]
            count += stat[4]

    # Calculate averages
    avg_encryption_time = total_time / count if count > 0 else 0
    avg_cpu_usage = total_cpu / count if count > 0 else 0
    avg_memory_usage = total_memory / count if count > 0 else 0

    return render_template('performance.html',
                         size_ranges=size_ranges,
                         encryption_times=encryption_times,
                         cpu_usage=cpu_usage,
                         memory_usage=memory_usage,
                         avg_encryption_time=avg_encryption_time,
                         avg_cpu_usage=avg_cpu_usage,
                         avg_memory_usage=avg_memory_usage,
                         total_operations=count,
                         recent_metrics=recent_metrics)

@app.route('/api/performance-stats')
def api_performance_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # Pass the current user's ID to get_performance_stats
    stats_by_size, recent_metrics = get_performance_stats(user_id=session['user_id'])

    size_ranges = []
    encryption_times = []
    cpu_usage = []
    memory_usage = []
    count = 0

    for stat in stats_by_size:
        if stat[5] == 'encryption':
            size_ranges.append(stat[0])
            encryption_times.append(float(stat[1]))
            cpu_usage.append(float(stat[2]))
            memory_usage.append(float(stat[3]))
            count += stat[4]

    return jsonify({
        'size_ranges': size_ranges,
        'encryption_times': encryption_times,
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage,
        'total_operations': count,
        'recent_metrics': recent_metrics
    })

@app.route('/verify-email')
def verify_email():
    token = request.args.get('token')
    if not token:
        flash('Invalid verification link.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE verification_token = ?', (token,))
    user = cursor.fetchone()
    if user:
        cursor.execute('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', (user[0],))
        conn.commit()
        flash('Email verified! You can now log in.', 'success')
    else:
        flash('Invalid or expired verification link.', 'danger')
    conn.close()
    return redirect(url_for('login'))

@app.before_request
def print_session():
    print(dict(session))

if __name__ == '__main__':
    app.run(debug=True)  # Disable debug mode in production