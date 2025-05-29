# Video Encryption Web Application

A secure web application for encrypting and sharing video files using AES and ECC encryption.

## Features

- User authentication with email verification
- Video file encryption using AES-256
- Key management using Elliptic Curve Cryptography (ECC)
- Secure file sharing with OTP verification
- Performance monitoring and metrics
- File integrity verification

## Security Features

- CSRF protection
- Rate limiting
- Secure session management
- Password hashing with bcrypt
- Input validation
- Security headers (HSTS, CSP, etc.)
- File integrity checks using SHA-256

## Prerequisites

- Python 3.8+
- pip (Python package manager)
- Git

## Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd <repository-name>
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file with the following variables:
```
MAIL_USERNAME=your_gmail
MAIL_PASSWORD=your_app_password
SENDGRID_API_KEY=your_sendgrid_key
EXTERNAL_URL=http://localhost:5000
```

5. Initialize the database:
```bash
python app.py
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Access the application at `http://localhost:5000`

3. Register an account and verify your email

4. Upload and encrypt video files

5. Share encrypted files securely

## Deployment

The application is configured for deployment on Render. See `render.yaml` for configuration details.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 