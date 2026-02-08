from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse

app = Flask(__name__)
# Database Setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "users.db")
MODEL_PATH = os.path.join(BASE_DIR, "phishing_detector_model.pkl")

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''CREATE TABLE users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      email TEXT UNIQUE NOT NULL, 
                      password TEXT NOT NULL)''')
        conn.commit()
        conn.close()
        print(f"Database initialized at {DB_NAME}")

# Allow CORS from all origins including chrome extensions
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})
# Load the trained model
try:
    print(f"Loading model from {MODEL_PATH}...")
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully!")
except:
    print("Warning: Model file not found. Prediction will mock responses for testing.")
    model = None

# Regex Patterns
# Regex Patterns
EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
PASSWORD_REGEX = r'^(?=.*[A-Za-z])(?=.*\d).{8,}$' # Min 8 chars, at least 1 letter and 1 number

def extract_features(url):
    """Extracts features from a URL for phishing detection."""
    features = {}
    
    url = str(url)
    
    # Normalize URL: strip protocols and www
    clean_url = url.replace('https://', '').replace('http://', '').replace('www.', '')
    
    # 1. URL Length
    features['url_length'] = len(clean_url)
    
    # 2. Special character counts
    features['dot_count'] = clean_url.count('.')
    features['hyphen_count'] = clean_url.count('-')
    features['slash_count'] = clean_url.count('/')
    features['question_count'] = clean_url.count('?')
    features['equal_count'] = clean_url.count('=')
    features['at_count'] = clean_url.count('@')
    
    # 3. IP address detection
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))'
    features['has_ip'] = 1 if re.search(ip_pattern, clean_url) else 0
    
    # 4. Hostname analysis
    try:
        parse_url = 'http://' + clean_url
        parsed = urlparse(parse_url)
        hostname = parsed.netloc
        
        features['hostname_length'] = len(hostname)
        features['digit_count_hostname'] = sum(c.isdigit() for c in hostname)
    except:
        features['hostname_length'] = 0
        features['digit_count_hostname'] = 0

    return features

@app.route('/check', methods=['POST'])
def check_url():
    """API endpoint to check if a URL is phishing."""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
            
        # WHITELIST: Trust big domains immediately to avoid false positives
        # Google search URLs are long and have many query params, which confuses the model
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
            
        trusted_domains = [
            'google.com', 'www.google.com',
            'github.com', 'www.github.com',
            'stackoverflow.com', 'www.stackoverflow.com',
            'microsoft.com', 'www.microsoft.com',
            'apple.com', 'www.apple.com',
            'amazon.com', 'www.amazon.com',
            'youtube.com', 'www.youtube.com',
            'linkedin.com', 'www.linkedin.com',
            'twitter.com', 'x.com',
            'facebook.com', 'www.facebook.com',
            'instagram.com', 'www.instagram.com',
            'wikipedia.org', 'en.wikipedia.org'
        ]
        
        if domain in trusted_domains or any(domain.endswith('.' + d) for d in trusted_domains):
            return jsonify({
                'url': url,
                'is_phishing': False,
                'confidence': 0.0,
                'label': 'SAFE (Trusted)'
            })
        
        # Extract features
        features = extract_features(url)
        df_features = pd.DataFrame([features])
        
        # Predict
        prediction = model.predict(df_features)[0]
        probability = model.predict_proba(df_features)[0]
        
        result = {
            'url': url,
            'is_phishing': bool(prediction == 1),
            'confidence': float(max(probability)),
            'label': 'PHISHING' if prediction == 1 else 'SAFE'
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Validation
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    if not re.match(EMAIL_REGEX, email):
        return jsonify({'error': 'Invalid email format'}), 400
        
    if not re.match(PASSWORD_REGEX, password):
        return jsonify({'error': 'Password must be at least 8 characters long and contain at least one number'}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'User already exists'}), 409

        # Hash password and save
        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User registered successfully'}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """Login a user."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE email=?", (email,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            return jsonify({'message': 'Login successful', 'email': email}), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# QR Code Scan Endpoint
@app.route('/scan_qr', methods=['POST'])
def scan_qr():
    """Extracts URL from a QR code image and checks it."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Read the image using OpenCV
        import cv2
        import numpy as np

        # Decode image from buffer
        nparr = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        # Use OpenCV's built-in QR Code detector (No external DLLs required)
        detector = cv2.QRCodeDetector()
        
        # Strategy 1: Original Image
        extracted_data, points, _ = detector.detectAndDecode(img)
        
        # Strategy 2: Grayscale (Better for colored QRs)
        if not extracted_data:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            extracted_data, points, _ = detector.detectAndDecode(gray)
            
        # Strategy 3: Binary Thresholding (Best for low contrast/bad lighting)
        if not extracted_data:
            # Ensure gray exists (it should from Strategy 2)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
            extracted_data, points, _ = detector.detectAndDecode(thresh)

        if not extracted_data:
             return jsonify({'error': 'No QR code found. Try identifying the QR code with a better quality image.'}), 400
        
        print(f"Extracted QR Data: {extracted_data}")

        # Check if it's a URL
        is_url = extracted_data.startswith('http://') or extracted_data.startswith('https://') or 'www.' in extracted_data
        
        if not is_url:
             # It's plain text. Run basic keyword analysis (Mini Semantic Engine)
             lower_text = extracted_data.lower()
             
             threat_keywords = [
                 'otp', 'password', 'pin', 'cvv', 'verification code',
                 'urgent', 'immediately', 'suspend', 'block', 'expire',
                 'winner', 'prize', 'congratulations', 'lottery',
                 'bank', 'account', 'verify'
             ]
             
             found_threats = [word for word in threat_keywords if word in lower_text]
             
             if found_threats:
                 return jsonify({
                     'url': extracted_data,
                     'is_phishing': True,
                     'label': 'SUSPICIOUS TEXT',
                     'confidence': 0.85,
                     'reasons': sorted(found_threats)
                 })
             else:
                 return jsonify({
                     'url': extracted_data,
                     'is_phishing': False,
                     'label': 'SAFE TEXT',
                     'confidence': 0.0
                 })

        # Re-use the existing check_url logic internally
        # We Mock the request payload for the check_url function logic
        # OR better, just refactor the core logic out. 
        # For simplicity, let's just call the same logic here directly.
        
        # 1. Check Whitelist
        parsed = urlparse(extracted_data)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'): domain = domain[4:]
        
        trusted_domains = [
            'google.com', 'github.com', 'stackoverflow.com', 'microsoft.com', 
            'apple.com', 'amazon.com', 'youtube.com', 'linkedin.com', 
            'twitter.com', 'facebook.com', 'instagram.com', 'wikipedia.org'
        ]
        
        if domain in trusted_domains or any(domain.endswith('.' + d) for d in trusted_domains):
            return jsonify({
                'url': extracted_data,
                'is_phishing': False,
                'confidence': 0.0,
                'label': 'SAFE (Trusted)'
            })

        # 2. Predict using Model
        if model:
             features = extract_features(extracted_data)
             # extract_features returns a dict, pd.DataFrame expects a list of dicts
             # But wait, the function above `extract_features` returns a plain dict?
             # Let's check `check_url`. It constructs a DF inside? 
             # No, `check_url` calls `extract_features` which returns a dict? 
             # Wait, in lines 53-87, extract_features returns a dict.
             # In lines 130-131 of original file: 
             # features = extract_features(url)
             # df_features = pd.DataFrame([features])
             # So we do the same.
             
             df_features = pd.DataFrame([features])
             prediction = model.predict(df_features)[0]
             probability = model.predict_proba(df_features)[0]
             
             return jsonify({
                'url': extracted_data,
                'is_phishing': bool(prediction == 1),
                'confidence': float(max(probability)),
                'label': 'PHISHING' if prediction == 1 else 'SAFE'
            })
        else:
             # Mock response if model missing
             return jsonify({
                 'url': extracted_data,
                 'is_phishing': False,
                 'label': 'SAFE (Model Missing)',
                 'confidence': 0.0
             })

    except Exception as e:
        print(f"QR Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'model_loaded': bool(model is not None)})

if __name__ == '__main__':
    init_db()  # Initialize database on start
    app.run(host='0.0.0.0', port=5000, debug=True)
