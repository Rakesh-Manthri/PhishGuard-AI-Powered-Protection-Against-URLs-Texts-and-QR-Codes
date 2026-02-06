from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
# Homoglyph detection utility
from utils.unicode_homoglyph import detect_homoglyph, analyze_hostname

app = Flask(__name__)
# Allow CORS from all origins including chrome extensions
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})
# Load the trained model
print("Loading model...")
model = joblib.load('phishing_detector_model.pkl')
print("Model loaded successfully!")

def extract_features(url):
    """Extracts features from a URL for phishing detection."""
    features = {}
    
    url = str(url)
    # Safer parsing: extract hostname and include path (do NOT mangle IDNs/punycode)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    clean_url = hostname + (parsed.path or "")
    
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
        features['hostname_length'] = len(hostname)
        features['digit_count_hostname'] = sum(c.isdigit() for c in hostname)
    except Exception:
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
        # ---- HARD RULE: Unicode homoglyph detection (before whitelist) ----
        try:
            is_homoglyph, matched_brand = detect_homoglyph(url)
            if is_homoglyph:
                original_h, normalized_h, skeleton = analyze_hostname(url)
                return jsonify({
                    'url': url,
                    'is_phishing': True,
                    'confidence': 0.999,
                    'label': 'PHISHING (homoglyph)',
                    'unicode_homoglyph': {
                        'is_homoglyph_attack': True,
                        'matched_brand': matched_brand,
                        'original_hostname': original_h,
                        'normalized_hostname': normalized_h,
                        'skeleton': skeleton
                    }
                })
        except Exception:
            # Fail open on homoglyph detection errors and continue with other checks
            pass
            
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
        # Note: unicode homoglyph detection is performed earlier (hard fail-fast)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'model_loaded': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
