

import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import sys
import time


# ---------------------------------------------------------
# feature extraction logic (Must be SAME as training!)
# ---------------------------------------------------------

def extract_features(url):
    features = {}
    
    # Ensure URL is a string
    url = str(url)
    
    # GLOBAL CLEANING: Normalize everything to "google.com/foo" format
    clean_url = url.replace('https://', '').replace('http://', '').replace('www.', '')
    
    # 1. URL Length (on clean url)
    features['url_length'] = len(clean_url)
    
    # 2. Count special characters
    features['dot_count'] = clean_url.count('.')
    features['hyphen_count'] = clean_url.count('-')
    features['slash_count'] = clean_url.count('/')
    features['question_count'] = clean_url.count('?')
    features['equal_count'] = clean_url.count('=')
    features['at_count'] = clean_url.count('@')
    
    # 3. Check for IP address usage
    ip_pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))'
    features['has_ip'] = 1 if re.search(ip_pattern, clean_url) else 0
    
    # 4. Hostname Length
    try:
        # Since we stripped protocol, parse_url needs one added back to parse correctly
        parse_url = 'http://' + clean_url
        parsed = urlparse(parse_url)
        
        hostname = parsed.netloc
        
        features['hostname_length'] = len(hostname)
        
        # 5. Numerical chars in hostname
        features['digit_count_hostname'] = sum(c.isdigit() for c in hostname)
        
    except:
        features['hostname_length'] = 0
        features['digit_count_hostname'] = 0

    return features

# ---------------------------------------------------------
# PREDICT
# ---------------------------------------------------------
def main():
    # Load Model
    try:
        model = joblib.load('phishing_detector_model.pkl')
    except:
        print("Model file not found. Run train_model.py first.")
        return

    # Check for command line arg, else use default list
    if len(sys.argv) > 1:
        urls_to_test = [sys.argv[1]]
    else:
        # ... (default listing) ...
        urls_to_test = [
            "http://google.com-security-check.xyz",
            "https://www.google.com",
            "google.com",
            "http://192.168.1.1/login.php",
            "https://mybank-verify-account.com",
            "https://github.com",
            "https://stackoverflow.com"
        ]

    print(f"Testing {len(urls_to_test)} URLs...")
    
    for url in urls_to_test:
        start_time = time.time()
        
        # 1. Extract features
        features = extract_features(url)
        df_features = pd.DataFrame([features])
        
        # 2. Predict
        prediction = model.predict(df_features)[0]
        label = "PHISHING" if prediction == 1 else "SAFE"
        
        end_time = time.time()
        elapsed_time_ms = (end_time - start_time) * 1000
        
        print(f"URL: {url}")
        print(f"Prediction: {label}")
        print(f"Time taken: {elapsed_time_ms:.2f} ms")
        print("-" * 30)

if __name__ == "__main__":
    main()
