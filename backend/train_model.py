import pandas as pd
import re
import random
import requests
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import kagglehub
import os
from urllib.parse import urlparse

# ---------------------------------------------------------
# 1. LOAD DATA
# ---------------------------------------------------------

def load_kaggle_data():
    """Downloads and loads the shashwatwork/web-page-phishing-detection-dataset."""
    urls = []
    labels = []
    
    try:
        print("Downloading Kaggle dataset via kagglehub...")
        path = kagglehub.dataset_download("shashwatwork/web-page-phishing-detection-dataset")
        print("Path to dataset files:", path)
        
        files = os.listdir(path)
        csv_file = next((f for f in files if f.endswith('.csv')), None)
        
        if csv_file:
            csv_path = os.path.join(path, csv_file)
            print(f"Loading data from {csv_path}...")
            df = pd.read_csv(csv_path)
            
            df['label'] = df['status'].map({'phishing': 1, 'legitimate': 0})
            df = df[['url', 'label']].dropna()
            
            urls = df['url'].tolist()
            labels = df['label'].tolist()
            
            print(f"Loaded {len(urls)} URLs.")
    except Exception as e:
        print(f"Error loading Kaggle dataset: {e}")
        
    return urls, labels

def load_alexa_data():
    """Downloads Alexa Top 1M benign sites."""
    urls = []
    labels = []
    try:
        print("Downloading Alexa Top 1M via kagglehub...")
        path = kagglehub.dataset_download("cheedcheed/top1m")
        csv_path = os.path.join(path, "top-1m.csv")
        
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path, header=None, names=['rank', 'url'])
            df = df.head(15000)
            
            urls = df['url'].tolist()
            labels = [0] * len(urls)
            print(f"Loaded {len(urls)} Benign URLs from Alexa Top 1M.")
    except Exception as e:
        print(f"Error loading Alexa data: {e}")
        
    return urls, labels

def load_github_phishing():
    """Downloads fresh phishing URLs from Phishing-Database GitHub repo."""
    urls = []
    labels = []
    try:
        print("Downloading fresh phishing feed from GitHub...")
        url = "https://raw.githubusercontent.com/Phishing-Database/phishing/master/additions/permanent/links.list"
        
        response = requests.get(url)
        if response.status_code == 200:
            lines = response.text.splitlines()
            urls = [line.strip() for line in lines if line.strip()]
            
            if len(urls) > 20000:
                print(f"Downsampling GitHub data from {len(urls)} to 20,000...")
                urls = random.sample(urls, 20000)
            
            labels = [1] * len(urls)
            print(f"Loaded {len(urls)} Fresh Phishing URLs from GitHub.")
        else:
            print(f"Failed to download GitHub data: Status {response.status_code}")
            
    except Exception as e:
        print(f"Error loading GitHub phishing data: {e}")
        
    return urls, labels

def load_stanpony_data():
    """Downloads stanpony/phishing_urls dataset from Hugging Face."""
    urls = []
    labels = []
    try:
        print("Downloading stanpony/phishing_urls from Hugging Face...")
        df = pd.read_csv("hf://datasets/stanpony/phishing_urls/train.csv")
        
        benign_df = df[df['label'] == 0].head(15000)
        phishing_df = df[df['label'] == 1].head(15000)
        
        df_sampled = pd.concat([benign_df, phishing_df])
        
        urls = df_sampled['text'].tolist()
        labels = df_sampled['label'].tolist()
        
        print(f"Loaded {len(urls)} URLs from stanpony dataset ({len(benign_df)} benign, {len(phishing_df)} phishing).")
    except Exception as e:
        print(f"Error loading stanpony dataset: {e}")
        
    return urls, labels

# ---------------------------------------------------------
# 2. FEATURE EXTRACTION
# ---------------------------------------------------------

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

# ---------------------------------------------------------
# 3. MAIN TRAINING FLOW
# ---------------------------------------------------------

def main():
    print("Starting process...")
    
    # Load datasets
    k_urls, k_labels = load_kaggle_data()
    a_urls, a_labels = load_alexa_data()
    g_urls, g_labels = load_github_phishing()
    s_urls, s_labels = load_stanpony_data()
    
    # Combine all data
    all_urls = k_urls + a_urls + g_urls + s_urls
    all_labels = k_labels + a_labels + g_labels + s_labels
    
    if not all_urls:
        print("No data loaded. Exiting.")
        return

    df = pd.DataFrame({'url': all_urls, 'label': all_labels})
    
    print(f"Total Data Points: {len(df)}")
    print(f"Class Distribution:\n{df['label'].value_counts()}")
    
    # Shuffle data
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Extract features
    print("Extracting features (this might take a moment)...")
    features_df = df['url'].apply(lambda x: pd.Series(extract_features(x)))
    
    X = features_df
    y = df['label']
    
    # Split data
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    print("Training XGBoost...")
    model = XGBClassifier(n_estimators=100, learning_rate=0.1, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    print("Evaluating...")
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    
    # Save model
    joblib.dump(model, 'phishing_detector_model.pkl', compress=3)
    print("Model saved as 'phishing_detector_model.pkl'")

if __name__ == "__main__":
    main()
