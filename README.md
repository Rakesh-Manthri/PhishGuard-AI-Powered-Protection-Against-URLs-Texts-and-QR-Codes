# 🛡️ PhishGuard - AI-Powered Phishing Protection

PhishGuard is a comprehensive phishing detection system that uses Machine Learning to identify malicious URLs in real-time. It includes a Web Dashboard, a REST API, and a Chrome Extension for active browsing protection.

## ✨ Features
- **Real-Time Analysis**: Scans URLs instantly using a trained XGBoost model.
- **Chrome Extension**: Protects you while you browse by showing warning banners on suspicious sites.
- **Web Dashboard**: Manually check URLs via a clean web interface.
- **High Accuracy**: Trained on over 65,000 verified phishing and benign URLs.

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.8+**
- **Node.js & npm** (for the web dashboard)

### 1. Backend Setup (API)
The API handles the machine learning inference.

1. Install Python dependencies:
   ```bash
   pip install flask flask-cors pandas joblib scikit-learn xgboost
   ```

2. Navigate to the backend directory and start the API server:
   ```bash
   cd backend
   python api.py
   ```
   > The API will start on **http://127.0.0.1:5000**. Keep this terminal open.

### 2. Web Dashboard Setup
The dashboard allows you to test URLs manually.

1. Install Node.js dependencies:
   ```bash
   npm install
   ```

2. Start the web server:
   ```bash
   npm run serve-web
   ```
   > The dashboard will open at **http://localhost:5500**.

### 3. Chrome Extension Setup
Enable real-time protection in your browser.

1. Open Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** (top right).
3. Click **Load unpacked**.
4. Select the `extension` folder located in this repository.
5. The PhishGuard icon should appear in your toolbar.

---

## 🧠 Machine Learning Model
The system uses an **XGBoost Classifier** trained on linguistic and structural features of URLs (e.g., length, special characters, IP usage).

- **Training**: To retrain the model with the provided dataset:
  ```bash
  cd backend
  python train_model.py
  ```
  This will generate a new `phishing_detector_model.pkl` file.

- **Prediction (CLI)**: To test a URL from the command line:
  ```bash
  cd backend
  python predict.py "http://suspect-url.com"
  ```

## 📁 Project Structure
- **`backend/`**: Contains API server, ML models, and database.
  - `api.py`: Flask API server.
  - `phishing_detector_model.pkl`: Trained XGBoost model.
  - `users.db`: SQLite database for user data.
- **`frontend/`**: Contains the web dashboard (HTML/CSS/JS).
  - `index.html`: Main landing page.
  - `url_detection.html`, `qr_detection.html`: Specialized tool pages.
- **`extension/`**: Source code for the Chrome Extension (manifest, scripts, popup).

## ⚠️ Note
This project is for educational and research purposes. While highly accurate, no anti-phishing tool is 100% perfect. Always verify URLs carefully.
