# PhishGuard Chrome Extension

AI-Powered Real-Time Phishing Protection for Chrome

## 🚀 Setup Instructions

### Step 1: Install Python Dependencies

```powershell
pip install flask flask-cors
```

### Step 2: Start the API Server

```powershell
python api.py
```

The API will start on `http://127.0.0.1:5000`

### Step 3: Create Extension Icons

You need to create 3 PNG icons for the extension:
- `extension/icons/icon16.png` (16x16 pixels)
- `extension/icons/icon48.png` (48x48 pixels)
- `extension/icons/icon128.png` (128x128 pixels)

**Quick Method:** Use an online tool like [Favicon Generator](https://favicon.io/) to create these icons from a simple shield emoji 🛡️ or upload a logo.

### Step 4: Load Extension in Chrome

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right corner)
3. Click **Load unpacked**
4. Select the `extension` folder from your project: `C:\CyberSentinels\extension`
5. The extension should now appear in your extensions list!

### Step 5: Test the Extension

1. Make sure the API server is running (`python api.py`)
2. Visit any website
3. Click the PhishGuard icon in your toolbar to see the analysis
4. Try visiting a known phishing site to see the warning banner

## 📁 Project Structure

```
CyberSentinels/
├── api.py                          # Flask API server
├── train_model.py                  # Model training script
├── predict.py                      # CLI prediction tool
├── phishing_detector_model.pkl     # Trained model
└── extension/
    ├── manifest.json               # Extension configuration
    ├── background.js               # Background service worker
    ├── content.js                  # Content script (warning banner)
    ├── popup.html                  # Extension popup UI
    ├── popup.js                    # Popup logic
    ├── styles.css                  # Popup styling
    └── icons/
        ├── icon16.png             # 16x16 toolbar icon
        ├── icon48.png             # 48x48 management icon
        └── icon128.png            # 128x128 store icon
```

## 🎯 Features

- ✅ **Real-time URL checking** - Automatically scans every website you visit
- ✅ **Prominent warning banners** - Full-screen alerts for phishing sites
- ✅ **Confidence scores** - Shows how certain the AI is about its prediction
- ✅ **Beautiful UI** - Modern gradient design with smooth animations
- ✅ **One-click analysis** - Check any page from the toolbar popup
- ✅ **84% accuracy** - Trained on 65,000+ URLs

## 🔧 Testing URLs

Try these in Chrome with the extension active:

**Safe Sites:**
- `https://google.com`
- `https://github.com`
- `https://stackoverflow.com`

**Phishing Sites (detected by model):**
- `http://google.com-security-check.xyz`
- `https://rajabets3.com/en`
- `http://192.168.1.1/login.php`

## 🛠️ Troubleshooting

**Extension not working?**
1. Make sure `api.py` is running
2. Check the browser console (F12) for errors
3. Verify the extension is enabled in `chrome://extensions/`

**API connection errors?**
- Ensure the API is running on `http://127.0.0.1:5000`
- Check firewall settings
- Look for errors in the Python terminal

**Icons not showing?**
- Create the 3 required PNG files in the `icons` folder
- Use simple 16x16, 48x48, and 128x128 pixel images
- Reload the extension after adding icons

## 📊 Model Information

- **Algorithm:** XGBoost Classifier
- **Training Data:** 65,389 URLs
  - 35,715 benign URLs
  - 29,674 phishing URLs
- **Accuracy:** 84%
- **Features:** 10 URL-based features (length, special chars, IP detection, etc.)

## 🎨 Customization

You can customize the warning banner colors and text in `extension/content.js`, and the popup design in `extension/styles.css`.

## 📝 Notes

- The extension requires the API server to be running locally
- For production use, deploy the API to a cloud server (Heroku, AWS, etc.)
- Extension works only on http/https pages (not chrome:// pages)

---

Made with ❤️ using AI & Machine Learning
