// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PHISHING_DETECTED') {
        showPhishingWarning(message.data);
    }
});

function showPhishingWarning(data) {
    // Remove existing warning if any
    const existing = document.getElementById('phishguard-warning');
    if (existing) {
        existing.remove();
    }

    // Create warning banner
    const warning = document.createElement('div');
    warning.id = 'phishguard-warning';
    warning.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
    color: white;
    padding: 20px;
    text-align: center;
    z-index: 999999;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    animation: slideDown 0.3s ease-out;
  `;

    const confidencePercent = (data.confidence * 100).toFixed(1);

    warning.innerHTML = `
    <style>
      @keyframes slideDown {
        from { transform: translateY(-100%); }
        to { transform: translateY(0); }
      }
      #phishguard-warning button {
        background: white;
        color: #dc2626;
        border: none;
        padding: 10px 20px;
        margin: 0 5px;
        border-radius: 5px;
        font-weight: bold;
        cursor: pointer;
        font-size: 14px;
        transition: all 0.2s;
      }
      #phishguard-warning button:hover {
        transform: scale(1.05);
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
      }
    </style>
    <div style="max-width: 800px; margin: 0 auto;">
      <h2 style="margin: 0 0 10px 0; font-size: 24px; display: flex; align-items: center; justify-content: center; gap: 10px;">
        <span style="font-size: 32px;">⚠️</span>
        <span>Phishing Warning</span>
      </h2>
      <p style="margin: 10px 0; font-size: 16px;">
        This website has been identified as a potential phishing site with ${confidencePercent}% confidence.
      </p>
      <p style="margin: 10px 0; font-size: 14px; opacity: 0.9;">
        PhishGuard AI has detected suspicious patterns in this URL that match known phishing techniques.
      </p>
      <div style="margin-top: 15px;">
        <button id="phishguard-go-back">← Go Back to Safety</button>
        <button id="phishguard-continue" style="background: rgba(255,255,255,0.2); color: white;">
          Continue Anyway (Not Recommended)
        </button>
      </div>
    </div>
  `;

    document.body.insertBefore(warning, document.body.firstChild);

    // Add event listeners
    document.getElementById('phishguard-go-back').addEventListener('click', () => {
        window.history.back();
    });

    document.getElementById('phishguard-continue').addEventListener('click', () => {
        warning.remove();
    });
}
