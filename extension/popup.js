document.addEventListener('DOMContentLoaded', () => {
    checkCurrentPage();

    document.getElementById('check-again').addEventListener('click', () => {
        checkCurrentPage();
    });
});

async function checkCurrentPage() {
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const urlDisplay = document.getElementById('url-display');
    const resultSection = document.getElementById('result-section');

    // Show loading state
    statusIndicator.className = 'status-indicator loading';
    statusText.textContent = 'Checking current page...';
    resultSection.style.display = 'none';

    try {
        // Get current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url) {
            showError('Unable to get current page URL');
            return;
        }

        urlDisplay.textContent = tab.url;

        // Skip chrome:// and extension pages
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            showInfo('This page cannot be checked');
            return;
        }

        // Send message to background script to check URL
        chrome.runtime.sendMessage(
            { type: 'CHECK_CURRENT_URL' },
            (response) => {
                if (response.error) {
                    showError('Error: ' + response.error);
                } else {
                    showResult(response);
                }
            }
        );

    } catch (error) {
        showError('Error: ' + error.message);
    }
}

function showResult(data) {
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const resultSection = document.getElementById('result-section');
    const resultIcon = document.getElementById('result-icon');
    const resultMessage = document.getElementById('result-message');
    const confidenceFill = document.getElementById('confidence-fill');
    const confidenceText = document.getElementById('confidence-text');

    resultSection.style.display = 'block';

    const confidencePercent = (data.confidence * 100).toFixed(1);

    if (data.is_phishing) {
        statusIndicator.className = 'status-indicator danger';
        statusText.textContent = 'Phishing Detected!';
        resultIcon.textContent = '⚠️';
        resultMessage.innerHTML = `
      <strong>Warning!</strong><br>
      This site may be trying to steal your information.
    `;
        confidenceFill.style.width = confidencePercent + '%';
        confidenceFill.style.background = 'linear-gradient(135deg, #dc2626, #b91c1c)';
    } else {
        statusIndicator.className = 'status-indicator safe';
        statusText.textContent = 'Site Appears Safe';
        resultIcon.textContent = '✅';
        resultMessage.innerHTML = `
      <strong>No threats detected</strong><br>
      This site appears to be legitimate.
    `;
        confidenceFill.style.width = confidencePercent + '%';
        confidenceFill.style.background = 'linear-gradient(135deg, #10b981, #059669)';
    }

    confidenceText.textContent = `Confidence: ${confidencePercent}%`;
}

function showError(message) {
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const resultSection = document.getElementById('result-section');

    statusIndicator.className = 'status-indicator error';
    statusText.textContent = message;
    resultSection.style.display = 'none';
}

function showInfo(message) {
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const resultSection = document.getElementById('result-section');

    statusIndicator.className = 'status-indicator info';
    statusText.textContent = message;
    resultSection.style.display = 'none';
}
