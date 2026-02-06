const API_URL = 'http://127.0.0.1:5000/check';

// Check URL against the phishing detection API
function checkURL(url) {
    return fetch(API_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
        .then(response => {
            if (!response.ok) {
                return { error: 'API request failed' };
            }
            return response.json();
        })
        .catch(error => {
            return { error: error.message };
        });
}

// Listen for URL updates (covers navigation and SPAs)
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.url) {
        const url = changeInfo.url;

        // Skip chrome:// and extension pages
        if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
            return;
        }

        checkURL(url).then(function (result) {
            if (result.is_phishing) {
                // Store warning
                chrome.storage.local.set({
                    ['warning_' + tabId]: {
                        url: url,
                        confidence: result.confidence,
                        timestamp: Date.now()
                    }
                });

                // Try to send message immediately
                chrome.tabs.sendMessage(tabId, {
                    type: 'PHISHING_DETECTED',
                    data: result
                }).catch(function () {
                    // Content script might not be ready
                });
            }
        });
    }
});

// Also re-send warning when tab finishes loading
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete') {
        chrome.storage.local.get(['warning_' + tabId], function (result) {
            const warning = result['warning_' + tabId];
            if (warning && warning.url === tab.url) {
                chrome.tabs.sendMessage(tabId, {
                    type: 'PHISHING_DETECTED',
                    data: {
                        is_phishing: true,
                        confidence: warning.confidence,
                        url: warning.url
                    }
                }).catch(function () { });
            }
        });
    }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    if (request.type === 'CHECK_CURRENT_URL') {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (tabs[0]) {
                checkURL(tabs[0].url).then(function (result) {
                    sendResponse(result);
                });
            } else {
                sendResponse({ error: 'No active tab found' });
            }
        });
        return true;
    }
});
