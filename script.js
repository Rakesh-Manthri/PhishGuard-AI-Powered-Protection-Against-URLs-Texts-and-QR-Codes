const chatContainer = document.getElementById("chat-container");
const DEFAULT_BACKEND = 'http://127.0.0.1:5000/check';

async function sendMessage() {
    const userInputEl = document.getElementById('user-input');
    const userInput = userInputEl.value.trim();
    if (!userInput) return;

    // Add user message
    addMessage('user', userInput);
    userInputEl.value = '';

    // Show "Analyzing..."
    const loadingId = addMessage('bot', '🔍 Analyzing URL...');

    try {
        // Send to YOUR PhishGuard API (api.py)
        const response = await fetch(DEFAULT_BACKEND, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: userInput })
        });

        const result = await response.json();

        // Remove loading message
        document.getElementById(loadingId).remove();

        // Show Result
        if (result.error) {
            addMessage('bot', '❌ Error: ' + result.error);
        } else {
            const confidence = (result.confidence * 100).toFixed(2);
            let icon = result.is_phishing ? '⚠️' : '✅';
            let status = result.is_phishing ? 'PHISHING DETECTED' : 'SAFE';
            let color = result.is_phishing ? '#dc2626' : '#10b981';

            const messageHtml = `
                <div style="border-left: 4px solid ${color}; padding-left: 10px;">
                    <h3>${icon} ${status}</h3>
                    <p><strong>URL:</strong> ${result.url}</p>
                    <p><strong>Confidence:</strong> ${confidence}%</p>
                    <p>${result.is_phishing ? 'Be careful! This site looks suspicious.' : 'You are safe to visit this site.'}</p>
                </div>
            `;

            addMessage('bot', messageHtml, true);
        }

    } catch (err) {
        document.getElementById(loadingId).remove();
        addMessage('bot', '❌ Connection Failed. Is the backend running?\n(Run `start_api.bat`)');
        console.error(err);
    }
}

function addMessage(type, text, isHtml = false) {
    const msgDiv = document.createElement('div');
    msgDiv.className = type === 'user' ? 'user-message' : 'bot-message';
    msgDiv.id = 'msg-' + Date.now();

    if (isHtml) {
        msgDiv.innerHTML = text;
    } else {
        msgDiv.innerText = (type === 'user' ? '🧑 ' : '🛡️ ') + text;
    }

    chatContainer.appendChild(msgDiv);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    return msgDiv.id;
}

// Allow pressing Enter to send
document.getElementById('user-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

// Initial Welcome Message
setTimeout(() => {
    addMessage('bot', 'Welcome to PhishGuard! 🛡️\nPaste a URL below to check if it is a phishing link.');
}, 500);