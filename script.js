const chatContainer = document.getElementById("chat-container");

async function sendMessage() {
    const userInputEl = document.getElementById('user-input');
    const userInput = userInputEl.value;
    if (!userInput) return;

    // Add user message
    const userMsg = document.createElement('div');
    userMsg.className = 'user-message';
    userMsg.innerText = '🧑 ' + userInput;
    chatContainer.appendChild(userMsg);
    chatContainer.scrollTop = chatContainer.scrollHeight;
    userInputEl.value = '';

    // 1) Immediate client analysis + UI
    const clientResult = await analyzeClient(userInput);
    displayResultBanner(clientResult.clientScore, clientResult.details);

    // 2) Fire-and-forget backend phishing scan (if enabled). Non-blocking and merges results when available.
    if (enableBackendEl && enableBackendEl.checked) {
        const endpoint = (backendEndpointEl && backendEndpointEl.value) ? backendEndpointEl.value : DEFAULT_BACKEND;
        postWithTimeout(endpoint, { text: userInput, urls: clientResult.urlScores.map(u => u.url) }, 1600)
            .then(serverRes => {
                if (!serverRes) return;
                // serverRes expected: { score: 0.8, label: 'phish', explain: [...] }
                const serverScore = Number(serverRes.score || 0);
                const merged = Math.max(clientResult.clientScore, serverScore);
                const mergedDetails = [...clientResult.details];
                if (serverRes.explain && serverRes.explain.length) mergedDetails.push(...serverRes.explain.slice(0, 5));
                mergedDetails.push(`fused with server (score ${serverScore})`);
                displayResultBanner(Number(merged.toFixed(3)), mergedDetails);
            });
    }

    // 3) Preserve existing chat behavior — send message to chat backend and show reply when available (non-blocking)
    (async() => {
        try {
            const response = await fetch('http://localhost:3000/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: userInput })
            });
            const data = await response.json();
            const botMsg = document.createElement('div');
            botMsg.className = 'bot-message';
            botMsg.innerText = '👩‍⚕️ ' + (data.reply || data.message || 'No reply');
            chatContainer.appendChild(botMsg);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        } catch (err) {
            // keep UI responsive; optionally log to console
            console.debug('chat backend unavailable', err && err.message);
        }
    })();
}

// Allow pressing Enter to send
document.getElementById('user-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        document.getElementById('send-btn').click();
    }
});