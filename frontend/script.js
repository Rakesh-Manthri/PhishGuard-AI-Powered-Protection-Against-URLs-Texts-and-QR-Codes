const DEFAULT_BACKEND = 'http://127.0.0.1:5000'; // Base URL

// Regex Patterns
const EMAIL_REGEX = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/; // Min 8 chars, 1 letter, 1 number

// --- Navigation Logic ---
// Handle hash changes for SPA-like feel on the index page
window.addEventListener('hashchange', handleHashChange);
window.addEventListener('DOMContentLoaded', handleHashChange);

function handleHashChange() {
    const hash = location.hash;
    const hero = document.querySelector('.hero');
    const features = document.getElementById('features');
    const about = document.getElementById('about');
    const login = document.getElementById('login');
    const signup = document.getElementById('signup');

    // Only run this logic if these elements exist (i.e. we are on index.html)
    if (!hero || !login) return;

    // Reset all to hidden first
    hero.style.display = 'none';
    if (features) features.style.display = 'none';
    if (about) about.style.display = 'none';
    login.style.display = 'none';
    if (signup) signup.style.display = 'none';

    if (hash === '#login') {
        login.style.display = 'block';
    } else if (hash === '#signup') {
        signup.style.display = 'block';
    } else {
        // Default Home View
        hero.style.display = 'block';
        if (features) features.style.display = 'grid'; // Grid for features
        if (about) about.style.display = 'block';
    }
}

// --- Auth Logic ---
async function registerUser() {
    const email = document.getElementById('signup-email').value.trim();
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm-password').value;

    if (!email || !password || !confirmPassword) {
        alert("All fields are required.");
        return;
    }

    if (!EMAIL_REGEX.test(email)) {
        alert("Please enter a valid email address.");
        return;
    }

    if (!PASSWORD_REGEX.test(password)) {
        alert("Password must be at least 8 characters long and contain at least one letter and one number.");
        return;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        return;
    }

    try {
        const response = await fetch(`${DEFAULT_BACKEND}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const result = await response.json();

        if (response.ok) {
            alert("Registration successful! Please login.");
            window.location.hash = '#login';
        } else {
            alert("Error: " + result.error);
        }
    } catch (err) {
        console.error(err);
        alert("Failed to connect to server.");
    }
}

async function loginUser() {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;

    if (!email || !password) {
        alert("Please enter both email and password.");
        return;
    }

    try {
        const response = await fetch(`${DEFAULT_BACKEND}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const result = await response.json();

        if (response.ok) {
            alert("Login Successful! Welcome " + result.email);
            window.location.hash = ''; // Go to home
            // Here you would typically store a token
            localStorage.setItem('user_email', result.email);
        } else {
            alert("Login Failed: " + result.error);
        }
    } catch (err) {
        console.error(err);
        alert("Failed to connect to server.");
    }
}


// --- URL Detection Logic ---
async function scanURL() {
    const input = document.getElementById('url-input');
    const resultContainer = document.getElementById('result-container');
    const contentDiv = document.getElementById('result-content');
    const loadingDiv = document.getElementById('loading');

    if (!input || !input.value.trim()) {
        alert("Please enter a URL first.");
        return;
    }

    const url = input.value.trim();

    // UI Updates
    resultContainer.style.display = 'block';
    loadingDiv.style.display = 'block';
    contentDiv.innerHTML = '';
    contentDiv.style.display = 'none';

    try {
        const response = await fetch(`${DEFAULT_BACKEND}/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const result = await response.json();

        // Hide loading
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';

        if (result.error) {
            contentDiv.innerHTML = `<div class="result-card result-danger">
                <h3>Error</h3>
                <p>${result.error}</p>
            </div>`;
        } else {
            const isPhishing = result.is_phishing;
            const confidence = (result.confidence * 100).toFixed(2);
            const statusClass = isPhishing ? 'result-danger' : 'result-safe';
            const icon = isPhishing ? 'warning' : 'verified_user';
            const statusText = isPhishing ? 'Phishing Detected' : 'Safe to Visit';

            contentDiv.innerHTML = `
                <div class="glass-panel" style="padding: 20px; border-left: 5px solid ${isPhishing ? '#ef4444' : '#10b981'};">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                        <span class="material-icons-round" style="font-size: 2.5rem; color: ${isPhishing ? '#ef4444' : '#10b981'};">${icon}</span>
                        <div>
                            <h3 style="margin: 0;">${statusText}</h3>
                            <span style="color: var(--text-muted); font-size: 0.9rem;">Confidence: ${confidence}%</span>
                        </div>
                    </div>
                    <p style="margin-bottom: 10px;"><strong>Analyzed URL:</strong> ${result.url}</p>
                    <p style="color: var(--text-muted);">${isPhishing ?
                    'Use caution! This website exhibits characteristics commonly found in phishing attacks.' :
                    'Our analysis did not find any known malicious patterns. Always remain vigilant.'}</p>
                </div>
            `;
        }
    } catch (err) {
        console.error(err);
        loadingDiv.style.display = 'none';
        contentDiv.style.display = 'block';
        contentDiv.innerHTML = `<div style="color: #ef4444; padding: 1rem; border: 1px solid #ef4444; border-radius: 8px;">
            <strong>Connection Failed:</strong> Could not reach the backend server. Make sure 'start_api.bat' is running.
        </div>`;
    }
}

// --- QR Detection Logic (Mockup for UI demo) ---
async function scanQR() {
    const loadingDiv = document.getElementById('qr-loading');
    const contentDiv = document.getElementById('qr-result-content'); // result content
    const resultContainer = document.getElementById('qr-result-container'); // result container
    const preview = document.getElementById('preview');

    // Hide preview button to simulate processing state
    preview.style.opacity = '0.5';
    resultContainer.style.display = 'block';
    loadingDiv.style.display = 'block';
    contentDiv.innerHTML = '';

    // Simulate API delay
    await new Promise(r => setTimeout(r, 2000));

    loadingDiv.style.display = 'none';
    preview.style.opacity = '1';

    // Mock Result
    contentDiv.innerHTML = `
        <div class="glass-panel" style="padding: 20px; border-left: 5px solid #10b981;">
            <div style="display: flex; align-items: center; gap: 15px;">
                <span class="material-icons-round" style="font-size: 2.5rem; color: #10b981;">qr_code_2</span>
                <div>
                    <h3 style="margin: 0;">Safe QR Code</h3>
                    <p style="margin: 5px 0 0 0; color: var(--text-muted);">Decoded: https://example.com/menu</p>
                </div>
            </div>
        </div>
    `;
}

// --- Semantic Analysis Logic (Mockup for UI demo) ---
async function analyzeText() {
    const input = document.getElementById('text-input');
    const resultContainer = document.getElementById('text-result-container');
    const contentDiv = document.getElementById('text-result-content');
    const loadingDiv = document.getElementById('text-loading');

    if (!input || !input.value.trim()) {
        alert("Please paste some text first.");
        return;
    }

    resultContainer.style.display = 'block';
    loadingDiv.style.display = 'block';
    contentDiv.innerHTML = '';

    // Simulate API delay
    await new Promise(r => setTimeout(r, 1500));

    loadingDiv.style.display = 'none';

    // Mock Result - check for keywords to make it feel real
    const text = input.value.toLowerCase();
    const suspiciousKeywords = ['verify', 'urgent', 'suspend', 'bank', 'password', 'click here'];
    const isSuspicious = suspiciousKeywords.some(w => text.includes(w));

    if (isSuspicious) {
        contentDiv.innerHTML = `
            <div class="glass-panel" style="padding: 20px; border-left: 5px solid #f59e0b;">
                 <div style="display: flex; align-items: center; gap: 15px;">
                    <span class="material-icons-round" style="font-size: 2.5rem; color: #f59e0b;">warning</span>
                    <div>
                        <h3 style="margin: 0;">Potential Social Engineering</h3>
                        <p style="margin: 5px 0 0 0; color: var(--text-muted);">Urgency detected in message tone.</p>
                    </div>
                </div>
                <div style="margin-top: 15px; padding: 10px; background: rgba(245, 158, 11, 0.1); border-radius: 8px;">
                    <strong>Analysis:</strong> The text contains keywords often used in phishing attempts (e.g., urgency, account verification). Verify the sender identity.
                </div>
            </div>
        `;
    } else {
        contentDiv.innerHTML = `
            <div class="glass-panel" style="padding: 20px; border-left: 5px solid #10b981;">
                 <div style="display: flex; align-items: center; gap: 15px;">
                    <span class="material-icons-round" style="font-size: 2.5rem; color: #10b981;">thumb_up</span>
                    <div>
                        <h3 style="margin: 0;">Likely Safe</h3>
                        <p style="margin: 5px 0 0 0; color: var(--text-muted);">No common social engineering patterns detected.</p>
                    </div>
                </div>
            </div>
        `;
    }
}