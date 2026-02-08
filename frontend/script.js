const DEFAULT_BACKEND = 'http://127.0.0.1:5000'; // Base URL

// Regex Patterns
const EMAIL_REGEX = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/; // Min 8 chars, 1 letter, 1 number

// --- Navigation Logic ---
// Handle hash changes for SPA-like feel on the index page
window.addEventListener('hashchange', handleHashChange);
window.addEventListener('DOMContentLoaded', handleHashChange);
window.addEventListener('DOMContentLoaded', checkAuthStatus); // Check auth on load

function handleHashChange() {
    const hash = location.hash;
    const hero = document.querySelector('.hero');
    const features = document.getElementById('features');
    const about = document.getElementById('about');
    const login = document.getElementById('login');
    const signup = document.getElementById('signup');
    const extension = document.getElementById('extension');

    // Only run this logic if these elements exist (i.e. we are on index.html)
    if (!hero || !login) return;

    // Reset all to hidden first
    hero.style.display = 'none';
    if (features) features.style.display = 'none';
    if (about) about.style.display = 'none';
    if (extension) extension.style.display = 'none';
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
        if (extension) extension.style.display = 'block';
    }
}

// --- Auth Logic ---
function checkAuthStatus() {
    const userEmail = localStorage.getItem('user_email');
    const navAuth = document.querySelector('.nav-auth');

    if (!navAuth) return;

    if (userEmail) {
        // User is logged in
        navAuth.innerHTML = `
            <span style="margin-right: 15px; font-weight: 500; color: var(--text-color);">Hello, ${userEmail.split('@')[0]}</span>
            <button class="btn btn-secondary" onclick="logoutUser()" style="display: inline-flex; align-items: center; gap: 5px;">
                <span class="material-icons-round" style="font-size: 1.2rem;">logout</span>
                Logout
            </button>
        `;
    } else {
        // User is logged out (Default state)
        navAuth.innerHTML = `
            <a href="index.html#login" class="btn btn-secondary">Login</a>
            <a href="index.html#signup" class="btn btn-primary">Get Started</a>
        `;
    }
}

function logoutUser() {
    localStorage.removeItem('user_email');
    alert("Logged out successfully.");
    checkAuthStatus();
    window.location.href = 'index.html'; // Redirect to home
}

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
            localStorage.setItem('user_email', result.email);
            checkAuthStatus(); // Update UI
            window.location.hash = ''; // Go to home
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

// --- QR Detection Logic ---
async function scanQR() {
    const loadingDiv = document.getElementById('qr-loading');
    const contentDiv = document.getElementById('qr-result-content');
    const resultContainer = document.getElementById('qr-result-container');
    const preview = document.getElementById('preview');
    // The Input ID in HTML is 'qr-file-input'
    const fileInput = document.getElementById('qr-file-input');

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        alert("Please upload a QR code image first.");
        return;
    }

    const file = fileInput.files[0];

    // UI Updates
    preview.style.opacity = '0.5';
    resultContainer.style.display = 'block';
    loadingDiv.style.display = 'block';
    contentDiv.innerHTML = '';
    contentDiv.style.display = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${DEFAULT_BACKEND}/scan_qr`, {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        // Hide loading
        loadingDiv.style.display = 'none';
        preview.style.opacity = '1';
        contentDiv.style.display = 'block';

        if (response.ok) {
            const isPhishing = result.is_phishing;
            const confidence = (result.confidence * 100).toFixed(2);
            const statusClass = isPhishing ? 'result-danger' : 'result-safe';
            const icon = isPhishing ? 'warning' : (result.label.includes('TEXT') ? 'text_fields' : 'verified_user');
            const color = isPhishing ? '#ef4444' : (result.label.includes('TEXT') ? '#3b82f6' : '#10b981');
            const statusText = isPhishing ? 'Phishing Detected' : result.label;

            contentDiv.innerHTML = `
                <div class="glass-panel" style="padding: 20px; border-left: 5px solid ${color};">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                        <span class="material-icons-round" style="font-size: 2.5rem; color: ${color};">${icon}</span>
                        <div>
                            <h3 style="margin: 0;">${statusText}</h3>
                             ${!result.label.includes('TEXT') ? `<span style="color: var(--text-muted); font-size: 0.9rem;">Confidence: ${confidence}%</span>` : ''}
                        </div>
                    </div>
                    <p style="margin-bottom: 10px;"><strong>Decoded Content:</strong> <span style="word-break: break-all;">${result.url}</span></p>
                    <p style="color: var(--text-muted);">${isPhishing ?
                    'Use caution! The URL embedded in this QR code exhibits characteristics found in phishing attacks.' :
                    'The QR code content appears safe.'}</p>
                </div>
            `;
        } else {
            contentDiv.innerHTML = `<div class="result-card result-danger">
                <h3>Error</h3>
                <p>${result.error || 'Failed to scan QR code'}</p>
            </div>`;
        }

    } catch (err) {
        console.error(err);
        loadingDiv.style.display = 'none';
        preview.style.opacity = '1';
        contentDiv.style.display = 'block';
        contentDiv.innerHTML = `<div style="color: #ef4444; padding: 1rem; border: 1px solid #ef4444; border-radius: 8px;">
            <strong>Connection Failed:</strong> Could not reach the backend server.
        </div>`;
    }
}

// --- Semantic Analysis Logic ---
async function analyzeText() {
    const input = document.getElementById('text-input');
    const resultContainer = document.getElementById('text-result-container');
    const contentDiv = document.getElementById('text-result-content');
    const loadingDiv = document.getElementById('text-loading');

    if (!input || !input.value.trim()) {
        alert("Please paste some text first.");
        return;
    }

    // UI Reset
    resultContainer.style.display = 'block';
    resultContainer.classList.add('visible');
    loadingDiv.style.display = 'block';
    contentDiv.innerHTML = '';
    contentDiv.style.display = 'none';

    // Small delay to simulate processing (optional, UI feel)
    await new Promise(r => setTimeout(r, 600));

    loadingDiv.style.display = 'none';
    contentDiv.style.display = 'block';

    try {
        // Use the ported SemanticEngine
        if (typeof SemanticEngine === 'undefined') {
            throw new Error("Semantic Engine not loaded. Check semantic_engine.js inclusion.");
        }

        const analysis = SemanticEngine.analyzeMessage(input.value);
        console.log("Analysis Result:", analysis); // Debug

        let html = '';

        if (analysis.isSafe) {
            html = `
                <div class="glass-panel result-safe">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="material-icons-round" style="font-size: 2.5rem;">verified_user</span>
                        <div>
                            <h3 style="margin: 0;">No Threats Detected</h3>
                            <p style="margin: 5px 0 0 0; opacity: 0.9;">Message appears safe based on semantic analysis.</p>
                        </div>
                    </div>
                </div>
            `;
        } else {
            // Render Threats
            const riskLevel = analysis.riskScore > 20 ? 'Critical' : (analysis.riskScore > 10 ? 'High' : 'Medium');
            const color = analysis.riskScore > 15 ? '#ef4444' : '#f59e0b';

            html = `
                <div class="glass-panel" style="padding: 20px; border-left: 6px solid ${color}; background: rgba(255, 255, 255, 0.9);">
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 20px;">
                        <span class="material-icons-round" style="font-size: 3rem; color: ${color};">warning</span>
                        <div>
                            <h3 style="margin: 0; color: #0f172a;">${riskLevel} Risk Detected</h3>
                            <span style="display: inline-block; background: ${color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-top: 5px;">Score: ${analysis.riskScore}</span>
                        </div>
                    </div>
            `;

            // List Checks
            if (analysis.signals.length > 0) {
                html += `<div style="display: flex; flex-direction: column; gap: 10px;">`;
                analysis.signals.forEach(sig => {
                    const sevColor = sig.severity === 'HIGH' ? '#ef4444' : (sig.severity === 'MEDIUM' ? '#f97316' : '#3b82f6');
                    const icon = sig.severity === 'HIGH' ? 'error' : 'info';

                    html += `
                        <div style="display: flex; gap: 10px; align-items: flex-start; padding: 10px; background: rgba(0,0,0,0.03); border-radius: 8px;">
                            <span class="material-icons-round" style="color: ${sevColor}; font-size: 1.2rem; margin-top: 2px;">${icon}</span>
                            <div>
                                <strong style="display: block; color: #334155; font-size: 0.95rem;">${sig.type.replace(/_/g, ' ')}</strong>
                                <span style="color: #64748b; font-size: 0.9rem;">${sig.reason}</span>
                            </div>
                        </div>
                    `;
                });
                html += `</div>`;
            }

            html += `</div>`;
        }

        contentDiv.innerHTML = html;

    } catch (err) {
        console.error(err);
        contentDiv.innerHTML = `<div class="result-card result-danger"><h3>Error</h3><p>${err.message}</p></div>`;
    }
}
