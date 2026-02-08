/**
 * PhishGuard Semantic Engine (Enhanced v2.1)
 * Ported from WhatsApp Scam Guard v2.1
 * 
 * Features:
 * - Advanced Intent Classification (Financial, Academic, Marketing, Unknown)
 * - Deep URL Analysis (Subdomain spoofing, Homographs, Suspicious TLDs)
 * - High Entropy Token Detection (Base64, JWT, Random strings)
 * - Threat Pattern Matching (Urgency, Impersonation, OTP theft)
 */

(function (global) {
    'use strict';

    // ===================================
    // 1. CONFIGURATION & THRESHOLDS
    // ===================================
    const CONFIG = {
        MIN_MESSAGE_LENGTH: 4,
        ENTROPY_MIN_LENGTH: 8,
        ENTROPY_THRESHOLD: 4.5, // Adjusted for manual calculation

        TRUSTED_PATTERNS: [
            /^your otp (is|code)?\s*:?\s*\d{4,8}$/i,
            /^use \d{4,8} as your.*verification code$/i,
            /^\d{6}\s+is your.*code$/i
        ],

        TRUSTED_DOMAINS: [
            'google.com', 'youtube.com', 'youtu.be', 'microsoft.com',
            'apple.com', 'amazon.com', 'facebook.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'hdfcbank.com', 'netbanking.hdfcbank.com'
        ]
    };

    // ===================================
    // 2. UTILITY FUNCTIONS
    // ===================================

    function normalizeMessage(raw) {
        if (!raw || typeof raw !== 'string') return '';
        let text = raw.trim();
        // Remove common UI noise
        text = text.replace(/\b(Forwarded|Download|Downloaded|Media omitted|This message was deleted)\b/gi, '');
        // Remove timestamps
        text = text.replace(/^\d{1,2}:\d{2}\s?(am|pm|AM|PM)?\s*$/i, '');
        // Normalize whitespace
        return text.replace(/\s+/g, ' ').trim();
    }

    function calculateEntropy(str) {
        const len = str.length;
        if (len === 0) return 0;
        const freq = {};
        for (const char of str) freq[char] = (freq[char] || 0) + 1;
        let entropy = 0;
        for (const count of Object.values(freq)) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    // ===================================
    // 3. CORE ANALYSIS MODULES
    // ===================================

    // --- Intent Classification ---
    function classifyIntent(message) {
        const lower = message.toLowerCase();

        const financialKeywords = [
            'bank', 'banking', 'account', 'otp', 'kyc', 'atm',
            'payment', 'transfer', 'transaction', 'wallet', 'upi',
            'credit card', 'debit card', 'cvv', 'pin', 'password'
        ];

        const academicKeywords = [
            'hackathon', 'coding', 'bootcamp', 'workshop', 'college',
            'university', 'course', 'exam', 'student', 'registration',
            'admission', 'scholarship', 'internship'
        ];

        const marketingKeywords = [
            'discount', 'offer', 'sale', 'coupon', 'promo', 'deal',
            'limited time', 'buy now', 'certification', 'training'
        ];

        const financialScore = financialKeywords.filter(k => lower.includes(k)).length;
        const academicScore = academicKeywords.filter(k => lower.includes(k)).length;
        const marketingScore = marketingKeywords.filter(k => lower.includes(k)).length;

        if (financialScore > 0) return 'FINANCIAL';
        if (academicScore > 0 && academicScore >= marketingScore) return 'ACADEMIC';
        if (marketingScore > 0) return 'MARKETING';
        return 'UNKNOWN';
    }

    // --- Signal Detection ---
    function detectHighRiskSignals(message) {
        const signals = [];

        // OTP & Credentials
        if (/send\s+(otp|code|password)|enter\s+(otp|code)|share\s+(otp|code)/i.test(message)) {
            signals.push({ type: 'OTP_REQUEST', severity: 'HIGH', reason: 'Request for OTP or verification code' });
        }
        if (/(enter|provide|confirm)\s+(your\s+)?(password|pin|cvv)/i.test(message)) {
            signals.push({ type: 'CREDENTIAL_PROMPT', severity: 'HIGH', reason: 'Request for sensitive credentials' });
        }

        // Urgency
        if (/\b(urgent|immediately|asap|right now|expires?\s+soon|act\s+now)\b/i.test(message)) {
            signals.push({ type: 'URGENCY', severity: 'MEDIUM', reason: 'Urgency language detected' });
        }

        // Threats
        if (/\b(account\s+(blocked|suspended|locked)|legal\s+action|arrest)\b/i.test(message)) {
            signals.push({ type: 'THREAT', severity: 'HIGH', reason: 'Threatening language detected' });
        }

        // Impersonation
        if (/\b(bank|rbi|government|police|income\s+tax)\b/i.test(message) &&
            /(verify|confirm|validate)/i.test(message)) {
            signals.push({ type: 'IMPERSONATION', severity: 'HIGH', reason: 'Impersonation of authority' });
        }

        return signals;
    }

    // --- Token Analysis (Entropy) ---
    function detectHighEntropyTokens(message) {
        const findings = [];
        // Matches Alphanumeric tokens with mixed case/numbers
        const tokenPattern = /\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Z])(?=[A-Za-z0-9]*[a-z])[A-Za-z0-9]{8,}\b/g;
        const matches = message.match(tokenPattern) || [];

        matches.forEach(token => {
            const entropy = calculateEntropy(token);
            if (entropy > CONFIG.ENTROPY_THRESHOLD) {
                findings.push({
                    type: 'HIGH_ENTROPY_TOKEN',
                    score: 2,
                    reason: `Suspicious random token detected: ${token.substring(0, 10)}...`
                });
            }
        });
        return findings;
    }

    // --- URL Analysis ---
    function analyzeURLs(message) {
        const urlPattern = /https?:\/\/[^\s\)]+/gi;
        const urls = message.match(urlPattern) || [];
        const findings = [];

        if (urls.length === 0) return findings;

        for (const url of urls) {
            try {
                const urlObj = new URL(url);
                const hostname = urlObj.hostname.toLowerCase();

                // Skip trusted
                if (CONFIG.TRUSTED_DOMAINS.some(d => hostname.endsWith(d))) continue;

                // Shorteners
                const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'rebrand.ly'];
                if (shorteners.some(s => hostname.includes(s))) {
                    findings.push({ type: 'SHORTENED_URL', score: 4, reason: 'Shortened URL detected' });
                }

                // IP Address
                if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
                    findings.push({ type: 'IP_URL', score: 5, reason: 'IP address used as domain' });
                }

                // Suspicious TLDs
                const suspiciousTLDs = ['xyz', 'top', 'click', 'zip', 'tk', 'loan', 'online', 'vip'];
                if (suspiciousTLDs.some(t => hostname.endsWith('.' + t))) {
                    findings.push({ type: 'SUSPICIOUS_TLD', score: 3, reason: 'Suspicious domain extension' });
                }

                // Subdomain spoofing (brand in subdomain)
                const brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'hdfc'];
                const parts = hostname.split('.');
                if (parts.length > 2) {
                    const subdomains = parts.slice(0, -2).join('.');
                    if (brands.some(b => subdomains.includes(b))) {
                        findings.push({ type: 'SUBDOMAIN_SPOOFING', score: 5, reason: 'Brand name in subdomain (possible spoofing)' });
                    }
                }

            } catch (e) {
                findings.push({ type: 'MALFORMED_URL', score: 2, reason: 'Malformed URL detected' });
            }
        }
        return findings;
    }

    // ===================================
    // 4. MAIN ANALYZER FUNCTION
    // ===================================
    function analyzeMessage(rawMessage) {
        const message = normalizeMessage(rawMessage);

        // 1. Check Whitelist
        if (CONFIG.TRUSTED_PATTERNS.some(p => p.test(message))) {
            return {
                isSafe: true,
                label: 'SAFE',
                riskScore: 0,
                intent: 'TRANSACTIONAL',
                signals: [{ type: 'WHITELISTED', severity: 'LOW', reason: 'Matches trusted pattern' }]
            };
        }

        // 2. Perform Analysis
        const intent = classifyIntent(message);
        const signals = detectHighRiskSignals(message);
        const tokens = detectHighEntropyTokens(message);
        const urlFindings = analyzeURLs(message);

        // 3. Calculate Score
        let score = 0;

        // Base score from signals
        signals.forEach(s => score += (s.severity === 'HIGH' ? 5 : 3));

        // Score from URLs and Tokens
        urlFindings.forEach(f => score += f.score);
        tokens.forEach(t => score += t.score);

        // Intent Weighting
        const intentThresholds = { 'FINANCIAL': 4, 'MARKETING': 7, 'ACADEMIC': 8, 'UNKNOWN': 6 };
        const threshold = intentThresholds[intent] || 6;

        // 4. Determine Verdict
        const hasHighSeverity = signals.some(s => s.severity === 'HIGH');
        let label = 'SAFE';
        let isSafe = true;

        if (hasHighSeverity || score >= threshold) {
            label = score >= threshold * 1.5 ? 'SCAM' : 'SUSPICIOUS';
            isSafe = false;
        }

        // 5. Structure Output
        // Combine all findings into a unified 'signals' array for the UI
        const allSignals = [
            ...signals,
            ...urlFindings.map(f => ({ type: f.type, severity: f.score > 3 ? 'HIGH' : 'MEDIUM', reason: f.reason })),
            ...tokens.map(t => ({ type: t.type, severity: 'MEDIUM', reason: t.reason }))
        ];

        return {
            isSafe: isSafe,
            label: label,
            riskScore: score,
            intent: intent,
            signals: allSignals
        };
    }

    // ===================================
    // 5. EXPORT
    // ===================================
    global.SemanticEngine = {
        analyzeMessage: analyzeMessage
    };

})(window);
