const CONFIG = {
    // Debug settings (set to false in production)
    DEBUG: true,
    
    // API settings
    API: {
        ENDPOINT: 'http://localhost:5000',
        TIMEOUT: 5000
    },
    
    // Cache settings - optimized for your approach
    CACHE: {
        MAX_SIZE: 500, // Larger cache since we're always warning
        TTL: 30 * 60 * 1000, // 30 minutes (longer since we always warn)
        CLEANUP_INTERVAL: 5 * 60 * 1000 // 5 minutes
    },
    
    // Detection settings
    DETECTION: {
        HOVER_DELAY: 500,
        WARNING_AUTO_HIDE: 12000, // Slightly longer for educational value
        MAX_URL_LENGTH: 2048,
        SIMILARITY_THRESHOLD: 0.8
    },
    
    // Educational tips - expanded for variety
    EDUCATIONAL_TIPS: [
        "Scammers often pressure you to act quickly. Stay calm and verify.",
        "Check the URL carefully - look for misspellings or unusual characters.",
        "Legitimate companies won't ask for passwords via email or suspicious links.",
        "When in doubt, navigate to the official website directly instead of clicking links.",
        "Be extra cautious with urgent requests for personal or financial information.",
        "Always check the sender's email address carefully - scammers often use similar-looking addresses.",
        "Legitimate websites use HTTPS (the lock icon) for sensitive information.",
        "If an offer seems too good to be true, it probably is.",
        "Banks and financial institutions will never ask for passwords via email.",
        "Hover over links to see the actual destination before clicking.",
        "Use two-factor authentication whenever possible for added security.",
        "Keep your browser and extensions updated to the latest versions.",
        "Phishing sites often copy the design of legitimate sites - check the URL!",
        "Be suspicious of shortened URLs (bit.ly, tinyurl) from unknown sources.",
        "Look for grammar and spelling mistakes in suspicious emails or websites."
    ],
    
    // Popular domains for typosquatting detection
    POPULAR_DOMAINS: [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'ebay.com', 'instagram.com',
        'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com',
        'github.com', 'stackoverflow.com', 'reddit.com', 'youtube.com'
    ],
    
    // Suspicious patterns for detection
    SUSPICIOUS_PATTERNS: [
        /secure.*update/i,
        /verify.*account/i,
        /suspended.*account/i,
        /click.*here.*now/i,
        /urgent.*action/i,
        /limited.*time/i,
        /confirm.*identity/i,
        /account.*locked/i,
        /security.*alert/i,
        /immediate.*action/i
    ],
    
    // Suspicious character patterns
    SUSPICIOUS_CHAR_PATTERNS: [
        /[а-я]/i, // Cyrillic characters
        /[αβγδεζηθικλμνξοπρστυφχψω]/i, // Greek characters
        /xn--/, // Punycode
        /-{2,}/, // Multiple consecutive hyphens
        /\d{4,}/ // Long sequences of numbers
    ],
    
    // Validation settings
    VALIDATION: {
        ALLOWED_PROTOCOLS: ['http:', 'https:'],
        MAX_TEXT_LENGTH: 500,
        DANGEROUS_PARAMS: ['javascript', 'vbscript', 'data', 'file'],
        VALID_ACTIONS: ['checkURL', 'reportPhishing', 'getStats']
    }
};

// Export for different environments
// Service Worker (background script)
if (typeof self !== 'undefined' && typeof window === 'undefined') {
    self.CONFIG = CONFIG;
}
// Content Script (has window object)
else if (typeof window !== 'undefined') {
    window.CONFIG = CONFIG;
}
// Node.js (for testing)
else if (typeof module !== 'undefined' && module.exports) {
    module.exports = CONFIG;
}
