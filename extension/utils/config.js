const CONFIG = {
    DEBUG: true,
    
    CACHE: {
        MAX_SIZE: 500,
        TTL: 30 * 60 * 1000,
        CLEANUP_INTERVAL: 5 * 60 * 1000
    },
    
    DETECTION: {
        HOVER_DELAY: 500,
        WARNING_AUTO_HIDE: 12000,
        MAX_URL_LENGTH: 2048,
        SIMILARITY_THRESHOLD: 0.65,  // Lowered for better detection
        
        // Enhanced detection thresholds
        HOMOGRAPH_SIMILARITY_THRESHOLD: 0.8,
        LONG_DOMAIN_THRESHOLD: 30,
        MAX_SUBDOMAIN_LEVELS: 4,
        SUSPICIOUS_DIGIT_RATIO: 0.3,
        
        // Confidence score weights
        CONFIDENCE_WEIGHTS: {
            IP_ADDRESS: 0.95,
            SUSPICIOUS_TLD: 0.8,
            HOMOGRAPH: 0.9,
            TYPOSQUATTING_BASE: 0.5,
            SUBSTRING_ABUSE: 0.8,
            SUSPICIOUS_PATTERN: 0.7,
            SUSPICIOUS_CHARS: 0.65,
            LONG_DOMAIN: 0.65,
            EXCESSIVE_SUBDOMAINS: 0.75,
            SUSPICIOUS_DIGITS: 0.6,
            DOMAIN_STRUCTURE: 0.7,
            SUSPICIOUS_KEYWORDS: 0.75
        }
    },
    
    // Combined Singapore + Global domains (simplified)
    PROTECTED_DOMAINS: [
        // Singapore Government (highest priority)
        'singpass.gov.sg', 'cpf.gov.sg', 'iras.gov.sg', 'moe.gov.sg',
        'moh.gov.sg', 'hdb.gov.sg', 'mom.gov.sg', 'sla.gov.sg',
        'gov.sg', 'police.gov.sg', 'scdf.gov.sg', 'pa.gov.sg',
        'nea.gov.sg', 'bca.gov.sg', 'lta.gov.sg', 'ura.gov.sg',
        
        // Singapore Banking
        'dbs.com.sg', 'posb.com.sg', 'ocbc.com.sg', 'uob.com.sg',
        'maybank.com.sg', 'standardchartered.com.sg', 'hsbc.com.sg',
        'citibank.com.sg', 'rhbgroup.com', 'cimbbank.com.sg',
        'bankofchina.com', 'icbc.com.sg',
        
        // Singapore Services
        'shopee.sg', 'lazada.sg', 'qoo10.sg', 'carousell.sg',
        'redmart.com', 'fairprice.com.sg', 'courts.com.sg',
        'challenger.sg', 'harvey-norman.com.sg', 'grab.com',
        'foodpanda.sg', 'deliveroo.com.sg', 'singtel.com', 'starhub.com',
        'circles.life', 'm1.com.sg', 'giga.com.sg', 'sp.com.sg',
        'citygas.com.sg', 'ema.gov.sg',
        
        // Global (ADD THESE - they were missing!)
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'instagram.com', 'twitter.com',
        'linkedin.com', 'netflix.com', 'spotify.com', 'github.com',
        'youtube.com', 'whatsapp.com', 'telegram.org'
    ],
    
    // Combined suspicious patterns (simplified)
    SUSPICIOUS_PATTERNS: [
        // Singapore-specific
        /singpass.*verify/i,
        /cpf.*bonus/i,
        /iras.*refund/i,
        /dbs.*security/i,
        /ocbc.*alert/i,
        /uob.*suspended/i,
        /singapore.*lottery/i,
        /skillsfuture.*credit/i,
        /cdc.*voucher/i,
        
        // Global patterns
        /secure.*update/i,
        /verify.*account/i,
        /suspended.*account/i,
        /urgent.*action/i,
        /limited.*time/i
    ],
    
    // Suspicious TLDs (commonly abused)
    SUSPICIOUS_TLDS: [
        '.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download',
        '.bid', '.win', '.party', '.review', '.trade', '.date', '.racing',
        '.accountant', '.science', '.work', '.cricket', '.space'
    ],

    // Suspicious character patterns (DOMAIN ONLY - not URL paths)
    SUSPICIOUS_CHAR_PATTERNS: [
        /[а-я]/i, // Cyrillic characters
        /[αβγδεζηθικλμνξοπρστυφχψω]/i, // Greek characters
        /[аеорсухі]/i, // Common Cyrillic lookalikes
        /xn--/, // Punycode domains
        /-{2,}/, // Multiple consecutive hyphens
        /\d{5,}/, // Very long number sequences (5+ digits) - reduced false positives
        /[0-9][a-z][0-9]/i, // Suspicious alternating number-letter-number patterns
        /[il1|]{3,}/i // Multiple character substitutions (3+ in a row)
    ],

    // Enhanced domain-specific patterns for better detection
    DOMAIN_SUSPICIOUS_PATTERNS: [
        /^[0-9]+-[a-z]+\.(com|net|org)$/i, // 123-bank.com pattern
        /[a-z]{2,}[0-9]{2,}[a-z]{2,}/i, // Mixed suspicious patterns like ab12cd
        /([a-z])\1{4,}/i, // Repeated characters (5+ times) like aaaaa
        /(.)(.)\1\2{2,}/i // Repeated character pairs like abababab
    ],

    // Homograph detection patterns
    HOMOGRAPH_PATTERNS: [
        { char: 'а', lookalike: 'a' }, // Cyrillic a
        { char: 'е', lookalike: 'e' }, // Cyrillic e
        { char: 'о', lookalike: 'o' }, // Cyrillic o
        { char: 'р', lookalike: 'p' }, // Cyrillic p
        { char: 'с', lookalike: 'c' }, // Cyrillic c
        { char: 'у', lookalike: 'y' }, // Cyrillic y
        { char: 'х', lookalike: 'x' }, // Cyrillic x
        { char: 'і', lookalike: 'i' }, // Cyrillic i
        { char: 'α', lookalike: 'a' }, // Greek alpha
        { char: 'ο', lookalike: 'o' }, // Greek omicron
        { char: 'ρ', lookalike: 'p' }  // Greek rho
    ],
    
    // Educational tips (Singapore-focused, simplified)
    EDUCATIONAL_TIPS: [
        "Singapore government websites always end with .gov.sg - be suspicious of anything else!",
        "Banks in Singapore will NEVER ask for your SingPass credentials via email or SMS.",
        "Be cautious of fake CDC voucher, SkillsFuture credit, or HDB grant scams.",
        "Verify government communications by visiting official .gov.sg websites directly.",
        "Report scams to ScamShield (scamshield.org.sg) to protect other Singaporeans.",
        "DBS, OCBC, UOB will never ask you to click links to verify your account.",
        "If you receive urgent 'account suspended' messages, call your bank directly.",
        "Scammers often pressure you to act quickly. Stay calm and verify first.",
        "Check URLs carefully - scammers often use similar-looking domains.",
        "When in doubt, navigate to websites directly rather than clicking links."
    ],
    
    VALIDATION: {
        ALLOWED_PROTOCOLS: ['http:', 'https:'],
        MAX_TEXT_LENGTH: 500,
        DANGEROUS_PARAMS: ['javascript', 'vbscript', 'data', 'file'],
        VALID_ACTIONS: ['checkURL', 'reportPhishing', 'getStats', 'resetStats']
    }
};

// Export for different environments
if (typeof self !== 'undefined' && typeof window === 'undefined') {
    self.CONFIG = CONFIG;
} else if (typeof window !== 'undefined') {
    window.CONFIG = CONFIG;
} else if (typeof module !== 'undefined' && module.exports) {
    module.exports = CONFIG;
}
