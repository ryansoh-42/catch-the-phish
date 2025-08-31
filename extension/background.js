console.log('CatchThePhish: Background script loaded');

class BackgroundService {
    constructor() {
        this.apiEndpoint = 'http://localhost:5000'; // Our Python backend
        this.urlCache = new Map();
        this.educationalTips = [
            "Scammers often pressure you to act quickly. Stay calm and verify.",
            "Check the URL carefully - look for misspellings or unusual characters.",
            "Legitimate companies won't ask for passwords via email or suspicious links.",
            "When in doubt, navigate to the official website directly instead of clicking links.",
            "Be extra cautious with urgent requests for personal or financial information."
        ];
        this.init();
    }

    init() {
        // Listen for messages from content scripts
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true; // Keep message channel open for async responses
        });

        console.log('CatchThePhish: Background service initialized');
    }

    async handleMessage(request, sender, sendResponse) {
        try {
            // Validate request
            if (!request || !request.action) {
                console.warn('CatchThePhish: Invalid request received');
                sendResponse({ error: 'Invalid request' });
                return;
            }

            switch (request.action) {
                case 'checkURL':
                    if (request.url) {
                        const result = await this.analyzeURL(request.url);
                        // Only send message if tab still exists
                        if (sender.tab && sender.tab.id) {
                            try {
                                await chrome.tabs.sendMessage(sender.tab.id, {
                                    action: 'urlCheckResult',
                                    data: result
                                });
                            } catch (tabError) {
                                console.warn('CatchThePhish: Could not send to tab:', tabError.message);
                            }
                        }
                    }
                    break;

                case 'reportPhishing':
                    if (request.url) {
                        await this.reportPhishingURL(request.url);
                    }
                    sendResponse({ success: true });
                    break;

                case 'getStats':
                    const stats = await this.getProtectionStats();
                    sendResponse(stats);
                    break;

                default:
                    console.warn('CatchThePhish: Unknown action:', request.action);
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('CatchThePhish: Error handling message:', error);
            sendResponse({ error: error.message });
        }
    }

    async analyzeURL(url) {
        console.log('CatchThePhish: Analyzing URL:', url);

        // Check cache first (simple 5-minute cache)
        const cacheKey = url.toLowerCase();
        const cached = this.urlCache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < 300000) { // 5 minutes
            console.log('CatchThePhish: Using cached result');
            return cached.result;
        }

        try {
            // Perform local checks
            const localCheck = this.performLocalChecks(url);
            
            // Cache the result
            this.urlCache.set(cacheKey, {
                result: localCheck,
                timestamp: Date.now()
            });
            
            // Simple cache cleanup (keep last 100)
            if (this.urlCache.size > 100) {
                const entries = Array.from(this.urlCache.entries());
                this.urlCache.clear();
                entries.slice(-50).forEach(([key, value]) => {
                    this.urlCache.set(key, value);
                });
            }

            // Always add educational tip
            return {
                ...localCheck,
                tip: this.getRandomTip()
            };

            // TODO: Add API call back when backend is ready
            // const response = await fetch(`${this.apiEndpoint}/check-url`, { ... });

        } catch (error) {
            console.error('CatchThePhish: Error analyzing URL:', error);
            
            // Fallback to local checks
            const fallback = this.performLocalChecks(url);
            return {
                ...fallback,
                tip: this.getRandomTip()
            };
        }
    }

    performLocalChecks(url) {
        const checks = {
            isSuspicious: false,
            reason: '',
            confidence: 0,
            url: url
        };

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();

            // Check for typosquatting patterns
            if (this.checkTyposquatting(domain)) {
                checks.isSuspicious = true;
                checks.reason = 'Domain appears to be impersonating a popular website';
                checks.confidence = 0.8;
                return checks;
            }

            // Check for suspicious characters
            if (this.checkSuspiciousCharacters(domain)) {
                checks.isSuspicious = true;
                checks.reason = 'Domain contains unusual characters or patterns';
                checks.confidence = 0.7;
                return checks;
            }

            // Check for suspicious URL patterns
            if (this.checkSuspiciousPatterns(url)) {
                checks.isSuspicious = true;
                checks.reason = 'URL contains suspicious patterns commonly used in phishing';
                checks.confidence = 0.6;
                return checks;
            }

            // Check for IP addresses instead of domains
            if (this.isIPAddress(domain)) {
                checks.isSuspicious = true;
                checks.reason = 'Using IP address instead of domain name';
                checks.confidence = 0.9;
                return checks;
            }

        } catch (error) {
            console.error('CatchThePhish: Error in local checks:', error);
        }

        return checks;
    }

    checkTyposquatting(domain) {
        // Common targets for typosquatting
        const popularDomains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'ebay.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com'
        ];

        for (const legitimate of popularDomains) {
            if (this.calculateSimilarity(domain, legitimate) > 0.8 && domain !== legitimate) {
                return true;
            }
        }
        return false;
    }

    checkSuspiciousCharacters(domain) {
        // Check for homograph attacks (Unicode characters that look like Latin)
        const suspiciousPatterns = [
            /[а-я]/i, // Cyrillic characters
            /[αβγδεζηθικλμνξοπρστυφχψω]/i, // Greek characters
            /xn--/, // Punycode
            /-{2,}/, // Multiple consecutive hyphens
            /\d{4,}/ // Long sequences of numbers
        ];

        return suspiciousPatterns.some(pattern => pattern.test(domain));
    }

    checkSuspiciousPatterns(url) {
        const suspiciousPatterns = [
            /secure.*update/i,
            /verify.*account/i,
            /suspended.*account/i,
            /click.*here.*now/i,
            /urgent.*action/i,
            /limited.*time/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(url));
    }

    isIPAddress(domain) {
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        return ipPattern.test(domain);
    }

    calculateSimilarity(str1, str2) {
        // Simple Levenshtein distance-based similarity
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        
        if (longer.length === 0) return 1.0;
        
        const distance = this.levenshteinDistance(longer, shorter);
        return (longer.length - distance) / longer.length;
    }

    levenshteinDistance(str1, str2) {
        const matrix = [];
        
        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }
        
        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }
        
        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        
        return matrix[str2.length][str1.length];
    }

    async reportPhishingURL(url) {
        try {
            // For demo purposes, we'll just log this
            console.log('CatchThePhish: Reporting phishing URL:', url);
            
            // In production, this would integrate with ScamShield API
            const reportData = {
                url: url,
                timestamp: new Date().toISOString(),
                source: 'CatchThePhish Extension'
            };

            // Store locally for now
            const reports = await this.getStoredReports();
            reports.push(reportData);
            await chrome.storage.local.set({ reports: reports });

            console.log('CatchThePhish: URL reported successfully');
        } catch (error) {
            console.error('CatchThePhish: Error reporting URL:', error);
        }
    }

    async getStoredReports() {
        try {
            const result = await chrome.storage.local.get(['reports']);
            return result.reports || [];
        } catch (error) {
            console.error('CatchThePhish: Error getting stored reports:', error);
            return [];
        }
    }

    async getProtectionStats() {
        try {
            const result = await chrome.storage.local.get(['blockedCount', 'reportedCount']);
            return {
                blocked: result.blockedCount || 0,
                reported: result.reportedCount || 0
            };
        } catch (error) {
            console.error('CatchThePhish: Error getting stats:', error);
            return { blocked: 0, reported: 0 };
        }
    }

    getRandomTip() {
        const randomIndex = Math.floor(Math.random() * this.educationalTips.length);
        return this.educationalTips[randomIndex];
    }
}

// Initialize the background service
new BackgroundService();
