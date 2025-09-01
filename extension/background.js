console.log('CatchThePhish: Background script loaded');

// Import utilities
try {
    importScripts('utils/config.js', 'utils/validators.js', 'utils/cache.js');
    console.log('CatchThePhish: Utilities loaded successfully');
} catch (error) {
    console.error('CatchThePhish: Error loading utilities:', error);
}

class BackgroundService {
    constructor() {
        this.apiEndpoint = CONFIG?.API?.ENDPOINT || 'http://localhost:5000';
        this.urlCache = new URLCache({
            maxSize: CONFIG?.CACHE?.MAX_SIZE || 200,
            ttl: CONFIG?.CACHE?.TTL || 10 * 60 * 1000,
            cleanupInterval: CONFIG?.CACHE?.CLEANUP_INTERVAL || 2 * 60 * 1000
        });
        this.init();
    }

    init() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true;
        });
        console.log('CatchThePhish: Background service initialized');
    }

    async handleMessage(request, sender, sendResponse) {
        try {
            if (!InputValidator.isValidMessage(request)) {
                console.warn('CatchThePhish: Invalid request received', request);
                sendResponse({ error: 'Invalid request' });
                return;
            }

            switch (request.action) {
                case 'checkURL':
                    if (request.url) {
                        const result = await this.analyzeURL(request.url);
                        if (sender.tab?.id) {
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

        // Validate and sanitize URL
        if (!InputValidator.isValidURL(url)) {
            throw new Error('Invalid URL provided for analysis');
        }
        const sanitizedUrl = InputValidator.sanitizeURL(url);
        const cacheKey = sanitizedUrl.toLowerCase();

        // Check cache first
        const cached = this.urlCache.get(cacheKey);
        if (cached) {
            console.log('CatchThePhish: Using cached analysis result');
            return {
                ...cached,
                tip: this.getRandomTip(),
                fromCache: true
            };
        }

        // Perform fresh analysis
        console.log('CatchThePhish: Performing fresh analysis');
        const analysisResult = this.performLocalChecks(sanitizedUrl);
        
        // Cache the result
        this.urlCache.set(cacheKey, analysisResult);

        return {
            ...analysisResult,
            tip: this.getRandomTip(),
            fromCache: false
        };
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

            // Check for typosquatting
            if (this.checkTyposquatting(domain)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: 'Domain appears to be impersonating a popular website',
                    confidence: 0.8
                };
            }

            // Check for suspicious characters
            if (this.checkSuspiciousCharacters(domain)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: 'Domain contains unusual characters or patterns',
                    confidence: 0.7
                };
            }

            // Check for suspicious URL patterns
            if (this.checkSuspiciousPatterns(url)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: 'URL contains suspicious patterns commonly used in phishing',
                    confidence: 0.6
                };
            }

            // Check for IP addresses
            if (this.isIPAddress(domain)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: 'Using IP address instead of domain name',
                    confidence: 0.9
                };
            }

        } catch (error) {
            console.error('CatchThePhish: Error in local checks:', error);
        }

        return checks;
    }

    checkTyposquatting(domain) {
        const popularDomains = CONFIG?.POPULAR_DOMAINS || [];
        const threshold = CONFIG?.DETECTION?.SIMILARITY_THRESHOLD || 0.8;

        return popularDomains.some(legitimate => {
            const similarity = this.calculateSimilarity(domain, legitimate);
            return similarity > threshold && domain !== legitimate;
        });
    }

    checkSuspiciousCharacters(domain) {
        const patterns = CONFIG?.SUSPICIOUS_CHAR_PATTERNS || [];
        return patterns.some(pattern => pattern.test(domain));
    }

    checkSuspiciousPatterns(url) {
        const patterns = CONFIG?.SUSPICIOUS_PATTERNS || [];
        return patterns.some(pattern => pattern.test(url));
    }

    isIPAddress(domain) {
        return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
    }

    calculateSimilarity(str1, str2) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;
        
        if (longer.length === 0) return 1.0;
        
        const distance = this.levenshteinDistance(longer, shorter);
        return (longer.length - distance) / longer.length;
    }

    levenshteinDistance(str1, str2) {
        const matrix = Array(str2.length + 1).fill().map(() => Array(str1.length + 1).fill(0));
        
        for (let i = 0; i <= str2.length; i++) matrix[i][0] = i;
        for (let j = 0; j <= str1.length; j++) matrix[0][j] = j;
        
        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2[i - 1] === str1[j - 1]) {
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
            const sanitizedUrl = InputValidator.sanitizeURL(url);
            console.log('CatchThePhish: Reporting phishing URL:', sanitizedUrl);
            
            const reportData = {
                url: sanitizedUrl,
                timestamp: new Date().toISOString(),
                source: 'CatchThePhish Extension'
            };

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
        const tips = CONFIG?.EDUCATIONAL_TIPS || [];
        return tips[Math.floor(Math.random() * tips.length)];
    }
}

// Initialize the background service
new BackgroundService();
