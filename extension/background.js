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
        this.urlCache = new URLCache({
            maxSize: CONFIG?.CACHE?.MAX_SIZE || 200,
            ttl: CONFIG?.CACHE?.TTL || 10 * 60 * 1000,
            cleanupInterval: CONFIG?.CACHE?.CLEANUP_INTERVAL || 2 * 60 * 1000
        });
        
        // Simple telemetry tracking
        this.stats = {
            urlsScanned: 0,
            urlsReported: 0,
            threatsBlocked: 0,
            lastReset: Date.now()
        };
        
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

                case 'resetStats':
                    this.resetStats();
                    sendResponse({ success: true });
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

        if (!InputValidator.isValidURL(url)) {
            throw new Error('Invalid URL provided for analysis');
        }
        const sanitizedUrl = InputValidator.sanitizeURL(url);
        const cacheKey = sanitizedUrl.toLowerCase();

        // Increment scanned count
        this.stats.urlsScanned++;

        // Check cache first
        const cached = this.urlCache.get(cacheKey);
        if (cached) {
            console.log('CatchThePhish: Using cached result');
            return {
                ...cached,
                tip: this.getRandomTip(),
                fromCache: true
            };
        }

        // Perform analysis
        console.log('CatchThePhish: Performing fresh analysis');
        const analysisResult = this.performEnhancedLocalChecks(sanitizedUrl);
        
        // Update statistics if threat detected
        if (analysisResult.isSuspicious) {
            this.stats.threatsBlocked++;
        }
        
        // Cache the result
        this.urlCache.set(cacheKey, analysisResult);

        return {
            ...analysisResult,
            tip: this.getRandomTip(),
            fromCache: false
        };
    }

    performEnhancedLocalChecks(url) {
        const checks = {
            isSuspicious: false,
            reason: '',
            confidence: 0,
            url: url
        };

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const normalizedDomain = this.normalizeDomain(domain);

            // 1. IP Address Check (Highest Priority)
            if (this.isIPAddress(domain)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: 'Using IP address instead of domain name',
                    confidence: 0.95
                };
            }

            // 2. Suspicious TLD Check (High Priority)
            const tld = domain.substring(domain.lastIndexOf('.'));
            if (CONFIG?.SUSPICIOUS_TLDS?.includes(tld)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: `Domain uses suspicious top-level domain (${tld})`,
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.SUSPICIOUS_TLD || 0.8
                };
            }

            // 3. Suspicious URL Path Patterns (Check BEFORE domain similarity - Industry Best Practice)
            const patterns = CONFIG?.SUSPICIOUS_PATTERNS || [];
            for (const pattern of patterns) {
                if (pattern.test(url)) {
                    return {
                        ...checks,
                        isSuspicious: true,
                        reason: 'Contains suspicious keywords commonly used in scams',
                        confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.SUSPICIOUS_PATTERN || 0.7
                    };
                }
            }

            // 4. Suspicious Subdomain Check
            if (this.hasSuspiciousSubdomain(domain)) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: 'Domain contains suspicious subdomain patterns',
                    confidence: 0.75
                };
            }

            // 5. Homograph Attack Detection
            const homographResult = this.detectHomographAttacks(normalizedDomain);
            if (homographResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: `Potential homograph attack: ${homographResult.reason}`,
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.HOMOGRAPH || 0.9
                };
            }

            // 6. Domain Substring Abuse Detection
            const substrResult = this.detectSubstringAbuseEnhanced(domain);
            if (substrResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: substrResult.reason,
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.SUBSTRING_ABUSE || 0.8
                };
            }

            // 7. Enhanced Typosquatting Detection (Only for non-exact matches after normalization)
            const typosquattingResult = this.detectTyposquatting(normalizedDomain, domain);
            if (typosquattingResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: typosquattingResult.reason,
                    confidence: typosquattingResult.confidence
                };
            }

            // 8. Enhanced Character Pattern Check
            const charResult = this.detectSuspiciousCharacters(domain);
            if (charResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: charResult.reason,
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.SUSPICIOUS_CHARS || 0.65
                };
            }

            // 9. Additional Heuristics
            const heuristicResult = this.applyAdditionalHeuristics(domain);
            if (heuristicResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: heuristicResult.reason,
                    confidence: heuristicResult.confidence
                };
            }

            return checks;

        } catch (error) {
            console.error('Detection error:', error);
            return checks;
        }
    }

    normalizeDomain(domain) {
        try {
            let normalized = domain.toLowerCase();
            
            // Handle punycode domains
            if (normalized.includes('xn--')) {
                normalized = normalized.normalize('NFKC');
            } else {
                normalized = normalized.normalize('NFKC');
            }
            
            // Remove common legitimate subdomains for comparison
            const legitimateSubdomains = ['www.', 'secure.', 'login.', 'm.', 'mobile.', 'app.', 'api.', 'mail.'];
            for (const subdomain of legitimateSubdomains) {
                if (normalized.startsWith(subdomain)) {
                    normalized = normalized.substring(subdomain.length);
                    break;
                }
            }
            
            return normalized;
        } catch (error) {
            console.warn('Domain normalization failed:', error);
            return domain.toLowerCase();
        }
    }

    // Helper method to check if a subdomain looks suspicious
    hasSuspiciousSubdomain(domain) {
        const suspiciousSubdomainPatterns = [
            /fake-/i,
            /phishing-/i,
            /scam-/i,
            /security-/i,
            /urgent-/i,
            /verify-/i,
            /update-/i,
            /alert-/i,
            /-gov\./i,  // like fake-gov.sg
            /-bank\./i, // like fake-bank.sg
            /-secure\./i
        ];
        
        for (const pattern of suspiciousSubdomainPatterns) {
            if (pattern.test(domain)) {
                return true;
            }
        }
        return false;
    }

    detectHomographAttacks(domain) {
        const homographPatterns = CONFIG?.HOMOGRAPH_PATTERNS || [];
        const threshold = CONFIG?.DETECTION?.HOMOGRAPH_SIMILARITY_THRESHOLD || 0.8;
        
        for (const pattern of homographPatterns) {
            if (domain.includes(pattern.char)) {
                // Check if this creates a confusing similarity to protected domains
                const convertedDomain = domain.replace(new RegExp(pattern.char, 'g'), pattern.lookalike);
                const protectedDomains = CONFIG?.PROTECTED_DOMAINS || [];
                
                for (const protectedDomain of protectedDomains) {
                    const similarity = this.calculateSimilarity(convertedDomain, protectedDomain);
                    if (similarity > threshold) {
                        return {
                            detected: true,
                            reason: `Contains lookalike characters that mimic ${protectedDomain}`
                        };
                    }
                }
            }
        }
        
        return { detected: false };
    }

    detectTyposquatting(normalizedDomain, originalDomain) {
        const protectedDomains = CONFIG?.PROTECTED_DOMAINS || [];
        const baseThreshold = CONFIG?.DETECTION?.SIMILARITY_THRESHOLD || 0.65;
        
        for (const protectedDomain of protectedDomains) {
            // Skip exact matches after normalization (prevents www.dbs.com.sg false positives)
            if (normalizedDomain === protectedDomain) continue;
            
            // Also skip if original domain is exactly the protected domain
            if (originalDomain.toLowerCase() === protectedDomain) continue;
            
            const similarity = this.calculateSimilarity(normalizedDomain, protectedDomain);
            
            // Enhanced scoring based on domain length and similarity
            if (similarity > baseThreshold) {
                // Don't flag if the difference is just common legitimate variations
                if (this.isLegitimateVariation(originalDomain.toLowerCase(), protectedDomain)) {
                    continue;
                }
                
                // Higher confidence for longer domains with high similarity
                const lengthFactor = Math.min(protectedDomain.length / 10, 1);
                const baseConfidence = CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.TYPOSQUATTING_BASE || 0.5;
                const confidence = Math.min(0.95, baseConfidence + similarity * 0.4 + lengthFactor * 0.1);
                
                return {
                    detected: true,
                    reason: `Potential impersonation of ${protectedDomain} (${Math.round(similarity * 100)}% similar)`,
                    confidence: confidence
                };
            }
        }
        
        return { detected: false };
    }

    // Helper to identify legitimate variations that shouldn't be flagged
    isLegitimateVariation(domain, protectedDomain) {
        // Common legitimate patterns that shouldn't be flagged
        const legitimatePatterns = [
            `www.${protectedDomain}`,
            `secure.${protectedDomain}`,
            `login.${protectedDomain}`,
            `m.${protectedDomain}`,
            `mobile.${protectedDomain}`,
            `app.${protectedDomain}`,
            `api.${protectedDomain}`,
            `mail.${protectedDomain}`
        ];
        
        return legitimatePatterns.includes(domain);
    }

    detectSubstringAbuseEnhanced(domain) {
        const protectedDomains = CONFIG?.PROTECTED_DOMAINS || [];
        
        for (const protectedDomain of protectedDomains) {
            if (this.detectSubstringAbuse(domain, protectedDomain)) {
                return {
                    detected: true,
                    reason: `Suspicious domain structure mimicking ${protectedDomain}`
                };
            }
        }
        
        return { detected: false };
    }

    detectSuspiciousCharacters(domain) {
        const charPatterns = CONFIG?.SUSPICIOUS_CHAR_PATTERNS || [];
        
        for (const pattern of charPatterns) {
            if (pattern.test(domain)) {
                let reason = 'Domain contains unusual characters';
                
                // Provide more specific reasons and avoid false positives
                if (pattern.source.includes('а-я')) {
                    // Only flag if it's actually suspicious, not just any Cyrillic
                    if (this.hasSuspiciousCyrillicUsage(domain)) {
                        reason = 'Domain contains Cyrillic characters that may mimic Latin letters';
                    } else {
                        continue; // Skip this detection
                    }
                } else if (pattern.source.includes('αβγ')) {
                    reason = 'Domain contains Greek characters that may mimic Latin letters';
                } else if (pattern.source.includes('xn--')) {
                    reason = 'Domain uses punycode encoding (potential homograph attack)';
                } else if (pattern.source.includes('\\d{4,}')) {
                    // Only flag truly suspicious long number sequences
                    if (!/^[a-z]+-\d{4,}$/.test(domain)) { // Don't flag legitimate patterns like "example-2024"
                        reason = 'Domain contains unusually long number sequences';
                    } else {
                        continue;
                    }
                } else if (pattern.source.includes('-{2,}')) {
                    // Only flag multiple consecutive hyphens in suspicious contexts
                    if (!domain.includes('--')) { // Double check the pattern actually exists
                        continue;
                    }
                    reason = 'Domain contains multiple consecutive hyphens';
                }
                
                return {
                    detected: true,
                    reason: reason
                };
            }
        }
        
        return { detected: false };
    }

    // Helper to detect truly suspicious Cyrillic usage (not just any Cyrillic)
    hasSuspiciousCyrillicUsage(domain) {
        // Only flag if Cyrillic chars are mixed with Latin in a way that could be deceptive
        const cyrillicChars = domain.match(/[а-я]/gi) || [];
        const latinChars = domain.match(/[a-z]/gi) || [];
        
        // If it's all Cyrillic, it's probably legitimate
        if (cyrillicChars.length > 0 && latinChars.length === 0) {
            return false;
        }
        
        // If it's mixed and looks like it could be impersonating Latin text
        return cyrillicChars.length > 0 && latinChars.length > cyrillicChars.length;
    }

    applyAdditionalHeuristics(domain) {
        const parts = domain.split('.');
        const maxSubdomains = CONFIG?.DETECTION?.MAX_SUBDOMAIN_LEVELS || 4;
        const longDomainThreshold = CONFIG?.DETECTION?.LONG_DOMAIN_THRESHOLD || 30;
        const suspiciousDigitRatio = CONFIG?.DETECTION?.SUSPICIOUS_DIGIT_RATIO || 0.3;
        
        // Check for excessive subdomains (but exclude common patterns)
        if (parts.length > maxSubdomains) {
            // Don't flag common legitimate patterns like www.secure.bank.com
            const hasLegitimateSubdomains = parts.some(part => 
                ['www', 'secure', 'login', 'm', 'mobile', 'app', 'api', 'mail'].includes(part)
            );
            
            if (!hasLegitimateSubdomains) {
                return {
                    detected: true,
                    reason: 'Domain has suspicious number of subdomains',
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.EXCESSIVE_SUBDOMAINS || 0.6
                };
            }
        }
        
        // Check for very long domain names (but exclude legitimate long domains)
        const fullDomain = domain;
        if (fullDomain.length > longDomainThreshold) {
            // Don't flag if it's just a long but legitimate-looking domain
            const hasRepeatingPatterns = /(.{3,})\1{2,}/.test(fullDomain); // Repeated patterns
            const hasRandomChars = /[0-9]{3,}/.test(fullDomain) && /[a-z]{10,}/i.test(fullDomain);
            
            if (hasRepeatingPatterns || hasRandomChars) {
                return {
                    detected: true,
                    reason: 'Domain name is unusually long with suspicious patterns',
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.LONG_DOMAIN || 0.55
                };
            }
        }
        
        // Check for domains with mixed numbers and letters in suspicious patterns
        const mainDomain = parts[0] || '';
        if (mainDomain.length > 8 && /\d/.test(mainDomain) && /[a-z]/i.test(mainDomain)) {
            const digitRatio = (mainDomain.match(/\d/g) || []).length / mainDomain.length;
            
            // More sophisticated check - don't flag legitimate patterns like "abc123"
            const hasObviousPattern = /^[a-z]+\d+$|^\d+[a-z]+$/i.test(mainDomain);
            
            if (digitRatio > suspiciousDigitRatio && !hasObviousPattern) {
                return {
                    detected: true,
                    reason: 'Domain contains suspicious mix of numbers and letters',
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.SUSPICIOUS_DIGITS || 0.6
                };
            }
        }
        
        return { detected: false };
    }

    // Enhanced method for Singapore context
    detectSubstringAbuse(suspiciousDomain, legitimateDomain) {
        // Extract the main domain part (before first dot)
        const legitParts = legitimateDomain.split('.');
        const suspiciousParts = suspiciousDomain.split('.');
        
        if (legitParts.length < 2 || suspiciousParts.length < 2) return false;
        
        const legitMain = legitParts[0]; // e.g., 'dbs' from 'dbs.com.sg'
        
        if (legitMain.length >= 3) {
            // Singapore-specific patterns
            // Pattern 1: legitname-com.sg, legitname-gov.sg, legitname-bank.sg
            if (suspiciousDomain.includes(`${legitMain}-com`) || 
                suspiciousDomain.includes(`${legitMain}-gov`) ||
                suspiciousDomain.includes(`${legitMain}-bank`)) {
                return true;
            }
            
            // Pattern 2: legitname.com-sg.net, legitname.gov-sg.com
            if (suspiciousDomain.includes(`${legitMain}.com-sg`) || 
                suspiciousDomain.includes(`${legitMain}.gov-sg`)) {
                return true;
            }
            
            // Pattern 3: Singapore-specific abuse patterns
            // posb-bank.sg (legitimate: posb.com.sg)
            // dbs-singapore.com (legitimate: dbs.com.sg)
            if (suspiciousDomain.includes(`${legitMain}-singapore`) ||
                suspiciousDomain.includes(`${legitMain}-bank`) ||
                suspiciousDomain.includes(`${legitMain}-sg`)) {
                return true;
            }
            
            // Pattern 4: Contains legitimate domain name but different TLD structure
            if (suspiciousDomain.includes(legitMain) && 
                suspiciousDomain !== legitimateDomain &&
                !this.isLegitimateVariation(suspiciousDomain, legitimateDomain) &&
                (suspiciousDomain.includes('.com') || suspiciousDomain.includes('.net') || suspiciousDomain.includes('.org'))) {
                return true;
            }
        }
        
        return false;
    }





    getRandomTip() {
        const tips = CONFIG?.EDUCATIONAL_TIPS || [];
        return tips[Math.floor(Math.random() * tips.length)];
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

    isIPAddress(domain) {
        return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
    }

    async reportPhishingURL(url) {
        try {
            console.log('CatchThePhish: Reporting phishing URL:', url);
            
            // Increment reported URLs counter
            this.stats.urlsReported++;
            
            // In a real implementation, this would send to a backend API
            return { success: true };
        } catch (error) {
            console.error('CatchThePhish: Error reporting URL:', error);
            return { success: false, error: error.message };
        }
    }

    async getProtectionStats() {
        try {
            return {
                // Simple telemetry
                blocked: this.stats.threatsBlocked,
                reported: this.stats.urlsReported,
                totalScanned: this.stats.urlsScanned,
                version: '1.0.0'
            };
        } catch (error) {
            console.error('CatchThePhish: Error getting stats:', error);
            return { error: error.message };
        }
    }

    // Method to reset statistics (useful for testing)
    resetStats() {
        this.stats = {
            urlsScanned: 0,
            urlsReported: 0,
            threatsBlocked: 0,
            lastReset: Date.now()
        };
        console.log('CatchThePhish: Statistics reset');
    }
}

// Initialize the background service
new BackgroundService();
