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
            threatsBlocked: 0,
            urlsReported: 0,
            urlsScanned: 0
        };
        
        // Add page state tracking
        this.pageStates = new Map(); // Track scan states per tab
        this.realtimeThreats = new Map(); // Track real-time threats per tab
        
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
                        const result = await this.analyzeURL(request.url); // Real scan (count it)
                        
                        // Record real-time threat if found
                        if (result.isSuspicious && sender.tab?.id) {
                            this.recordRealtimeThreat(sender.tab.id, request.url, result);
                        }
                        
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

                case 'getPageStatus':  // New action for popup
                    if (request.tabId && request.url) {
                        const status = this.getPageStatus(request.tabId, request.url);
                        sendResponse(status);
                    } else {
                        sendResponse({
                            status: 'needs_scan',
                            message: 'Click to scan this website',
                            icon: '🔍',
                            needsScan: true
                        });
                    }
                    break;

                case 'scanCurrentPage':
                    // Handle this asynchronously
                    this.handleScanCurrentPage(request, sender, sendResponse);
                    return; // Don't call sendResponse here

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

    async handleScanCurrentPage(request, sender, sendResponse) {
        console.log('🔍 CatchThePhish: scanCurrentPage received:', request);
        console.log('🔍 URL:', request.url);
        console.log('🔍 TabID:', request.tabId);
        console.log('🔍 Sender:', sender);
        
        // Use tabId from request instead of sender.tab.id
        if (!request.url || !request.tabId) {
            console.error('❌ CatchThePhish: Missing URL or tab ID');
            console.error('❌ URL check:', !!request.url, 'TabID check:', !!request.tabId);
            sendResponse({ 
                success: false,
                isSuspicious: false, 
                reason: 'Unable to scan page - missing information' 
            });
            return;
        }

        try {
            console.log('🚀 CatchThePhish: Starting comprehensive scan for:', request.url);
            
            // 1. First do local analysis
            const localResult = await this.analyzeURL(request.url, true);
            console.log('📊 CatchThePhish: Local result:', localResult);
            
            // 2. Try comprehensive backend scan
            let finalResult = localResult;
            let backendResult = null;
            
            try {
                // Get links and call backend - use request.tabId instead of sender.tab.id
                console.log('🔗 CatchThePhish: Extracting links from tab:', request.tabId);
                const links = await this.extractLinksFromPage(request.tabId);
                console.log('🔗 CatchThePhish: Extracted links:', links);
                
                console.log('🌐 CatchThePhish: Calling backend with:', {
                    page_url: request.url,
                    extracted_links: links.slice(0, 10)
                });
                
                backendResult = await this.performComprehensiveScan(request.url, links);
                console.log('🌐 CatchThePhish: Backend result:', backendResult);
                
                if (backendResult.success) {
                    // Use backend result if successful
                    console.log('✅ CatchThePhish: Using backend result');
                    finalResult = {
                        isSuspicious: backendResult.is_suspicious,
                        confidence: backendResult.confidence,
                        reason: backendResult.reason,
                        scanType: 'comprehensive',
                        links_scanned: backendResult.links_scanned,
                        suspicious_links_found: backendResult.suspicious_links_found,
                        suspicious_links: backendResult.suspicious_links,
                        scan_summary: backendResult.scan_summary,
                        success: true
                    };
                } else {
                    console.log('⚠️ CatchThePhish: Backend returned success: false, using local result');
                }
            } catch (backendError) {
                console.warn('⚠️ CatchThePhish: Backend scan failed, using local result:', backendError);
                // Keep local result as fallback
            }
            
            // 🆕 Update stats using backend scan results
            if (backendResult && backendResult.success && backendResult.links_scanned !== undefined) {
                // Add the scanned links to total count
                this.stats.urlsScanned += backendResult.links_scanned;
                // Add the suspicious links to blocked count
                this.stats.threatsBlocked += backendResult.suspicious_links_found || 0;
            } else {
                // Fallback for local-only scans
                this.stats.urlsScanned++;
                if (finalResult.isSuspicious) {
                    this.stats.threatsBlocked++;
                }
            }

            console.log('📊 Updated stats after scan:', {
                urlsScanned: this.stats.urlsScanned,
                threatsBlocked: this.stats.threatsBlocked,
                urlsReported: this.stats.urlsReported,
                backendData: {
                    links_scanned: backendResult?.links_scanned,
                    suspicious_links_found: backendResult?.suspicious_links_found
                }
            });
            
            // Store scan result - use request.tabId
            this.pageStates.set(request.tabId, {
                url: request.url,
                result: finalResult,
                scanned: true,
                timestamp: Date.now()
            });
            
            console.log('📤 CatchThePhish: Sending final result:', finalResult);
            sendResponse(finalResult);
            
        } catch (error) {
            console.error('💥 CatchThePhish: Scan failed completely:', error);
            sendResponse({ 
                success: false,
                isSuspicious: false, 
                reason: 'Scan failed - please try again',
                error: true 
            });
        }
    }

    async analyzeURL(url, fromPopup = false) {
        console.log('CatchThePhish: Analyzing URL:', url);

        if (!InputValidator.isValidURL(url)) {
            throw new Error('Invalid URL provided for analysis');
        }
        const sanitizedUrl = InputValidator.sanitizeURL(url);
        if (!sanitizedUrl) return { isSuspicious: false, reason: 'Invalid URL' };
        
        const cacheKey = sanitizedUrl.toLowerCase();

        // Only increment scanned count for actual user interactions, not popup checks
        if (!fromPopup) {
            this.stats.urlsScanned++;
        }

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

        // Perform local analysis first
        console.log('CatchThePhish: Performing local analysis');
        const localResult = this.performEnhancedLocalChecks(sanitizedUrl);
        
        // 🆕 Smart backend integration with clear source attribution
        let finalResult = localResult;
        
        if (this.shouldCallBackend(localResult, sanitizedUrl)) {
            console.log('CatchThePhish: Local analysis uncertain - consulting backend');
            const serverResult = await this.performServerAnalysis(sanitizedUrl, localResult);
            
            if (serverResult.serverEnhanced) {
                console.log('CatchThePhish: Server enhanced the analysis');
                
                // 🔑 KEY FIX: Use server explanation completely, don't mix with local
                finalResult = {
                    isSuspicious: serverResult.isSuspicious,
                    confidence: serverResult.confidence,
                    reason: serverResult.reason, // 📝 This is now the server's explanation
                    threatType: serverResult.threatType,
                    url: sanitizedUrl,
                    serverEnhanced: true,
                    analysisSource: 'server', // 🆕 Clear source attribution
                    localConfidence: localResult.confidence, // Keep for debugging
                    localReason: localResult.reason // Keep for debugging
                };
            } else {
                console.log('CatchThePhish: Server unavailable, using local result');
                finalResult = {
                    ...localResult,
                    serverAttempted: true,
                    analysisSource: 'local_fallback', // 🆕 Clear source attribution
                    reason: localResult.reason // Remove: `⚡ Local Detection: ${localResult.reason}`
                };
            }
        } else {
            console.log('CatchThePhish: Local analysis sufficient - skipping backend');
            finalResult = {
                ...localResult,
                backendSkipped: true,
                analysisSource: 'local_confident', // 🆕 Clear source attribution
                reason: localResult.reason // Remove: `⚡ Local Detection: ${localResult.reason}`
            };
        }
        
        // Update statistics if threat detected
        if (finalResult.isSuspicious) {
            this.stats.threatsBlocked++;
        }
        
        // Cache the result
        this.urlCache.set(cacheKey, finalResult);

        return {
            ...finalResult,
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

            // 8. Enhanced Character Pattern Check (Domain only)
            const charResult = this.detectSuspiciousCharacters(domain);
            if (charResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: charResult.reason,
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.SUSPICIOUS_CHARS || 0.65
                };
            }

            // 9. Domain Length and Structure Heuristics
            const structureResult = this.analyzedomainStructure(domain);
            if (structureResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: structureResult.reason,
                    confidence: structureResult.confidence
                };
            }

            // 10. Keyword-based Detection (for suspicious domain names)
            const keywordResult = this.detectSuspiciousKeywords(domain);
            if (keywordResult.detected) {
                return {
                    ...checks,
                    isSuspicious: true,
                    reason: keywordResult.reason,
                    confidence: 0.7
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
        
        // CRITICAL FIX: Check if the normalized domain IS a protected domain first
        if (protectedDomains.includes(normalizedDomain)) {
            // This is a legitimate protected domain, don't flag it
            return { detected: false };
        }
        
        // Also check if original domain is a protected domain
        if (protectedDomains.includes(originalDomain.toLowerCase())) {
            return { detected: false };
        }
        
        for (const protectedDomain of protectedDomains) {
            // Skip exact matches (redundant now, but keeping for safety)
            if (normalizedDomain === protectedDomain) continue;
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
        // First check basic character patterns
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
                } else if (pattern.source.includes('\\d{5,}')) {
                    reason = 'Domain contains unusually long number sequences';
                } else if (pattern.source.includes('[0-9][a-z][0-9]')) {
                    reason = 'Domain has suspicious alternating number-letter patterns';
                } else if (pattern.source.includes('-{2,}')) {
                    reason = 'Domain contains multiple consecutive hyphens';
                } else if (pattern.source.includes('[il1|]{3,}')) {
                    reason = 'Domain contains multiple character substitutions';
                }
                
                return {
                    detected: true,
                    reason: reason
                };
            }
        }

        // Then check domain-specific suspicious patterns
        const domainPatterns = CONFIG?.DOMAIN_SUSPICIOUS_PATTERNS || [];
        
        for (const pattern of domainPatterns) {
            if (pattern.test(domain)) {
                let reason = 'Domain structure appears suspicious';
                
                if (pattern.source.includes('^[0-9]+-[a-z]+')) {
                    reason = 'Domain uses suspicious number-name pattern (e.g., 123-bank.com)';
                } else if (pattern.source.includes('[a-z]{2,}[0-9]{2,}[a-z]{2,}')) {
                    reason = 'Domain has suspicious mixed character patterns';
                } else if (pattern.source.includes('\\1{4,}')) {
                    reason = 'Domain contains repeated characters';
                } else if (pattern.source.includes('\\1\\2{2,}')) {
                    reason = 'Domain contains repeated character sequences';
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

    // New method for analyzing domain structure based on your suggestions
    analyzedomainStructure(domain) {
        const parts = domain.split('.');
        const maxSubdomains = CONFIG?.DETECTION?.MAX_SUBDOMAIN_LEVELS || 4;
        const longDomainThreshold = CONFIG?.DETECTION?.LONG_DOMAIN_THRESHOLD || 30;
        
        // Check for excessive subdomains (enhanced logic)
        if (parts.length > maxSubdomains) {
            // Don't flag common legitimate patterns
            const hasLegitimateSubdomains = parts.some(part => 
                ['www', 'secure', 'login', 'm', 'mobile', 'app', 'api', 'mail', 'cdn', 'static'].includes(part)
            );
            
            if (!hasLegitimateSubdomains) {
                return {
                    detected: true,
                    reason: 'Domain has excessive subdomain levels (potential subdomain abuse)',
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.EXCESSIVE_SUBDOMAINS || 0.75
                };
            }
        }
        
        // Enhanced domain length check
        if (domain.length > longDomainThreshold) {
            // More sophisticated analysis of long domains
            const hasRepeatingPatterns = /(.{3,})\1{2,}/.test(domain);
            const hasRandomChars = /[a-z]{15,}/i.test(domain) && /\d{3,}/.test(domain);
            const isObviouslyGenerated = /[a-z0-9]{20,}/i.test(domain) && !/[aeiou]{2,}/i.test(domain);
            
            if (hasRepeatingPatterns || hasRandomChars || isObviouslyGenerated) {
                return {
                    detected: true,
                    reason: 'Domain name is unusually long and appears to be generated',
                    confidence: CONFIG?.DETECTION?.CONFIDENCE_WEIGHTS?.LONG_DOMAIN || 0.65
                };
            }
        }
        
        return { detected: false };
    }

    // New method for keyword-based detection in domain names
    detectSuspiciousKeywords(domain) {
        const suspiciousKeywords = [
            'login', 'secure', 'update', 'verify', 'account', 'suspended', 
            'urgent', 'security', 'alert', 'warning', 'blocked', 'expired',
            'confirm', 'activate', 'unlock', 'restore', 'support', 'help',
            'bank', 'payment', 'paypal', 'amazon', 'microsoft', 'apple',
            'google', 'facebook', 'instagram', 'twitter', 'linkedin'
        ];
        
        // Only flag if domain contains suspicious keywords in suspicious contexts
        const domainWithoutTLD = domain.split('.')[0];
        
        for (const keyword of suspiciousKeywords) {
            // Look for keyword in suspicious contexts
            const suspiciousPatterns = [
                new RegExp(`${keyword}-[a-z]+`, 'i'),     // login-bank, secure-update
                new RegExp(`[a-z]+-${keyword}`, 'i'),     // mybank-login, update-secure  
                new RegExp(`${keyword}[0-9]+`, 'i'),      // login123, secure456
                new RegExp(`[0-9]+${keyword}`, 'i')       // 123login, 456secure
            ];
            
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(domainWithoutTLD)) {
                    return {
                        detected: true,
                        reason: `Domain name contains suspicious keyword pattern: "${keyword}"`
                    };
                }
            }
        }
        
        return { detected: false };
    }

    // Keep legacy method for backward compatibility but improve it
    applyAdditionalHeuristics(domain) {
        // This method is now used for edge cases not covered by the main structure analysis
        const parts = domain.split('.');
        const suspiciousDigitRatio = CONFIG?.DETECTION?.SUSPICIOUS_DIGIT_RATIO || 0.4; // Increased threshold
        
        // Check for domains with suspicious digit patterns (improved logic)
        const mainDomain = parts[0] || '';
        if (mainDomain.length > 6 && /\d/.test(mainDomain) && /[a-z]/i.test(mainDomain)) {
            const digitRatio = (mainDomain.match(/\d/g) || []).length / mainDomain.length;
            
            // More sophisticated patterns to avoid false positives
            const isLegitimatePattern = /^[a-z]+\d{1,3}$|^[a-z]+-\d{1,3}$|^v\d+/i.test(mainDomain);
            
            if (digitRatio > suspiciousDigitRatio && !isLegitimatePattern) {
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

    shouldCallBackend(localResult, url) {
        // Only call backend for uncertain cases
        if (localResult.isSuspicious && localResult.confidence >= 0.75) {
            return false; // Trust local analysis at 75%+ confidence
        }
        
        if (!localResult.isSuspicious && this.isKnownSafeDomain(url)) {
            return false; // Known safe domain
        }
        
        // Call backend only for genuinely uncertain cases
        return (
            (localResult.isSuspicious && localResult.confidence < 0.75) ||
            (!localResult.isSuspicious && !this.isKnownSafeDomain(url))
        );
    }

    async performServerAnalysis(url, localResult) {
        try {
            const response = await fetch('http://localhost:8000/url-analysis/analyze-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: url,
                    confidence: localResult.confidence,
                    reason: this.encodeReason(localResult.reason)
                })
            });

            if (response.ok) {
                const result = await response.json();
                console.log('CatchThePhish: Server response:', result);
                
                return {
                    isSuspicious: result.suspicious,
                    confidence: result.confidence,
                    reason: this.cleanReasonForUser(result.reason), // Clean up server responses
                    threatType: result.type,
                    serverEnhanced: true
                };
            } else {
                console.warn('CatchThePhish: Server returned error:', response.status);
            }
        } catch (error) {
            console.warn('CatchThePhish: Server unavailable:', error.message);
        }
        
        return { serverAvailable: false };
    }

    // Encode reasons to short codes to reduce payload
    encodeReason(reason) {
        const reasonMap = {
            'Using IP address instead of domain name': 'ip_addr',
            'Domain uses suspicious top-level domain': 'bad_tld',
            'Contains suspicious keywords': 'sus_keywords',
            'Potential impersonation': 'typo_detected',
            'Domain contains suspicious subdomain patterns': 'bad_subdomain'
        };
        
        for (const [fullReason, code] of Object.entries(reasonMap)) {
            if (reason.includes(fullReason)) return code;
        }
        return 'other';
    }

    // Helper to check if a domain is known to be safe (e.g., from a trusted list)
    isKnownSafeDomain(url) {
        try {
            const domain = new URL(url).hostname.toLowerCase();
            const trustedDomains = CONFIG?.PROTECTED_DOMAINS || [];
            
            // Check if it's an exact match or subdomain of trusted domain
            return trustedDomains.some(trusted => 
                domain === trusted || domain.endsWith('.' + trusted)
            );
        } catch (error) {
            return false;
        }
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
            const stats = {
                // Simple telemetry
                blocked: this.stats.threatsBlocked,
                reported: this.stats.urlsReported,
                totalScanned: this.stats.urlsScanned,
                version: '1.0.0'
            };
            console.log('📊 Returning stats:', stats);
            return stats;
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

    cleanReasonForUser(serverReason) {
        // Remove technical prefixes and make user-friendly
        return serverReason
            .replace(/^🛡️ Server Confirmed: /, '')
            .replace(/^🛡️ Server Alert: /, '')
            .replace(/^🔍 Server Analysis: /, '')
            .replace(/^⚠️ Server Error: /, '')
            .replace(/Local analysis detected suspicious patterns \(confidence: \d+%\)/, 'This website looks suspicious')
            .replace(/security vendors/, 'security experts')
            .replace(/malicious vendors/, 'security experts');
    }

    // Track real-time threats detected on a page
    recordRealtimeThreat(tabId, url, threat) {
        if (!this.realtimeThreats.has(tabId)) {
            this.realtimeThreats.set(tabId, []);
        }
        
        const threats = this.realtimeThreats.get(tabId);
        // Avoid duplicates
        if (!threats.some(t => t.url === url)) {
            threats.push({
                url: url,
                threat: threat,
                timestamp: Date.now()
            });
        }
    }
    
    // Get page security status
    getPageStatus(tabId, pageUrl) {
        const pageState = this.pageStates.get(tabId);
        const realtimeThreats = this.realtimeThreats.get(tabId) || [];
        
        // Check if there are real-time threats on this page
        if (realtimeThreats.length > 0) {
            return {
                status: 'threats_detected',
                message: `${realtimeThreats.length} suspicious link${realtimeThreats.length > 1 ? 's' : ''} found on this page`,
                icon: '⚠️',
                threats: realtimeThreats,
                needsScan: false
            };
        }
        
        // Check if page was manually scanned
        if (pageState?.scanned && pageState?.url === pageUrl) {
            const timeSince = Date.now() - pageState.timestamp;
            const minutesAgo = Math.floor(timeSince / (1000 * 60));
            
            return {
                status: pageState.result.isSuspicious ? 'dangerous' : 'safe',
                message: pageState.result.isSuspicious 
                    ? pageState.result.reason 
                    : `Scanned ${minutesAgo < 1 ? 'just now' : `${minutesAgo} minute${minutesAgo > 1 ? 's' : ''} ago`}`,
                icon: pageState.result.isSuspicious ? '🚨' : '✅',
                result: pageState.result,
                needsScan: false
            };
        }
        
        // Default: needs scanning
        return {
            status: 'needs_scan',
            message: 'Click to scan this website for threats',
            icon: '🔍',
            needsScan: true
        };
    }

    async extractLinksFromPage(tabId) {
        try {
            const links = await chrome.tabs.sendMessage(tabId, {
                action: 'extractAllLinks'
            });
            return links || [];
        } catch (error) {
            console.warn('Could not extract links from page:', error);
            return [];
        }
    }

    async performComprehensiveScan(pageUrl, links) {
        try {
            const response = await fetch('http://localhost:8000/url-analysis/scan-page', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    page_url: pageUrl,
                    extracted_links: links.slice(0, 10) // Limit to 10 links
                })
            });
            
            return await response.json();
        } catch (error) {
            console.error('Backend comprehensive scan failed:', error);
            throw error;
        }
    }
}

// Initialize the background service
new BackgroundService();
