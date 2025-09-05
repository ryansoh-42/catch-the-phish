console.log('CatchThePhish: Content script loaded');

class PhishingDetector {
    constructor() {
        this.isEnabled = true;
        this.warningElement = null;
        this.hoverTimeout = null;
        this.init();
    }

    init() {
        this.setupLinkMonitoring();
        this.setupMessageListener();
        this.setupPageNavigationMonitoring();
        // Scan current page URL on load to catch address-bar navigations
        setTimeout(() => this.scanCurrentPageURL(), 0);
        console.log('CatchThePhish: Phishing detector initialized');
    }

    setupLinkMonitoring() {
        // Monitor mouse hover events with debouncing
        document.addEventListener('mouseover', (event) => {
            if (event.target.tagName === 'A' && event.target.href) {
                if (this.hoverTimeout) {
                    clearTimeout(this.hoverTimeout);
                }
                
                this.hoverTimeout = setTimeout(() => {
                    this.checkLink(event.target);
                }, 500); // Fixed 500ms delay
            }
        });

        // Clear timeout when mouse leaves
        document.addEventListener('mouseout', (event) => {
            if (event.target.tagName === 'A' && this.hoverTimeout) {
                clearTimeout(this.hoverTimeout);
                this.hoverTimeout = null;
            }
        });

        // Monitor copy events
        document.addEventListener('copy', (event) => {
            const selection = window.getSelection().toString();
            if (this.isURL(selection)) {
                this.checkURL(selection, 'copied');
            }
        });

        // Monitor paste events (reliable via clipboardData + fallback)
        document.addEventListener('paste', (event) => {
            try {
                let pastedText = '';
                if (event.clipboardData && typeof event.clipboardData.getData === 'function') {
                    pastedText = event.clipboardData.getData('text/plain');
                }

                // If clipboardData is unavailable, fallback to reading from the target after paste
                if (!pastedText) {
                    setTimeout(() => {
                        const fallbackText = (event.target && (event.target.value || event.target.textContent)) || '';
                        if (this.isURL(fallbackText)) {
                            this.checkURL(fallbackText, 'pasted');
                        }
                    }, 50);
                    return;
                }

                if (this.isURL(pastedText)) {
                    this.checkURL(pastedText, 'pasted');
                }
            } catch (e) {
                console.warn('CatchThePhish: paste handler error', e);
            }
        }, true);
    }

    setupPageNavigationMonitoring() {
        try {
            let lastScannedUrl = '';
            const scanIfChanged = () => {
                const current = window.location.href;
                if (current !== lastScannedUrl) {
                    lastScannedUrl = current;
                    this.scanCurrentPageURL();
                }
            };

            // Handle SPA navigations
            const pushState = history.pushState;
            history.pushState = (...args) => {
                const ret = pushState.apply(history, args);
                setTimeout(scanIfChanged, 0);
                return ret;
            };

            const replaceState = history.replaceState;
            history.replaceState = (...args) => {
                const ret = replaceState.apply(history, args);
                setTimeout(scanIfChanged, 0);
                return ret;
            };

            window.addEventListener('popstate', () => {
                setTimeout(scanIfChanged, 0);
            });
        } catch (e) {
            console.warn('CatchThePhish: setupPageNavigationMonitoring error', e);
        }
    }

    scanCurrentPageURL() {
        try {
            const href = window.location.href;
            if (this.isURL(href) && InputValidator.isValidURL(href)) {
                this.checkURL(href, 'page_load');
            }
        } catch (e) {
            console.warn('CatchThePhish: scanCurrentPageURL error', e);
        }
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            switch (request.action) {
                case 'urlCheckResult':
                    this.handleURLCheckResult(request.data);
                    sendResponse({ success: true });
                    break;
                case 'textAnalysisResult':
                    this.handleTextAnalysisResult(request.data);
                    sendResponse({ success: true });
                    break;
                case 'extractTextChunks':
                    const chunks = this.extractTextChunks();
                    sendResponse(chunks);
                    break;
                case 'extractAllLinks':
                    try {
                        console.log('CatchThePhish: Extracting all links from page');
                        const links = Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href)
                            .filter(href => href.startsWith('http'))
                            .slice(0, 20); // Limit to 20 links
                        
                        console.log('CatchThePhish: Found links:', links);
                        sendResponse(links);
                    } catch (error) {
                        console.error('CatchThePhish: Error extracting links:', error);
                        sendResponse([]);
                    }
                    break;
                default:
                    console.warn('CatchThePhish: Unknown action in content script:', request.action);
                    sendResponse({ error: 'Unknown action' });
                    break;
            }
            return true; // Keep message channel open for async response
        });
    }

    checkLink(linkElement) {
        try {
            const url = linkElement.href;
            
            if (!InputValidator.isValidURL(url)) {
                // Skip invalid URLs (javascript:, mailto:, etc.) silently - this is expected behavior
                if (url && !url.startsWith('javascript:') && !url.startsWith('mailto:') && !url.startsWith('tel:') && url !== '#') {
                    console.warn('CatchThePhish: Invalid URL detected:', url);
                }
                return;
            }
            
            const sanitizedUrl = InputValidator.sanitizeURL(url);
            console.log('CatchThePhish: Checking link:', sanitizedUrl);
            
            chrome.runtime.sendMessage({
                action: 'checkURL',
                url: sanitizedUrl,
                element: this.getElementInfo(linkElement)
            });
        } catch (error) {
            console.error('CatchThePhish: Error checking link:', error);
        }
    }

    checkURL(url, context) {
        try {
            const normalizedUrl = this.normalizeURLInput(url);
            if (!InputValidator.isValidURL(normalizedUrl)) {
                console.warn('CatchThePhish: Invalid URL in context:', context, url);
                return;
            }
            
            const sanitizedUrl = InputValidator.sanitizeURL(normalizedUrl);
            console.log(`CatchThePhish: Checking ${context} URL:`, sanitizedUrl);
            
            chrome.runtime.sendMessage({
                action: 'checkURL',
                url: sanitizedUrl,
                context: context
            });
        } catch (error) {
            console.error('CatchThePhish: Error checking URL:', error);
        }
    }

    isURL(text) {
        if (!text || typeof text !== 'string') return false;
        const trimmed = text.trim();
        // Quick reject for obvious non-URLs
        if (trimmed.length < 4 || /\s/.test(trimmed)) return false;
        // Accept common URL forms with or without protocol
        const urlLike = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,})(:[0-9]{2,5})?(\/[^\s]*)?$/i;
        return urlLike.test(trimmed);
    }

    normalizeURLInput(text) {
        const candidate = (text || '').trim();
        if (!candidate) return candidate;
        // If already has protocol, return as-is
        if (/^https?:\/\//i.test(candidate)) return candidate;
        // If it looks like a domain path, prefix https://
        if (/^([\da-z.-]+)\.([a-z.]{2,})(:[0-9]{2,5})?(\/.*)?$/i.test(candidate)) {
            return `https://${candidate}`;
        }
        return candidate;
    }

    getElementInfo(element) {
        return {
            tagName: element.tagName,
            className: element.className,
            id: element.id,
            text: element.textContent.trim().substring(0, 100)
        };
    }

    handleURLCheckResult(data) {
        if (data.isSuspicious) {
            console.log('CatchThePhish: Showing warning for suspicious URL:', {
                url: data.url,
                fromCache: data.fromCache,
                reason: data.reason
            });
            this.showWarning(data);
        }
    }

    showWarning(warningData) {
        this.hideWarning();
        this.warningElement = this.createWarningElement(warningData);
        document.body.appendChild(this.warningElement);

        setTimeout(() => {
            this.hideWarning();
        }, 12000); // Fixed 12 second auto-hide
    }

    createWarningElement(data) {
        const warning = document.createElement('div');
        warning.id = 'catchthephish-warning';
        warning.className = 'catchthephish-warning';
        
        const warningContent = document.createElement('div');
        warningContent.className = 'warning-content';
        
        // Simple Header
        const header = document.createElement('div');
        header.className = 'warning-header';
        
        const icon = document.createElement('span');
        icon.className = 'warning-icon';
        icon.textContent = '⚠️';
        
        const title = document.createElement('span');
        title.className = 'warning-title';
        title.textContent = 'Suspicious URL Detected'; // Simple, consistent title
        
        const closeBtn = document.createElement('button');
        closeBtn.className = 'warning-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.setAttribute('aria-label', 'Close warning');
        closeBtn.addEventListener('click', () => this.hideWarning());
        
        header.appendChild(icon);
        header.appendChild(title);
        header.appendChild(closeBtn);
        
        // Simple Body - Just the essentials
        const body = document.createElement('div');
        body.className = 'warning-body';
        
        // Main reason (simplified)
        const reasonP = document.createElement('p');
        reasonP.style.cssText = 'margin: 0 0 15px 0; font-size: 14px; color: #333;';
        reasonP.textContent = InputValidator.sanitizeText(data.reason);
        body.appendChild(reasonP);
        
        // Educational tip (combined, Singapore-focused)
        if (data.tip) {
            const tipDiv = document.createElement('div');
            tipDiv.className = 'educational-tip';
            tipDiv.style.cssText = 'background: #fff8e1; padding: 12px; border-radius: 4px; border-left: 4px solid #ffc107;';
            
            const tipStrong = document.createElement('strong');
            tipStrong.textContent = '💡 Security Tip: ';
            tipStrong.style.color = '#e65100';
            tipDiv.appendChild(tipStrong);
            
            const tipText = document.createElement('span');
            tipText.textContent = InputValidator.sanitizeText(data.tip);
            tipText.style.color = '#bf360c';
            tipDiv.appendChild(tipText);
            
            body.appendChild(tipDiv);
        }
        
        // Simple Actions
        const actions = document.createElement('div');
        actions.className = 'warning-actions';
        actions.style.cssText = 'padding: 15px 20px; border-top: 1px solid #eee; display: flex; gap: 10px;';
        
        const safeBtn = document.createElement('button');
        safeBtn.className = 'btn-safe';
        safeBtn.textContent = 'I Understand';
        safeBtn.addEventListener('click', () => this.hideWarning());
        
        const reportBtn = document.createElement('button');
        reportBtn.className = 'btn-report';
        reportBtn.textContent = 'Report Scam';
        reportBtn.addEventListener('click', () => {
            try {
                const sanitizedUrl = InputValidator.sanitizeURL(data.url);
                chrome.runtime.sendMessage({
                    action: 'reportPhishing',
                    url: sanitizedUrl
                });
                this.hideWarning();
            } catch (error) {
                console.error('CatchThePhish: Error reporting URL:', error);
            }
        });
        
        actions.appendChild(safeBtn);
        actions.appendChild(reportBtn);
        
        // Assemble
        warningContent.appendChild(header);
        warningContent.appendChild(body);
        warningContent.appendChild(actions);
        warning.appendChild(warningContent);
        
        warning.setAttribute('role', 'alert');
        warning.setAttribute('aria-live', 'assertive');
        
        return warning;
    }

    extractTextChunks() {
        const chunks = [];
        const textElements = document.querySelectorAll('p, div, span, h1, h2, h3, h4, h5, h6, li, td, th');
        
        textElements.forEach((element, index) => {
            const text = element.textContent?.trim();
            if (text && text.length > 20 && text.length < 1000) {
                chunks.push({
                    id: `chunk_${index}`,
                    text: text,
                    element_type: element.tagName.toLowerCase(),
                    position: this.getElementPosition(element)
                });
            }
        });
        
        console.log('CatchThePhish: Extracted', chunks.length, 'text chunks from page');
        return chunks.slice(0, 50); // Limit to 50 chunks to avoid overwhelming the backend
    }

    getElementPosition(element) {
        const rect = element.getBoundingClientRect();
        return {
            top: rect.top + window.scrollY,
            left: rect.left + window.scrollX
        };
    }

    handleTextAnalysisResult(data) {
        if (data.error) {
            this.showTextAnalysisNotification(
                '❌ Text Analysis Failed',
                'Unable to analyze selected text',
                'error'
            );
            return;
        }

        const { result, text } = data;
        const truncatedText = text.length > 100 ? text.substring(0, 100) + '...' : text;
        
        if (result.is_suspicious) {
            this.showTextAnalysisNotification(
                '⚠️ Suspicious Text Detected',
                `"${truncatedText}" - ${result.reasons.join(', ')}`,
                'warning'
            );
        } else {
            this.showTextAnalysisNotification(
                '✅ Text Appears Safe',
                `"${truncatedText}" - No threats detected`,
                'safe'
            );
        }
    }

    showTextAnalysisNotification(title, message, type) {
        // Remove existing notification
        const existing = document.getElementById('ctp-text-analysis-notification');
        if (existing) {
            existing.remove();
        }

        // Create notification element
        const notification = document.createElement('div');
        notification.id = 'ctp-text-analysis-notification';
        notification.className = `ctp-text-notification ctp-${type}`;
        
        notification.innerHTML = `
            <div class="ctp-notification-header">
                <strong>${title}</strong>
                <button class="ctp-close-btn" onclick="this.parentElement.parentElement.remove()">×</button>
            </div>
            <div class="ctp-notification-body">${message}</div>
        `;

        // Add styles
        const style = document.createElement('style');
        style.textContent = `
            .ctp-text-notification {
                position: fixed;
                top: 20px;
                right: 20px;
                max-width: 400px;
                padding: 15px;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                z-index: 999999;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 14px;
                line-height: 1.4;
            }
            .ctp-warning {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                color: #856404;
            }
            .ctp-safe {
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
            }
            .ctp-error {
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                color: #721c24;
            }
            .ctp-notification-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 8px;
            }
            .ctp-close-btn {
                background: none;
                border: none;
                font-size: 18px;
                cursor: pointer;
                padding: 0;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .ctp-notification-body {
                word-wrap: break-word;
            }
        `;
        
        if (!document.getElementById('ctp-text-notification-styles')) {
            style.id = 'ctp-text-notification-styles';
            document.head.appendChild(style);
        }

        document.body.appendChild(notification);

        // Auto-remove after 8 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 8000);
    }

    hideWarning() {
        if (this.warningElement) {
            this.warningElement.remove();
            this.warningElement = null;
        }
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new PhishingDetector());
} else {
    new PhishingDetector();
}
