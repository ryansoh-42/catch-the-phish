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
                }, CONFIG?.DETECTION?.HOVER_DELAY || 500);
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

        // Monitor paste events
        document.addEventListener('paste', (event) => {
            setTimeout(() => {
                const pastedText = event.target.value || event.target.textContent;
                if (this.isURL(pastedText)) {
                    this.checkURL(pastedText, 'pasted');
                }
            }, 100);
        });
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === 'urlCheckResult') {
                this.handleURLCheckResult(request.data);
            }
        });
    }

    checkLink(linkElement) {
        try {
            const url = linkElement.href;
            
            if (!InputValidator.isValidURL(url)) {
                console.warn('CatchThePhish: Invalid URL detected:', url);
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
            if (!InputValidator.isValidURL(url)) {
                console.warn('CatchThePhish: Invalid URL in context:', context, url);
                return;
            }
            
            const sanitizedUrl = InputValidator.sanitizeURL(url);
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
        const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;
        return urlPattern.test(text.trim());
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
        }, CONFIG?.DETECTION?.WARNING_AUTO_HIDE || 12000);
    }

    createWarningElement(data) {
        const warning = document.createElement('div');
        warning.id = 'catchthephish-warning';
        warning.className = 'catchthephish-warning';
        
        const warningContent = document.createElement('div');
        warningContent.className = 'warning-content';
        
        // Header
        const header = this.createWarningHeader();
        
        // Body
        const body = this.createWarningBody(data);
        
        // Actions
        const actions = this.createWarningActions(data);
        
        warningContent.appendChild(header);
        warningContent.appendChild(body);
        warningContent.appendChild(actions);
        warning.appendChild(warningContent);
        
        warning.setAttribute('role', 'alert');
        warning.setAttribute('aria-live', 'assertive');
        
        return warning;
    }

    createWarningHeader() {
        const header = document.createElement('div');
        header.className = 'warning-header';
        
        const icon = document.createElement('span');
        icon.className = 'warning-icon';
        icon.textContent = '⚠️';
        
        const title = document.createElement('span');
        title.className = 'warning-title';
        title.textContent = 'Suspicious Link Detected';
        
        const closeBtn = document.createElement('button');
        closeBtn.className = 'warning-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.setAttribute('aria-label', 'Close warning');
        closeBtn.addEventListener('click', () => this.hideWarning());
        
        header.appendChild(icon);
        header.appendChild(title);
        header.appendChild(closeBtn);
        
        return header;
    }

    createWarningBody(data) {
        const body = document.createElement('div');
        body.className = 'warning-body';
        
        // Reason
        const reasonP = document.createElement('p');
        const reasonStrong = document.createElement('strong');
        reasonStrong.textContent = 'Reason: ';
        reasonP.appendChild(reasonStrong);
        reasonP.appendChild(document.createTextNode(InputValidator.sanitizeText(data.reason)));
        
        // URL
        const urlP = document.createElement('p');
        const urlStrong = document.createElement('strong');
        urlStrong.textContent = 'URL: ';
        urlP.appendChild(urlStrong);
        urlP.appendChild(document.createTextNode(InputValidator.sanitizeText(data.url)));
        
        body.appendChild(reasonP);
        body.appendChild(urlP);
        
        // Educational tip
        if (data.tip) {
            const tipDiv = document.createElement('div');
            tipDiv.className = 'educational-tip';
            const tipStrong = document.createElement('strong');
            tipStrong.textContent = '💡 Security Tip: ';
            tipDiv.appendChild(tipStrong);
            tipDiv.appendChild(document.createTextNode(InputValidator.sanitizeText(data.tip)));
            body.appendChild(tipDiv);
        }
        
        return body;
    }

    createWarningActions(data) {
        const actions = document.createElement('div');
        actions.className = 'warning-actions';
        
        const safeBtn = document.createElement('button');
        safeBtn.className = 'btn-safe';
        safeBtn.textContent = 'I Understand';
        safeBtn.addEventListener('click', () => this.hideWarning());
        
        const reportBtn = document.createElement('button');
        reportBtn.className = 'btn-report';
        reportBtn.textContent = 'Report This Site';
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
        
        return actions;
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
