console.log('CatchThePhish: Content script loaded');

class PhishingDetector {
    constructor() {
        this.isEnabled = true;
        this.warningElement = null;
        this.init();
    }

    init() {
        // Listen for link interactions
        this.setupLinkMonitoring();
        
        // Listen for messages from background script
        this.setupMessageListener();
        
        console.log('CatchThePhish: Phishing detector initialized');
    }

    setupLinkMonitoring() {
        // Add these properties to track state
        this.checkedURLs = new Set();
        this.hoverTimeout = null;
        this.lastCheckedURL = null;

        // Monitor mouse hover events on links with debouncing
        document.addEventListener('mouseover', (event) => {
            if (event.target.tagName === 'A' && event.target.href) {
                // Clear previous timeout
                if (this.hoverTimeout) {
                    clearTimeout(this.hoverTimeout);
                }
                
                const url = event.target.href;
                
                // Skip if already checked this URL
                if (this.checkedURLs.has(url)) {
                    return;
                }
                
                // Wait 500ms before checking (debounce)
                this.hoverTimeout = setTimeout(() => {
                    this.checkLink(event.target);
                }, 500);
            }
        });

        // Clear timeout when mouse leaves
        document.addEventListener('mouseout', (event) => {
            if (event.target.tagName === 'A' && this.hoverTimeout) {
                clearTimeout(this.hoverTimeout);
                this.hoverTimeout = null;
            }
        });

        // Monitor when users copy links
        document.addEventListener('copy', (event) => {
            const selection = window.getSelection().toString();
            if (this.isURL(selection)) {
                this.checkURL(selection, 'copied');
            }
        });

        // Monitor paste events (for when users paste URLs)
        document.addEventListener('paste', (event) => {
            // Small delay to let paste complete
            setTimeout(() => {
                const pastedText = event.target.value || event.target.textContent;
                if (this.isURL(pastedText)) {
                    this.checkURL(pastedText, 'pasted');
                }
            }, 100);
        });
    }

    setupMessageListener() {
        // Listen for messages from background script
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            if (request.action === 'urlCheckResult') {
                this.handleURLCheckResult(request.data);
            }
        });
    }

    checkLink(linkElement) {
        const url = linkElement.href;
        
        // Add to checked URLs to prevent duplicates
        this.checkedURLs.add(url);
        
        console.log('CatchThePhish: Checking link:', url);
        
        // Send URL to background script for analysis
        chrome.runtime.sendMessage({
            action: 'checkURL',
            url: url,
            element: this.getElementInfo(linkElement)
        });
    }

    checkURL(url, context) {
        console.log(`CatchThePhish: Checking ${context} URL:`, url);
        
        chrome.runtime.sendMessage({
            action: 'checkURL',
            url: url,
            context: context
        });
    }

    isURL(text) {
        // Simple URL detection regex
        const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;
        return urlPattern.test(text.trim());
    }

    getElementInfo(element) {
        return {
            tagName: element.tagName,
            className: element.className,
            id: element.id,
            text: element.textContent.trim().substring(0, 100) // First 100 chars
        };
    }

    handleURLCheckResult(data) {
        if (data.isSuspicious) {
            this.showWarning(data);
        }
    }

    showWarning(warningData) {
        // Remove any existing warnings
        this.hideWarning();

        // Create warning popup
        this.warningElement = this.createWarningElement(warningData);
        document.body.appendChild(this.warningElement);

        // Auto-hide after 10 seconds
        setTimeout(() => {
            this.hideWarning();
        }, 10000);
    }

    createWarningElement(data) {
        const warning = document.createElement('div');
        warning.id = 'catchthephish-warning';
        warning.className = 'catchthephish-warning';
        
        warning.innerHTML = `
            <div class="warning-content">
                <div class="warning-header">
                    <span class="warning-icon">⚠️</span>
                    <span class="warning-title">Suspicious Link Detected</span>
                    <button class="warning-close" onclick="this.parentElement.parentElement.parentElement.remove()">&times;</button>
                </div>
                <div class="warning-body">
                    <p><strong>Reason:</strong> ${data.reason}</p>
                    <p><strong>URL:</strong> ${data.url}</p>
                    ${data.tip ? `<div class="educational-tip"><strong>💡 Tip:</strong> ${data.tip}</div>` : ''}
                </div>
                <div class="warning-actions">
                    <button class="btn-safe" onclick="this.parentElement.parentElement.parentElement.remove()">I Understand</button>
                    <button class="btn-report" onclick="window.catchThePhishReport('${data.url}')">Report This</button>
                </div>
            </div>
        `;

        return warning;
    }

    hideWarning() {
        if (this.warningElement) {
            this.warningElement.remove();
            this.warningElement = null;
        }
    }
}

// Global function for reporting (called from warning buttons)
window.catchThePhishReport = function(url) {
    chrome.runtime.sendMessage({
        action: 'reportPhishing',
        url: url
    });
    
    // Hide the warning
    const warning = document.getElementById('catchthephish-warning');
    if (warning) warning.remove();
};

// Initialize the detector when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishingDetector();
    });
} else {
    new PhishingDetector();
}
