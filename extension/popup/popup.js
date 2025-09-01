document.addEventListener('DOMContentLoaded', async () => {
    console.log('CatchThePhish: Popup loaded');
    
    // Initialize popup
    await initializePopup();
    
    // Setup event listeners
    setupEventListeners();
});

async function initializePopup() {
    try {
        // Load protection stats
        await loadStats();
        
        // Load daily tip
        await loadDailyTip();
        
        // Check current page status
        await checkCurrentPage();
        
        // Load settings
        await loadSettings();
        
    } catch (error) {
        console.error('CatchThePhish: Error initializing popup:', error);
    }
}

async function loadStats() {
    try {
        // Get stats from background script
        const response = await chrome.runtime.sendMessage({ action: 'getStats' });
        
        if (response) {
            document.getElementById('blockedCount').textContent = response.blocked || 0;
            document.getElementById('reportedCount').textContent = response.reported || 0;
        }
    } catch (error) {
        console.error('CatchThePhish: Error loading stats:', error);
    }
}

async function loadDailyTip() {
    const tips = [
        "Always verify the sender before clicking links in emails or messages.",
        "Check URLs carefully - scammers often use similar-looking domains.",
        "Be suspicious of urgent requests for personal information.",
        "When in doubt, navigate to websites directly rather than clicking links.",
        "Look for HTTPS and valid security certificates on websites.",
        "Scammers often create fake urgency to pressure quick decisions.",
        "Trust your instincts - if something feels wrong, it probably is."
    ];
    
    // Use date to get consistent daily tip
    const today = new Date();
    const dayOfYear = Math.floor((today - new Date(today.getFullYear(), 0, 0)) / 1000 / 60 / 60 / 24);
    const tipIndex = dayOfYear % tips.length;
    
    document.getElementById('dailyTip').textContent = tips[tipIndex];
}

async function checkCurrentPage() {
    try {
        // Get current active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            // Send URL to background for analysis
            const response = await chrome.runtime.sendMessage({
                action: 'checkURL',
                url: tab.url
            });
            
            updatePageStatus(response);
        }
    } catch (error) {
        console.error('CatchThePhish: Error checking current page:', error);
    }
}

function updatePageStatus(analysis) {
    const statusElement = document.getElementById('pageStatus');
    const pageIcon = statusElement.querySelector('.page-icon');
    const pageText = statusElement.querySelector('.page-text');
    
    if (analysis && analysis.isSuspicious) {
        pageIcon.textContent = '⚠️';
        pageText.textContent = `Warning: ${analysis.reason}`;
        statusElement.style.background = '#ffebee';
        pageText.style.color = '#c62828';
    } else {
        pageIcon.textContent = '✅';
        pageText.textContent = 'This page appears safe';
        statusElement.style.background = '#e8f5e8';
        pageText.style.color = '#2e7d32';
    }
}

async function loadSettings() {
    try {
        const result = await chrome.storage.sync.get(['enableProtection', 'enableTips']);
        
        document.getElementById('enableProtection').checked = result.enableProtection !== false;
        document.getElementById('enableTips').checked = result.enableTips !== false;
        
    } catch (error) {
        console.error('CatchThePhish: Error loading settings:', error);
    }
}

function setupEventListeners() {
    // Scan page button
    document.getElementById('scanPage').addEventListener('click', async () => {
        const button = document.getElementById('scanPage');
        const originalText = button.textContent;
        
        button.textContent = 'Scanning...';
        button.disabled = true;
        
        await checkCurrentPage();
        
        setTimeout(() => {
            button.textContent = originalText;
            button.disabled = false;
        }, 1000);
    });
    
    // Report page button
    document.getElementById('reportPage').addEventListener('click', async () => {
        const button = document.getElementById('reportPage');
        
        try {
            // Check if already reported
            if (button.classList.contains('reported')) {
                return;
            }

            // Update button to loading state
            button.disabled = true;
            button.innerHTML = '<span class="btn-icon">⏳</span>Reporting...';
            
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (tab && tab.url) {
                // Send report to background script
                const response = await chrome.runtime.sendMessage({
                    action: 'reportPhishing',
                    url: tab.url
                });

                if (response && response.success) {
                    // Update reported count
                    const reportedEl = document.getElementById('reportedCount');
                    const newCount = parseInt(reportedEl.textContent || '0') + 1;
                    reportedEl.textContent = newCount;
                    
                    // Show permanent success state
                    button.innerHTML = '<span class="btn-icon">✅</span>Reported';
                    button.classList.add('reported');
                    // Don't reset the button state
                } else {
                    throw new Error('Failed to report URL');
                }
            }
        } catch (error) {
            console.error('CatchThePhish: Error reporting page:', error);
            button.innerHTML = '<span class="btn-icon">⚠️</span>Error';
            button.disabled = false;
        }
    });
    
    // View reports button
    document.getElementById('viewReports').addEventListener('click', () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('reports.html') });
    });
    
    // Settings toggles
    document.getElementById('enableProtection').addEventListener('change', async (e) => {
        await chrome.storage.sync.set({ enableProtection: e.target.checked });
        
        // Update status indicator
        const indicator = document.getElementById('statusIndicator');
        const statusText = document.getElementById('statusText');
        
        if (e.target.checked) {
            indicator.classList.add('active');
            statusText.textContent = 'Active';
        } else {
            indicator.classList.remove('active');
            statusText.textContent = 'Disabled';
        }
    });
    
    document.getElementById('enableTips').addEventListener('change', async (e) => {
        await chrome.storage.sync.set({ enableTips: e.target.checked });
    });
}

async function handlePhishingReport(url) {
    try {
        // Get current stats
        const stats = await chrome.storage.local.get(['reported']);
        const currentReported = stats.reported || 0;

        // Increment reported count
        await chrome.storage.local.set({
            reported: currentReported + 1
        });

        // Here you would typically send the report to your backend
        // For now, we'll just log it
        console.log('Phishing URL reported:', url);

        return {
            success: true,
            newCount: currentReported + 1
        };
    } catch (error) {
        console.error('Failed to handle phishing report:', error);
        throw error;
    }
}
