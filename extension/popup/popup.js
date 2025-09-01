document.addEventListener('DOMContentLoaded', async () => {
    console.log('CatchThePhish: Popup loaded');
    
    // Initialize popup
    await initializePopup();
    
    // Setup event listeners
    setupEventListeners();
});

async function initializePopup() {
    try {
        await Promise.all([
            loadStats(),
            loadDailyTip(),
            checkCurrentPage(),
            loadSettings()
        ]);
    } catch (error) {
        console.error('CatchThePhish: Error initializing popup:', error);
    }
}

async function loadStats() {
    try {
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
    // Use tips from CONFIG instead of hardcoded array
    const tips = [
        "Always verify the sender before clicking links in emails or messages.",
        "Check URLs carefully - scammers often use similar-looking domains.",
        "Be suspicious of urgent requests for personal information.",
        "When in doubt, navigate to websites directly rather than clicking links.",
        "Look for HTTPS and valid security certificates on websites.",
        "Scammers often create fake urgency to pressure quick decisions.",
        "Trust your instincts - if something feels wrong, it probably is."
    ];
    
    const today = new Date();
    const dayOfYear = Math.floor((today - new Date(today.getFullYear(), 0, 0)) / 1000 / 60 / 60 / 24);
    const tipIndex = dayOfYear % tips.length;
    
    document.getElementById('dailyTip').textContent = tips[tipIndex];
}

async function checkCurrentPage() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab?.url) {
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
    
    if (analysis?.isSuspicious) {
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
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab?.url) {
            await chrome.runtime.sendMessage({
                action: 'reportPhishing',
                url: tab.url
            });
            
            const button = document.getElementById('reportPage');
            const originalHTML = button.innerHTML;
            button.innerHTML = '<span class="btn-icon">✅</span>Reported!';
            
            setTimeout(() => {
                button.innerHTML = originalHTML;
            }, 2000);
        }
    });
    
    // REMOVE OR FIX: View reports button (reports.html doesn't exist)
    // document.getElementById('viewReports').addEventListener('click', () => {
    //     chrome.tabs.create({ url: chrome.runtime.getURL('reports.html') });
    // });
    
    // Settings toggles
    document.getElementById('enableProtection').addEventListener('change', async (e) => {
        await chrome.storage.sync.set({ enableProtection: e.target.checked });
        
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
