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
        console.log('📊 Loading stats...');
        const response = await chrome.runtime.sendMessage({ action: 'getStats' });
        console.log('📊 Stats response:', response);
        
        if (response && !response.error) {
            // Updated to use more informative labels
            const suspiciousElement = document.getElementById('suspiciousFound');
            const websitesElement = document.getElementById('websitesChecked');
            
            console.log('📊 Updating UI elements:', {
                blocked: response.blocked,
                totalScanned: response.totalScanned
            });
            
            if (suspiciousElement) {
                suspiciousElement.textContent = response.blocked || 0;
                console.log('📊 Set suspicious count to:', response.blocked || 0);
            }
            if (websitesElement) {
                websitesElement.textContent = response.totalScanned || 0;
                console.log('📊 Set websites count to:', response.totalScanned || 0);
            }
        }
    } catch (error) {
        console.error('CatchThePhish: Error loading stats:', error);
        // Fallback to show zeros with null checks
        const suspiciousElement = document.getElementById('suspiciousFound');
        const websitesElement = document.getElementById('websitesChecked');
        
        if (suspiciousElement) suspiciousElement.textContent = '0';
        if (websitesElement) websitesElement.textContent = '0';
    }
}

async function loadDailyTip() {
    // Use Singapore-focused tips from CONFIG
    const tips = CONFIG?.EDUCATIONAL_TIPS || [
        "Stay safe online - verify before you trust!"
    ];
    
    const today = new Date();
    const dayOfYear = Math.floor((today - new Date(today.getFullYear(), 0, 0)) / 1000 / 60 / 60 / 24);
    const tipIndex = dayOfYear % tips.length;
    
    const tipElement = document.getElementById('dailyTip');
    if (tipElement) {
        tipElement.textContent = tips[tipIndex];
    }
}

async function checkCurrentPage() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        console.log('CatchThePhish: Current tab:', tab); // Debug log
        
        if (tab?.url && tab?.id) {
            const response = await chrome.runtime.sendMessage({
                action: 'getPageStatus',
                tabId: tab.id,
                url: tab.url
            });
            updatePageStatus(response, tab); // Make sure tab is passed
        } else {
            console.error('CatchThePhish: No valid tab found');
            // Set default state but still set tab data
            updatePageStatus({
                status: 'needs_scan',
                message: 'Click to scan this website',
                icon: '🔍',
                needsScan: true
            }, tab);
        }
    } catch (error) {
        console.error('CatchThePhish: Error checking current page:', error);
    }
}

function updatePageStatus(status, tab = null) {
    const statusElement = document.getElementById('pageStatus');
    const scanButton = document.getElementById('scanPage');
    const threatDetails = document.getElementById('threatDetails');
    
    if (!statusElement) return;
    
    const pageIcon = statusElement.querySelector('.page-icon');
    const pageText = statusElement.querySelector('.page-text');
    
    if (!pageIcon || !pageText || !scanButton) return;
    
    console.log('CatchThePhish: Popup status update:', status);
    
    // Update icon and text
    pageIcon.textContent = status.icon;
    pageText.textContent = status.message;
    
    // Update styling based on status
    switch (status.status) {
        case 'threats_detected':
            statusElement.style.background = '#fff3cd';
            pageText.style.color = '#856404';
            pageText.style.fontWeight = 'bold';
            scanButton.textContent = 'View Threat Details';
            scanButton.style.background = '#ffc107';
            
            // Show threat details if available
            if (status.threats && threatDetails) {
                showThreatDetails(status.threats);
            }
            break;
            
        case 'dangerous':
            statusElement.style.background = '#ffebee';
            pageText.style.color = '#c62828';
            pageText.style.fontWeight = 'bold';
            scanButton.textContent = 'Scan Again';
            scanButton.style.background = '#dc3545';
            break;
            
        case 'safe':
            statusElement.style.background = '#e8f5e8';
            pageText.style.color = '#2e7d32';
            pageText.style.fontWeight = 'normal';
            scanButton.textContent = 'Scan Again';
            scanButton.style.background = '#28a745';
            break;
            
        case 'needs_scan':
        default:
            statusElement.style.background = '#f8f9fa';
            pageText.style.color = '#6c757d';
            pageText.style.fontWeight = 'normal';
            scanButton.textContent = 'Scan This Website';
            scanButton.style.background = '#007bff';
            break;
    }
    
    // Store current tab for scanning
    scanButton.dataset.tabId = tab?.id || '';
    scanButton.dataset.tabUrl = tab?.url || '';
}

function showThreatDetails(threats) {
    const threatDetails = document.getElementById('threatDetails');
    const threatList = document.getElementById('threatList');
    
    if (!threatDetails || !threatList) return;
    
    threatList.innerHTML = '';
    
    threats.forEach(threat => {
        const threatItem = document.createElement('div');
        threatItem.className = 'threat-item';
        threatItem.innerHTML = `
            <div class="threat-url">${threat.url}</div>
            <div class="threat-reason">${threat.threat.reason}</div>
        `;
        threatList.appendChild(threatItem);
    });
    
    threatDetails.style.display = 'block';
}

async function loadSettings() {
    try {
        const result = await chrome.storage.sync.get(['enableProtection']);
        const enableProtectionElement = document.getElementById('enableProtection');
        if (enableProtectionElement) {
            enableProtectionElement.checked = result.enableProtection !== false;
        }
    } catch (error) {
        console.error('CatchThePhish: Error loading settings:', error);
    }
}

function setupEventListeners() {
    // Scan page button - Fixed integration
    const scanButton = document.getElementById('scanPage');
    if (scanButton) {
        console.log('CatchThePhish: Scan button found, adding event listener');
        scanButton.addEventListener('click', async () => {
            console.log('CatchThePhish: Scan button clicked!');
            
            // Get current tab data fresh (don't rely on dataset)
            try {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                
                if (!tab?.url) {
                    console.error('CatchThePhish: No tab URL available');
                    alert('Unable to get current page URL');
                    return;
                }
                
                console.log('CatchThePhish: Scanning tab:', tab.url);
                
                const originalText = scanButton.textContent;
                const originalColor = scanButton.style.background;
                
                // Show scanning state
                scanButton.textContent = 'Scanning...';
                scanButton.disabled = true;
                scanButton.style.background = '#6c757d';
                
                try {
                    console.log('CatchThePhish: Sending scanCurrentPage message');
                    const result = await chrome.runtime.sendMessage({
                        action: 'scanCurrentPage',
                        url: tab.url,
                        tabId: tab.id
                    });
                    
                    console.log('CatchThePhish: Scan result received:', result);
                    
                    // Update the UI based on comprehensive scan results
                    if (result.success !== false) {
                        updateScanResults(result);
                    } else {
                        alert('Scan failed: ' + (result.reason || 'Unknown error'));
                    }
                    
                    // 🆕 Refresh stats after scanning
                    await loadStats();
                    
                    // Refresh page status after scan
                    await checkCurrentPage();
                    
                } catch (error) {
                    console.error('CatchThePhish: Error scanning page:', error);
                    alert(`Scan failed: ${error.message}`);
                } finally {
                    // Always reset button state
                    scanButton.textContent = originalText;
                    scanButton.style.background = originalColor;
                    scanButton.disabled = false;
                }
                
            } catch (tabError) {
                console.error('CatchThePhish: Error getting current tab:', tabError);
                alert('Unable to access current tab');
            }
        });
    } else {
        console.error('CatchThePhish: Scan button not found!');
    }
    
    // Report page button
    const reportButton = document.getElementById('reportPage');
    if (reportButton) {
        reportButton.addEventListener('click', async () => {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (tab?.url) {
                await chrome.runtime.sendMessage({
                    action: 'reportPhishing',
                    url: tab.url
                });
                
                const originalHTML = reportButton.innerHTML;
                reportButton.innerHTML = '<span class="btn-icon">✅</span>Reported!';
                
                setTimeout(() => {
                    reportButton.innerHTML = originalHTML;
                }, 2000);
            }
        });
    }
    
    // Settings toggle
    const enableProtectionElement = document.getElementById('enableProtection');
    if (enableProtectionElement) {
        enableProtectionElement.addEventListener('change', async (e) => {
            await chrome.storage.sync.set({ enableProtection: e.target.checked });
            
            const indicator = document.getElementById('statusIndicator');
            const statusText = document.getElementById('statusText');
            
            if (indicator && statusText) {
                if (e.target.checked) {
                    indicator.classList.add('active');
                    statusText.textContent = 'Protecting You';
                } else {
                    indicator.classList.remove('active');
                    statusText.textContent = 'Disabled';
                }
            }
        });
    }
}

// Add new function to handle comprehensive scan results
function updateScanResults(result) {
    console.log('CatchThePhish: Updating scan results:', result);
    
    // Update stats if available
    if (result.links_scanned !== undefined) {
        const statsText = document.querySelector('.page-text');
        if (statsText && result.scan_summary) {
            // Show scan summary in the status
            statsText.textContent = result.scan_summary;
        }
    }
    
    // Show threat details if suspicious links found
    if (result.suspicious_links_found > 0 && result.suspicious_links) {
        showThreatDetails(result.suspicious_links.map(link => ({
            url: link.url,
            threat: { reason: link.reason }
        })));
    }
}
