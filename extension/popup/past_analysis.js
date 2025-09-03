async function showPastAnalysisModal() {
    const modal = document.getElementById('pastAnalysisModal');
    if (!modal) return;

    modal.style.display = 'flex';
    
    // Load statistics and history
    await loadPastAnalysisStats();
    await loadPastAnalysisHistory('all');
}

function hidePastAnalysisModal() {
    const modal = document.getElementById('pastAnalysisModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

async function loadPastAnalysisStats() {
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'getScanStatistics'
        });

        if (response && !response.error) {
            // Update statistics display
            document.getElementById('totalDomains').textContent = response.totalDomains || 0;
            document.getElementById('totalScans').textContent = response.totalScans || 0;
            document.getElementById('threatsDetected').textContent = response.suspiciousFound || 0;
            
            // Format storage usage
            const storageUsed = response.storageUsed || 0;
            const storageText = storageUsed > 1024 
                ? `${(storageUsed / 1024).toFixed(1)} KB`
                : `${storageUsed} bytes`;
            document.getElementById('storageUsed').textContent = storageText;
        }

    } catch (error) {
        console.error('CatchThePhish: Error loading past analysis stats:', error);
        // Show error state
        document.getElementById('totalDomains').textContent = 'Error';
        document.getElementById('totalScans').textContent = 'Error';
        document.getElementById('threatsDetected').textContent = 'Error';
        document.getElementById('storageUsed').textContent = 'Error';
    }
}

async function loadPastAnalysisHistory(filter = 'all') {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    // Show loading state
    historyList.innerHTML = '<div class="loading">Loading scan history...</div>';

    try {
        const response = await chrome.runtime.sendMessage({
            action: 'getAllPastScans',
            filter: filter
        });

        if (response && response.success) {
            displayPastAnalysisHistory(response.scans);
        } else {
            historyList.innerHTML = '<div class="no-history">❌ Failed to load scan history</div>';
        }

    } catch (error) {
        console.error('CatchThePhish: Error loading past analysis history:', error);
        historyList.innerHTML = '<div class="no-history">❌ Error loading scan history</div>';
    }
}

function displayPastAnalysisHistory(scans) {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    if (!scans || scans.length === 0) {
        historyList.innerHTML = `
            <div class="no-history">
                <div class="icon">📊</div>
                <p>No scan history found</p>
                <p style="font-size: 12px; margin-top: 5px;">Scan some websites to see your history here!</p>
            </div>
        `;
        return;
    }

    historyList.innerHTML = '';

    scans.forEach(scan => {
        const historyItem = createHistoryItem(scan);
        historyList.appendChild(historyItem);
    });
}

function createHistoryItem(scan) {
    const item = document.createElement('div');
    const isSuspicious = scan.result?.overall_assessment?.is_suspicious || scan.result?.isSuspicious;
    const isStale = !scan.isValid;
    
    item.className = `history-item ${isSuspicious ? 'suspicious' : 'safe'} ${isStale ? 'stale' : ''}`;
    
    // Get main details
    const domain = scan.domain;
    const timeAgo = formatTimeAgo(scan.timestamp);
    const confidence = scan.result?.overall_assessment?.confidence || scan.result?.confidence || 0;
    const scanType = scan.comprehensive ? 'Comprehensive' : 'Basic';
    
    // Get status and reason
    let status, reason;
    if (isSuspicious) {
        status = '⚠️ Suspicious';
        reason = scan.result?.overall_assessment?.primary_concern || 
                scan.result?.reason || 
                'Potential threats detected';
    } else {
        status = '✅ Safe';
        reason = scan.result?.overall_assessment?.primary_concern || 
                scan.result?.scan_summary || 
                'No threats detected';
    }

    item.innerHTML = `
        <div class="history-header">
            <div class="history-domain">${domain}</div>
            <div class="history-time">${timeAgo}</div>
        </div>
        <div class="history-status ${isSuspicious ? 'suspicious' : 'safe'}">
            ${status}
            <span class="history-confidence">
                ${Math.round(confidence * 100)}% confidence
            </span>
        </div>
        <div class="history-details">
            ${reason}
            <br>
            <em style="color: #888; font-size: 11px;">
                ${scanType} scan • ${scan.scanHistory?.length || 0} total scans
                ${isStale ? ' • Data may be outdated' : ''}
            </em>
        </div>
    `;

    // Add click handler to show more details
    item.addEventListener('click', () => {
        showScanDetails(scan);
    });

    return item;
}

function showScanDetails(scan) {
    const modal = document.getElementById('scanDetailModal');
    if (!modal) return;

    // Populate modal content
    populateScanDetailModal(scan);
    
    // Show modal
    modal.style.display = 'flex';
    
    // Setup close handlers
    setupScanDetailModalHandlers();
}

function populateScanDetailModal(scan) {
    const isSuspicious = scan.result?.overall_assessment?.is_suspicious || scan.result?.isSuspicious;
    const result = scan.result;
    
    // Update modal title
    document.getElementById('detailModalTitle').textContent = `📊 Scan Details - ${scan.domain}`;
    
    // Populate overview section
    populateOverviewSection(scan, isSuspicious);
    
    // Populate URL analysis section
    populateUrlAnalysisSection(result?.url_analysis || result);
    
    // Populate text analysis section
    populateTextAnalysisSection(result?.text_analysis);
    
    // Populate scan history section
    populateScanHistorySection(scan.scanHistory || []);
}

function populateOverviewSection(scan, isSuspicious) {
    const overviewContainer = document.getElementById('scanOverview');
    const confidence = scan.result?.overall_assessment?.confidence || scan.result?.confidence || 0;
    const scanType = scan.comprehensive ? 'Comprehensive' : 'Basic';
    
    overviewContainer.innerHTML = `
        <div class="overview-header">
            <div class="overview-domain">${scan.domain}</div>
            <div class="overview-status ${isSuspicious ? 'suspicious' : 'safe'}">
                ${isSuspicious ? '⚠️ Suspicious' : '✅ Safe'}
            </div>
        </div>
        <div class="overview-details">
            <div class="overview-item">
                <span class="overview-label">Scanned:</span>
                <span class="overview-value">${new Date(scan.timestamp).toLocaleString()}</span>
            </div>
            <div class="overview-item">
                <span class="overview-label">Confidence:</span>
                <span class="overview-value">${Math.round(confidence * 100)}%</span>
            </div>
            <div class="overview-item">
                <span class="overview-label">Scan Type:</span>
                <span class="overview-value">${scanType}</span>
            </div>
            <div class="overview-item">
                <span class="overview-label">Total Scans:</span>
                <span class="overview-value">${scan.scanHistory?.length || 1}</span>
            </div>
        </div>
    `;
}

function populateUrlAnalysisSection(urlAnalysis) {
    const urlSection = document.getElementById('urlAnalysisSection');
    const urlContent = document.getElementById('urlAnalysisContent');
    
    if (!urlAnalysis || (!urlAnalysis.isSuspicious && !urlAnalysis.reason)) {
        urlSection.classList.add('hidden');
        return;
    }
    
    urlSection.classList.remove('hidden');
    
    const isSuspicious = urlAnalysis.isSuspicious;
    const confidence = urlAnalysis.confidence || 0;
    const reason = urlAnalysis.reason || 'No specific reason provided';
    
    urlContent.innerHTML = `
        <div class="url-result ${isSuspicious ? 'suspicious' : 'safe'}">
            <div class="url-header">
                <div class="url-status ${isSuspicious ? 'suspicious' : 'safe'}">
                    ${isSuspicious ? '⚠️ Threats Detected' : '✅ No Threats Found'}
                </div>
                <div class="url-confidence">${Math.round(confidence * 100)}% confidence</div>
            </div>
            <div class="url-reason">${reason}</div>
            ${urlAnalysis.links_scanned ? `
                <div class="url-metrics">
                    <div class="metric-item">
                        <div class="metric-value">${urlAnalysis.links_scanned}</div>
                        <div class="metric-label">Links Scanned</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-value">${urlAnalysis.suspicious_links_found || 0}</div>
                        <div class="metric-label">Suspicious Links</div>
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

function populateTextAnalysisSection(textAnalysis) {
    const textSection = document.getElementById('textAnalysisSection');
    const textContent = document.getElementById('textAnalysisContent');
    
    if (!textAnalysis || !textAnalysis.overall_risk) {
        textSection.classList.add('hidden');
        return;
    }
    
    textSection.classList.remove('hidden');
    
    const overallRisk = textAnalysis.overall_risk;
    const suspiciousChunks = textAnalysis.suspicious_chunks || [];
    const totalChunks = textAnalysis.total_chunks_analyzed || 0;
    
    let content = `
        <div class="text-overview">
            <div class="text-summary">
                <span>Overall Risk Assessment:</span>
                <span class="text-risk ${overallRisk}">${overallRisk.toUpperCase()}</span>
            </div>
            <div>Analyzed ${totalChunks} text chunks from the webpage</div>
        </div>
    `;
    
    if (suspiciousChunks.length > 0) {
        content += `
            <div class="suspicious-chunks">
                <h4>Suspicious Content Found:</h4>
        `;
        
        suspiciousChunks.forEach((chunk, index) => {
            const truncatedText = chunk.text?.length > 150 
                ? chunk.text.substring(0, 150) + '...' 
                : chunk.text;
            
            content += `
                <div class="chunk-item">
                    <div class="chunk-text">"${truncatedText}"</div>
                    <div class="chunk-reasons">
                        Detected issues: ${chunk.reasons?.join(', ') || 'Suspicious patterns found'}
                    </div>
                </div>
            `;
        });
        
        content += '</div>';
    } else if (overallRisk === 'safe') {
        content += '<div class="section-empty">No suspicious content detected in webpage text</div>';
    }
    
    textContent.innerHTML = content;
}

function populateScanHistorySection(scanHistory) {
    const historySection = document.getElementById('scanHistorySection');
    const historyContent = document.getElementById('scanHistoryContent');
    
    if (!scanHistory || scanHistory.length === 0) {
        historySection.classList.add('hidden');
        return;
    }
    
    historySection.classList.remove('hidden');
    
    let content = '<div class="history-timeline">';
    
    scanHistory.forEach((historyItem, index) => {
        const isSuspicious = historyItem.is_suspicious;
        const scanDate = new Date(historyItem.timestamp).toLocaleString();
        const confidence = Math.round((historyItem.confidence || 0) * 100);
        
        content += `
            <div class="timeline-item ${isSuspicious ? 'suspicious' : 'safe'}">
                <div class="timeline-dot"></div>
                <div class="timeline-content">
                    <div class="timeline-header">
                        <div class="timeline-date">${scanDate}</div>
                        <div class="timeline-status ${isSuspicious ? 'suspicious' : 'safe'}">
                            ${isSuspicious ? 'Suspicious' : 'Safe'}
                        </div>
                    </div>
                    <div class="timeline-details">
                        ${historyItem.scan_type || 'Basic'} scan • ${confidence}% confidence
                        ${historyItem.risk_level ? ` • ${historyItem.risk_level} risk` : ''}
                    </div>
                </div>
            </div>
        `;
    });
    
    content += '</div>';
    historyContent.innerHTML = content;
}

function setupScanDetailModalHandlers() {
    // Close button handler
    const closeButton = document.getElementById('closeScanDetail');
    if (closeButton) {
        closeButton.onclick = hideScanDetailModal;
    }
    
    // Click outside to close
    const modal = document.getElementById('scanDetailModal');
    if (modal) {
        modal.onclick = (e) => {
            if (e.target === modal) {
                hideScanDetailModal();
            }
        };
    }
}

function hideScanDetailModal() {
    const modal = document.getElementById('scanDetailModal');
    if (modal) {
        modal.style.display = 'none';
    }
}


async function clearScanHistory() {
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'clearScanHistory'
        });

        if (response && response.success) {
            // Reload the statistics and history
            await loadPastAnalysisStats();
            await loadPastAnalysisHistory('all');
            
            // Reset filter to 'all'
            const historyFilter = document.getElementById('historyFilter');
            if (historyFilter) {
                historyFilter.value = 'all';
            }
            
            console.log('CatchThePhish: Scan history cleared successfully');
        } else {
            alert('Failed to clear scan history: ' + (response?.error || 'Unknown error'));
        }

    } catch (error) {
        console.error('CatchThePhish: Error clearing scan history:', error);
        alert('Error clearing scan history: ' + error.message);
    }
}
