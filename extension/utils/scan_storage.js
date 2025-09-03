
class ScanStorageService {
    constructor() {
        this.storageKey = 'catchthephish_scan_results';
        this.maxStorageSize = 5 * 1024 * 1024; // 5MB limit (chrome.storage.local limit is ~10MB)
        this.maxHistoryPerDomain = 3;
        this.dataRetentionDays = 30;
        this.maxAge = 3600000; // 1 hour cache validity
    }

    async saveScanResult(url, scanResult) {
        try {
            const domain = this.extractDomain(url);
            const currentData = await this.getAllScanData();
            
            if (!currentData[domain]) {
                currentData[domain] = {
                    url: url,
                    scanHistory: [],
                    settings: { 
                        autoRescan: false, 
                        scanInterval: 86400000 // 24 hours
                    }
                };
            }

            // Update latest scan
            currentData[domain].lastScan = {
                timestamp: Date.now(),
                comprehensive: scanResult.success !== undefined,
                result: this.compressResult(scanResult)
            };

            // Add to history (keep last N scans)
            const historyEntry = {
                timestamp: Date.now(),
                confidence: scanResult.overall_assessment?.confidence || scanResult.confidence || 0,
                is_suspicious: scanResult.overall_assessment?.is_suspicious || scanResult.isSuspicious || false,
                scan_type: scanResult.success !== undefined ? 'comprehensive' : 'basic',
                risk_level: scanResult.overall_assessment?.risk_level || 'unknown'
            };

            currentData[domain].scanHistory.unshift(historyEntry);
            
            if (currentData[domain].scanHistory.length > this.maxHistoryPerDomain) {
                currentData[domain].scanHistory = currentData[domain].scanHistory.slice(0, this.maxHistoryPerDomain);
            }

            await this.saveAllScanData(currentData);
            console.log('CatchThePhish: Scan result saved for domain:', domain);
            return true;

        } catch (error) {
            console.error('CatchThePhish: Failed to save scan result:', error);
            return false;
        }
    }

    async getLatestScan(url) {
        try {
            const domain = this.extractDomain(url);
            const currentData = await this.getAllScanData();
            const domainData = currentData[domain];
            
            if (!domainData?.lastScan) {
                return null;
            }

            // Check if scan is still valid (not too old)
            const isValid = this.isScanStillValid(domainData.lastScan);
            
            return {
                ...domainData.lastScan,
                isValid: isValid,
                domain: domain,
                scanHistory: domainData.scanHistory || []
            };

        } catch (error) {
            console.error('CatchThePhish: Failed to get latest scan:', error);
            return null;
        }
    }

    async hasFreshScan(url) {
        const latestScan = await this.getLatestScan(url);
        return latestScan && latestScan.isValid;
    }

    async getScanStatistics() {
        try {
            const currentData = await this.getAllScanData();
            const domains = Object.keys(currentData);
            
            let totalScans = 0;
            let suspiciousFound = 0;
            let recentScans = 0;
            const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);

            for (const domain of domains) {
                const domainData = currentData[domain];
                if (domainData.scanHistory) {
                    totalScans += domainData.scanHistory.length;
                    suspiciousFound += domainData.scanHistory.filter(scan => scan.is_suspicious).length;
                    recentScans += domainData.scanHistory.filter(scan => scan.timestamp > oneDayAgo).length;
                }
            }

            return {
                totalDomains: domains.length,
                totalScans: totalScans,
                suspiciousFound: suspiciousFound,
                recentScans: recentScans,
                storageUsed: await this.getStorageUsage()
            };

        } catch (error) {
            console.error('CatchThePhish: Failed to get scan statistics:', error);
            return {
                totalDomains: 0,
                totalScans: 0,
                suspiciousFound: 0,
                recentScans: 0,
                storageUsed: 0
            };
        }
    }

    async cleanup() {
        try {
            const currentData = await this.getAllScanData();
            const cleaned = this.cleanupOldData(currentData);
            await this.saveAllScanData(cleaned);
            
            const beforeSize = Object.keys(currentData).length;
            const afterSize = Object.keys(cleaned).length;
            
            console.log(`CatchThePhish: Cleanup removed ${beforeSize - afterSize} old scan records`);
            return true;

        } catch (error) {
            console.error('CatchThePhish: Failed to cleanup scan data:', error);
            return false;
        }
    }

    async getAllScanData() {
        try {
            const result = await chrome.storage.local.get([this.storageKey]);
            return result[this.storageKey] || {};
        } catch (error) {
            console.error('CatchThePhish: Failed to get scan data from storage:', error);
            return {};
        }
    }

    async saveAllScanData(data) {
        try {
            // Clean old data before saving
            const cleanedData = this.cleanupOldData(data);
            
            // Check storage size before saving
            const estimatedSize = JSON.stringify(cleanedData).length;
            if (estimatedSize > this.maxStorageSize) {
                console.warn('CatchThePhish: Storage size limit approached, performing aggressive cleanup');
                const aggressivelyCleaned = this.aggressiveCleanup(cleanedData);
                await chrome.storage.local.set({ [this.storageKey]: aggressivelyCleaned });
            } else {
                await chrome.storage.local.set({ [this.storageKey]: cleanedData });
            }
            
        } catch (error) {
            console.error('CatchThePhish: Failed to save scan data to storage:', error);
        }
    }

    extractDomain(url) {
        try {
            return new URL(url).hostname.toLowerCase();
        } catch {
            // Fallback for invalid URLs
            return url.toLowerCase().replace(/[^a-z0-9.-]/g, '');
        }
    }

    isScanStillValid(scanData, maxAge = this.maxAge) {
        if (!scanData || !scanData.timestamp) {
            return false;
        }
        return (Date.now() - scanData.timestamp) < maxAge;
    }

    cleanupOldData(data) {
        const cutoffTime = Date.now() - (this.dataRetentionDays * 24 * 60 * 60 * 1000);
        const cleaned = {};

        for (const [domain, domainData] of Object.entries(data)) {
            // Keep domain if it has a recent scan
            if (domainData.lastScan?.timestamp > cutoffTime) {
                cleaned[domain] = {
                    ...domainData,
                    // Also clean old entries from scan history
                    scanHistory: domainData.scanHistory?.filter(scan => 
                        scan.timestamp > cutoffTime
                    ) || []
                };
            }
        }

        return cleaned;
    }

    aggressiveCleanup(data) {
        const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        const cleaned = {};

        // Only keep data from the last week
        for (const [domain, domainData] of Object.entries(data)) {
            if (domainData.lastScan?.timestamp > oneWeekAgo) {
                cleaned[domain] = {
                    ...domainData,
                    // Keep only the most recent scan in history
                    scanHistory: domainData.scanHistory?.slice(0, 1) || []
                };
            }
        }

        return cleaned;
    }

    compressResult(result) {
        // Keep only essential data for storage
        return {
            success: result.success,
            overall_assessment: result.overall_assessment,
            scan_summary: result.scan_summary,
            url_analysis: {
                isSuspicious: result.url_analysis?.isSuspicious,
                confidence: result.url_analysis?.confidence,
                reason: result.url_analysis?.reason,
                links_scanned: result.url_analysis?.links_scanned,
                suspicious_links_found: result.url_analysis?.suspicious_links_found
            },
            text_analysis: {
                overall_risk: result.text_analysis?.overall_risk,
                suspicious_chunks: result.text_analysis?.suspicious_chunks?.slice(0, 3), // Keep only first 3
                total_chunks_analyzed: result.text_analysis?.total_chunks_analyzed
            },
            timestamp: result.timestamp
        };
    }

    async getStorageUsage() {
        try {
            const bytesInUse = await chrome.storage.local.getBytesInUse([this.storageKey]);
            return bytesInUse;
        } catch (error) {
            console.error('CatchThePhish: Failed to get storage usage:', error);
            return 0;
        }
    }

    async getAllPastScans(filter = 'all') {
        try {
            const currentData = await this.getAllScanData();
            const allScans = [];
            const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);

            for (const [domain, domainData] of Object.entries(currentData)) {
                if (domainData.lastScan) {
                    const scan = {
                        domain: domain,
                        url: domainData.url,
                        timestamp: domainData.lastScan.timestamp,
                        comprehensive: domainData.lastScan.comprehensive,
                        result: domainData.lastScan.result,
                        scanHistory: domainData.scanHistory || [],
                        isValid: this.isScanStillValid(domainData.lastScan)
                    };

                    // Apply filters
                    switch (filter) {
                        case 'suspicious':
                            if (scan.result?.overall_assessment?.is_suspicious || scan.result?.isSuspicious) {
                                allScans.push(scan);
                            }
                            break;
                        case 'safe':
                            if (!(scan.result?.overall_assessment?.is_suspicious || scan.result?.isSuspicious)) {
                                allScans.push(scan);
                            }
                            break;
                        case 'recent':
                            if (scan.timestamp > oneDayAgo) {
                                allScans.push(scan);
                            }
                            break;
                        case 'all':
                        default:
                            allScans.push(scan);
                            break;
                    }
                }
            }

            // Sort by timestamp (most recent first)
            allScans.sort((a, b) => b.timestamp - a.timestamp);

            return allScans;

        } catch (error) {
            console.error('CatchThePhish: Failed to get past scans:', error);
            return [];
        }
    }

    async clearAllData() {
        try {
            await chrome.storage.local.remove([this.storageKey]);
            console.log('CatchThePhish: All scan data cleared');
            return true;
        } catch (error) {
            console.error('CatchThePhish: Failed to clear scan data:', error);
            return false;
        }
    }
}

// Export for different environments
// Service Worker (background script)
if (typeof self !== 'undefined' && typeof window === 'undefined') {
    self.ScanStorageService = ScanStorageService;
}
// Content Script (has window object)
else if (typeof window !== 'undefined') {
    window.ScanStorageService = ScanStorageService;
}
// Node.js (for testing)
else if (typeof module !== 'undefined' && module.exports) {
    module.exports = ScanStorageService;
}
