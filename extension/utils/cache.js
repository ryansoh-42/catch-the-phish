class URLCache {
    constructor(options = {}) {
        this.cache = new Map();
        this.maxSize = options.maxSize || 100;
        this.ttl = options.ttl || 5 * 60 * 1000; // 5 minutes default
        this.cleanupInterval = options.cleanupInterval || 60 * 1000; // 1 minute
        
        // Start automatic cleanup
        this.startCleanup();
    }
    
    set(key, value) {
        // Clean expired entries before adding new ones
        this.cleanup();
        
        // If at capacity, remove oldest entries
        if (this.cache.size >= this.maxSize) {
            const oldestKeys = Array.from(this.cache.keys()).slice(0, this.cache.size - this.maxSize + 1);
            oldestKeys.forEach(key => this.cache.delete(key));
        }
        
        const entry = {
            value,
            timestamp: Date.now(),
            accessCount: 0,
            lastAccessed: Date.now()
        };
        
        this.cache.set(key.toLowerCase(), entry);
    }
    
    get(key) {
        const entry = this.cache.get(key.toLowerCase());
        
        if (!entry) return null;
        
        // Check if expired
        if (Date.now() - entry.timestamp > this.ttl) {
            this.cache.delete(key.toLowerCase());
            return null;
        }
        
        // Update access statistics
        entry.accessCount++;
        entry.lastAccessed = Date.now();
        
        return entry.value;
    }
    
    has(key) {
        return this.get(key) !== null;
    }
    
    delete(key) {
        return this.cache.delete(key.toLowerCase());
    }
    
    clear() {
        this.cache.clear();
    }
    
    cleanup() {
        const now = Date.now();
        const expiredKeys = [];
        
        for (const [key, entry] of this.cache.entries()) {
            if (now - entry.timestamp > this.ttl) {
                expiredKeys.push(key);
            }
        }
        
        expiredKeys.forEach(key => this.cache.delete(key));
        
        console.log(`CatchThePhish: Cache cleanup removed ${expiredKeys.length} expired entries`);
    }
    
    startCleanup() {
        setInterval(() => {
            this.cleanup();
        }, this.cleanupInterval);
    }
    
    getStats() {
        const entries = Array.from(this.cache.values());
        return {
            size: this.cache.size,
            maxSize: this.maxSize,
            averageAge: entries.length > 0 ? 
                entries.reduce((sum, entry) => sum + (Date.now() - entry.timestamp), 0) / entries.length : 0,
            totalAccesses: entries.reduce((sum, entry) => sum + entry.accessCount, 0)
        };
    }
}

// Export for different environments
// Service Worker (background script)
if (typeof self !== 'undefined' && typeof window === 'undefined') {
    self.URLCache = URLCache;
}
// Content Script (has window object)
else if (typeof window !== 'undefined') {
    window.URLCache = URLCache;
}
// Node.js (for testing)
else if (typeof module !== 'undefined' && module.exports) {
    module.exports = URLCache;
}
