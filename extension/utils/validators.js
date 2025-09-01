class InputValidator {
    static isValidURL(input) {
        if (!input || typeof input !== 'string') return false;
        
        try {
            const url = new URL(input.trim());
            // Use allowed protocols from config
            const allowedProtocols = (typeof CONFIG !== 'undefined' && CONFIG?.VALIDATION?.ALLOWED_PROTOCOLS) 
                || ['http:', 'https:'];
            return allowedProtocols.includes(url.protocol);
        } catch {
            return false;
        }
    }
    
    static sanitizeURL(url) {
        if (!this.isValidURL(url)) {
            throw new Error('Invalid URL format');
        }
        
        try {
            const urlObj = new URL(url.trim());
            
            // Remove dangerous parameters using config
            const dangerousParams = (typeof CONFIG !== 'undefined' && CONFIG?.VALIDATION?.DANGEROUS_PARAMS)
                || ['javascript', 'vbscript', 'data', 'file'];
                
            for (const param of dangerousParams) {
                urlObj.searchParams.delete(param);
            }
            
            // Limit URL length using config
            const maxLength = (typeof CONFIG !== 'undefined' && CONFIG?.DETECTION?.MAX_URL_LENGTH) || 2048;
            if (urlObj.href.length > maxLength) {
                throw new Error('URL too long');
            }
            
            return urlObj.href;
        } catch (error) {
            throw new Error(`URL sanitization failed: ${error.message}`);
        }
    }
    
    static sanitizeText(text, maxLength) {
        if (!text || typeof text !== 'string') return '';
        
        // Use config for max length if not provided
        const limit = maxLength || (typeof CONFIG !== 'undefined' && CONFIG?.VALIDATION?.MAX_TEXT_LENGTH) || 500;
        
        return text
            .replace(/<[^>]*>/g, '') // Remove HTML tags
            .replace(/[<>'"&]/g, '') // Remove dangerous characters
            .trim()
            .substring(0, limit);
    }
    
    static isValidMessage(message) {
        if (!message || typeof message !== 'object') return false;
        if (!message.action || typeof message.action !== 'string') return false;
        
        // Use valid actions from config
        const validActions = (typeof CONFIG !== 'undefined' && CONFIG?.VALIDATION?.VALID_ACTIONS)
            || ['checkURL', 'reportPhishing', 'getStats'];
        return validActions.includes(message.action);
    }
}

// Export for different environments
// Service Worker (background script)
if (typeof self !== 'undefined' && typeof window === 'undefined') {
    self.InputValidator = InputValidator;
}
// Content Script (has window object)
else if (typeof window !== 'undefined') {
    window.InputValidator = InputValidator;
}
// Node.js (for testing)
else if (typeof module !== 'undefined' && module.exports) {
    module.exports = InputValidator;
}