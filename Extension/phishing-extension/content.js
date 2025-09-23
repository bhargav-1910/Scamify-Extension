// ScamiFy Content Script - Ultra Simple Version
console.log("🚀 SCAMIFY: CONTENT SCRIPT LOADED - CHECK CONSOLE!");

// Force immediate test
console.log("🧪 SCAMIFY: Creating immediate test tooltip...");
createTestTooltip();

// Try again after DOM is ready
setTimeout(() => {
    console.log("🧪 SCAMIFY: Creating delayed test tooltip...");
    createTestTooltip();
}, 1000);

// Global variables
let currentTooltip = null;
let hoverTimeout = null;

// Check URL safety using backend API with caching
async function checkUrlSafety(url) {
    try {
        // Check cache first
        const cacheKey = url;
        const cachedResult = urlCache.get(cacheKey);
        if (cachedResult && Date.now() - cachedResult.timestamp < CACHE_DURATION) {
            console.log('📋 Using cached result for:', url, '→', cachedResult.result.prediction);
            return cachedResult.result;
        }
        
        console.log('🌐 Making API call for:', url);
        const response = await fetch('http://127.0.0.1:5000/predict_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('📊 Backend result for', url, '→', result.prediction, `(${Math.round(result.probability * 100)}%)`);
        
        // Cache the result
        urlCache.set(cacheKey, {
            result: {
                prediction: result.prediction,
                probability: result.probability
            },
            timestamp: Date.now()
        });
        
        return {
            prediction: result.prediction,
            probability: result.probability
        };
    } catch (error) {
        console.error('❌ Error checking URL safety for', url, ':', error.message);
        
        // Check cache for any previous result, even expired
        const cacheKey = url;
        const cachedResult = urlCache.get(cacheKey);
        if (cachedResult) {
            console.log('📋 Using expired cached result due to error:', url, '→', cachedResult.result.prediction);
            return cachedResult.result;
        }
        
        // Fallback to local analysis if backend is unavailable
        console.log('🔄 Using local analysis fallback for:', url);
        const localResult = getLocalUrlAnalysis(url);
        console.log('🔄 Local analysis result:', localResult.prediction, `(${Math.round(localResult.probability * 100)}%)`);
        return localResult;
    }
}

// Fallback local URL analysis when backend is unavailable
function getLocalUrlAnalysis(url) {
    try {
        let suspiciousScore = 0;
        const urlLower = url.toLowerCase();
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        
        // Conservative suspicious patterns - only flag obvious phishing indicators
        const suspiciousPatterns = [
            { pattern: /bit\.ly|goo\.gl|tinyurl\.com|t\.co/, weight: 0.4 },
            { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, weight: 0.3 },
            { pattern: /(secure|verify|update|login).*[0-9]{6,}/, weight: 0.6 }, // Specific suspicious combinations
            { pattern: /[a-zA-Z0-9]{35,}/, weight: 0.3 }, // Very long random strings
            { pattern: /phishing|malware|virus|scam/, weight: 0.8 }
        ];
        
        suspiciousPatterns.forEach(({ pattern, weight }) => {
            if (pattern.test(urlLower)) {
                suspiciousScore += weight;
            }
        });
        
        // Lenient scoring for URL characteristics
        if (url.length > 200) suspiciousScore += 0.2;
        if (url.length > 400) suspiciousScore += 0.3;
        
        // Don't penalize non-HTTPS unless other factors present
        if (!url.startsWith('https://') && suspiciousScore > 0.4) {
            suspiciousScore += 0.2;
        }
        
        // Normalize score - most URLs should be safe
        const probability = Math.min(suspiciousScore / 3.0, 1.0);
        
        let prediction = 'Safe';
        if (probability > 0.7) {
            prediction = 'Phishing';
        } else if (probability > 0.5) {
            prediction = 'Suspicious';
        }
        
        return { prediction, probability };
    } catch (error) {
        console.error('Error in local URL analysis:', error);
        return { prediction: 'Safe', probability: 0.2 }; // Default to safe with low confidence
    }
}

// Simple initialization
function initializeContentScript() {
    console.log('🚀 ScamiFy: Initializing...');
    
    // Always enable for testing
    isExtensionEnabled = true;
    isHoverDetectionEnabled = true;
    
    // Set up event listeners immediately
    setupEventListeners();
    
    console.log('✅ ScamiFy: Initialization complete');
    
    // Listen for settings changes
    chrome.storage.onChanged.addListener(function(changes, namespace) {
        if (namespace === 'local') {
            if (changes.extension_enabled) {
                isExtensionEnabled = changes.extension_enabled.newValue;
                console.log('🔄 Extension state changed to:', isExtensionEnabled);
                if (!isExtensionEnabled) {
                    hideTooltip();
                    clearTimeouts();
                }
            }
            if (changes.hover_detection) {
                isHoverDetectionEnabled = changes.hover_detection.newValue;
                console.log('🔄 Hover Detection changed to:', isHoverDetectionEnabled);
                if (isHoverDetectionEnabled && isExtensionEnabled) {
                    setupEventListeners();
                } else {
                    hideTooltip();
                }
            }
        }
    });
}

// Add safety CSS to prevent conflicts with page layout
function addSafetyCSS() {
    // Only add once
    if (document.getElementById('scamify-safety-styles')) {
        return;
    }
    
    const style = document.createElement('style');
    style.id = 'scamify-safety-styles';
    style.textContent = `
        /* ScamiFy Safety Styles - Prevent conflicts */
        .scamify-tooltip {
            all: initial !important;
            position: fixed !important;
            z-index: 2147483647 !important;
            pointer-events: auto !important;
            box-sizing: border-box !important;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        }
        
        /* Prevent any interference with page layout */
        body:not(.scamify-tooltip) {
            /* Don't modify body styles */
        }
        
        /* Ensure tooltips don't affect page flow */
        .scamify-tooltip * {
            box-sizing: border-box !important;
            margin: 0 !important;
            padding: 0 !important;
        }
    `;
    
    try {
        document.head.appendChild(style);
        console.log('🎨 ScamiFy safety styles added');
    } catch (e) {
        console.error('❌ Failed to add safety styles:', e);
    }
    
    // Clean up URL cache periodically
    setInterval(cleanupCache, 10 * 60 * 1000); // Every 10 minutes
}

// Ultra simple test tooltip
function createTestTooltip() {
    console.log("🧪 SCAMIFY: Attempting to create test tooltip...");
    
    try {
        // Remove any existing test tooltip
        const existing = document.getElementById('scamify-test');
        if (existing) {
            existing.remove();
        }
        
        if (!document.body) {
            console.log("❌ SCAMIFY: document.body not available yet");
            return;
        }
        
        const tooltip = document.createElement('div');
        tooltip.id = 'scamify-test';
        tooltip.innerHTML = 'SCAMIFY WORKING!';
        
        // Ultra simple styling
        tooltip.style.position = 'fixed';
        tooltip.style.top = '10px';
        tooltip.style.right = '10px';
        tooltip.style.background = 'red';
        tooltip.style.color = 'white';
        tooltip.style.padding = '10px';
        tooltip.style.zIndex = '999999999';
        tooltip.style.fontSize = '14px';
        tooltip.style.fontFamily = 'Arial';
        tooltip.style.border = '2px solid yellow';
        
        document.body.appendChild(tooltip);
        console.log("✅ SCAMIFY: Test tooltip created and added to DOM");
        
        // Remove after 5 seconds
        setTimeout(() => {
            if (tooltip.parentNode) {
                tooltip.remove();
                console.log("🧹 SCAMIFY: Test tooltip removed");
            }
        }, 5000);
        
    } catch (error) {
        console.error("❌ SCAMIFY: Test tooltip failed:", error);
    }
}

// Clean up expired cache entries
function cleanupCache() {
    const now = Date.now();
    for (const [key, value] of urlCache.entries()) {
        if (now - value.timestamp > CACHE_DURATION) {
            urlCache.delete(key);
        }
    }
    console.log(`🧹 Cache cleanup completed. ${urlCache.size} entries remaining.`);
}

// Ultra simple setup
function setupListeners() {
    console.log('🔧 SCAMIFY: Setting up event listeners...');
    
    // Remove existing
    document.removeEventListener('mouseover', handleHover);
    document.removeEventListener('mouseout', handleLeave);
    
    // Add new
    document.addEventListener('mouseover', handleHover);
    document.addEventListener('mouseout', handleLeave);
    
    console.log('✅ SCAMIFY: Event listeners added');
}

// Disconnect MutationObserver
function disconnectObserver() {
    if (observer) {
        observer.disconnect();
        console.log('MutationObserver disconnected.');
        observer = null;
    }
}

// Ultra simple hover handler
function handleHover(event) {
    const target = event.target;
    
    // Only handle A tags with href
    if (target.tagName === 'A' && target.href && target.href !== '#') {
        console.log('🔍 SCAMIFY: Hovering over link:', target.href);
        
        // Clear existing timeout
        if (hoverTimeout) {
            clearTimeout(hoverTimeout);
        }
        
        // Show tooltip after short delay
        hoverTimeout = setTimeout(() => {
            showTooltip(target.href, event);
        }, 500);
    }
}

// Ultra simple mouse leave
function handleLeave(event) {
    if (hoverTimeout) {
        clearTimeout(hoverTimeout);
        hoverTimeout = null;
    }
    
    // Hide tooltip after delay
    setTimeout(() => {
        hideTooltip();
    }, 200);
}

// Check if element is link-like
function isLinkLikeElement(element) {
    // Direct link elements
    if (element.tagName === 'A') {
        return true;
    }
    
    // Elements with click handlers that might be links
    if (element.onclick || element.getAttribute('onclick')) {
        return true;
    }
    
    // Elements with data attributes suggesting they're links
    const linkDataAttrs = ['data-url', 'data-href', 'data-link', 'data-target'];
    for (const attr of linkDataAttrs) {
        if (element.hasAttribute(attr)) {
            return true;
        }
    }
    
    // Elements that look clickable (have cursor pointer)
    try {
        const computedStyle = window.getComputedStyle(element);
        if (computedStyle.cursor === 'pointer') {
            return true;
        }
    } catch (e) {
        // Ignore style computation errors
    }
    
    // Check if parent is a link (up to 2 levels)
    let parent = element.parentElement;
    let depth = 0;
    while (parent && depth < 2) {
        if (parent.tagName === 'A') {
            return true;
        }
        parent = parent.parentElement;
        depth++;
    }
    
    return false;
}

// Clear all active timeouts
function clearAllTimeouts() {
    if (hoverTimeout) {
        clearTimeout(hoverTimeout);
        hoverTimeout = null;
    }
    if (hideTimeout) {
        clearTimeout(hideTimeout);
        hideTimeout = null;
    }
}

// Basic URL validation - permissive for testing
function isValidUrl(string) {
    try {
        if (!string || typeof string !== 'string') return false;
        
        const ignorePatterns = [
            'chrome-extension://', 'moz-extension://', 'safari-extension://',
            'chrome://', 'about:', 'data:', 'blob:', 'javascript:', 'mailto:', 'tel:', 'file:'
        ];
        
        // Check if URL should be ignored
        for (const pattern of ignorePatterns) {
            if (string.startsWith(pattern)) {
                return false;
            }
        }
        
        // Skip fragments
        if (string === '#' || string.startsWith('#')) {
            return false;
        }
        
        // Try to create URL object to validate
        const url = new URL(string);
        
        // Only allow HTTP/HTTPS URLs
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

// Simple mouse leave handler
function handleMouseLeave(event) {
    clearTimeouts();
    lastHoveredElement = null;
    
    // Hide tooltip after short delay
    hideTimeout = setTimeout(() => {
        hideTooltip();
    }, 200);
}

// Extract URL from element
function extractUrlFromElement(element) {
    if (!element) return null;
    
    // Priority 1: Direct href attribute
    if (element.tagName === 'A' && element.href) {
        return element.href;
    }
    
    // Priority 2: Form actions
    if (element.tagName === 'FORM' && element.action) {
        return element.action;
    }
    
    // Priority 3: Data attributes
    const navigationDataAttrs = ['data-url', 'data-href', 'data-link', 'data-target'];
    for (const attr of navigationDataAttrs) {
        const value = element.getAttribute(attr);
        if (value) {
            return value;
        }
    }
    
    // Priority 4: Parent link
    const parent = element.parentElement;
    if (parent && parent.tagName === 'A' && parent.href) {
        return parent.href;
    }
    
    // Priority 5: Platform-specific
    const platformUrl = extractPlatformSpecificUrl(element);
    if (platformUrl) {
        return platformUrl;
    }
    
    return null;
}

// Targeted platform-specific URL extraction focusing on external/risky links
function extractPlatformSpecificUrl(element) {
    const hostname = window.location.hostname.toLowerCase();
    
    // Google Search Results - highest priority for phishing detection
    if (hostname.includes('google.com')) {
        // Search result direct links
        if (element.dataset.href && !element.dataset.href.includes('google.com')) {
            return element.dataset.href;
        }
        
        // Extract from ping URL (Google's click tracking)
        if (element.ping) {
            const match = element.ping.match(/url=([^&]+)/);
            if (match) {
                try {
                    const decodedUrl = decodeURIComponent(match[1]);
                    // Only return if it's not a Google internal URL
                    if (!decodedUrl.includes('google.com') && !decodedUrl.includes('googleapis.com')) {
                        return decodedUrl;
                    }
                } catch (e) {
                    return null;
                }
            }
        }
    }
    
    // Social Media - focus on external links that could be phishing
    if (hostname.includes('facebook.com')) {
        if (element.dataset.lynxUri) {
            try {
                const url = new URL(element.dataset.lynxUri);
                if (url.searchParams.has('u')) {
                    const externalUrl = decodeURIComponent(url.searchParams.get('u'));
                    // Only analyze external URLs, not Facebook internal
                    if (!externalUrl.includes('facebook.com') && !externalUrl.includes('fbcdn.net')) {
                        return externalUrl;
                    }
                }
            } catch (e) {
                return null;
            }
        }
    }
    
    // Twitter/X external links
    if (hostname.includes('twitter.com') || hostname.includes('x.com')) {
        if (element.dataset.expandedUrl) {
            const url = element.dataset.expandedUrl;
            // Only analyze external URLs
            if (!url.includes('twitter.com') && !url.includes('x.com') && !url.includes('t.co')) {
                return url;
            }
        }
    }
    
    // LinkedIn external links
    if (hostname.includes('linkedin.com')) {
        if (element.dataset.trackingUrl) {
            const url = element.dataset.trackingUrl;
            // Only analyze external URLs
            if (!url.includes('linkedin.com') && !url.includes('licdn.com')) {
                return url;
            }
        }
    }
    
    // Reddit external links
    if (hostname.includes('reddit.com')) {
        if (element.dataset.url) {
            const url = element.dataset.url;
            // Only analyze external URLs
            if (!url.includes('reddit.com') && !url.includes('redd.it')) {
                return url;
            }
        }
    }
    
    return null;
}

// Ultra simple tooltip
function showTooltip(url, event) {
    console.log('🎯 SCAMIFY: Creating tooltip for:', url);
    
    // Remove existing
    hideTooltip();
    
    // Create tooltip
    currentTooltip = document.createElement('div');
    currentTooltip.innerHTML = 'SCAMIFY: ' + url;
    
    // Simple styling
    currentTooltip.style.position = 'fixed';
    currentTooltip.style.background = 'black';
    currentTooltip.style.color = 'white';
    currentTooltip.style.padding = '8px';
    currentTooltip.style.zIndex = '999999999';
    currentTooltip.style.fontSize = '12px';
    currentTooltip.style.maxWidth = '300px';
    currentTooltip.style.border = '1px solid white';
    
    // Position
    const x = event.clientX || 100;
    const y = event.clientY || 100;
    currentTooltip.style.left = (x + 10) + 'px';
    currentTooltip.style.top = (y + 10) + 'px';
    
    // Add to page
    try {
        document.body.appendChild(currentTooltip);
        console.log('✅ SCAMIFY: Tooltip created and added');
    } catch (error) {
        console.error('❌ SCAMIFY: Tooltip failed:', error);
    }
}

// Hide tooltip
function hideTooltip() {
    if (currentTooltip) {
        try {
            currentTooltip.remove();
            console.log('🧹 SCAMIFY: Tooltip removed');
        } catch (e) {
            console.error('❌ SCAMIFY: Error removing tooltip:', e);
        }
        currentTooltip = null;
    }
}

// Position tooltip
function positionTooltip(tooltip, event) {
    const rect = tooltip.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    
    let left = event.clientX + 10;
    let top = event.clientY - rect.height - 10;
    
    // Adjust if tooltip goes off screen
    if (left + rect.width > viewportWidth) {
        left = event.clientX - rect.width - 10;
    }
    
    if (top < 0) {
        top = event.clientY + 20;
    }
    
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
    console.log(`Tooltip positioned at Left: ${left}px, Top: ${top}px. Rect: ${JSON.stringify(rect)}`);
}

// Truncate URL for display
function truncateUrl(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const path = urlObj.pathname;
        
        const domainLength = domain.length;
        const remainingLength = maxLength - domainLength - 3; // 3 for "..."
        
        if (remainingLength > 0 && path.length > remainingLength) {
            return `${domain}${path.substring(0, remainingLength)}...`;
        }
        
        return url.substring(0, maxLength - 3) + '...';
    } catch (e) {
        return url.substring(0, maxLength - 3) + '...';
    }
}

// Update tooltip with analysis result
function updateTooltipWithResult(tooltip, result) {
    const prediction = result.prediction.toLowerCase();
    const probability = Math.round(result.probability * 100);
    
    let statusIcon = '✅';
    let statusText = 'Safe';
    let statusColor = '#22c55e';
    let borderColor = '#22c55e';
    let warningText = 'This link appears to be legitimate.';
    
    if (prediction === 'suspicious') {
        statusIcon = '⚠️';
        statusText = 'Suspicious';
        statusColor = '#f59e0b';
        borderColor = '#f59e0b';
        warningText = 'Exercise caution when visiting this link.';
    } else if (prediction === 'phishing') {
        statusIcon = '🚨';
        statusText = 'Phishing Detected!';
        statusColor = '#ef4444';
        borderColor = '#ef4444';
        warningText = 'This link may be dangerous. Avoid clicking.';
    }
    
    // Update border color
    tooltip.style.borderColor = borderColor;
    
    tooltip.innerHTML = `
        <div style="margin-bottom: 10px;">
            <div style="font-weight: 700; font-size: 16px; color: ${statusColor}; margin-bottom: 4px;">
                ${statusIcon} ${statusText}
            </div>
            <div style="font-size: 12px; color: #e5e7eb; margin-bottom: 6px; word-break: break-all;">
                🔗 ${truncateUrl(tooltip.dataset.url || 'Unknown URL', 40)}
            </div>
            <div style="font-size: 13px; color: #d1d5db;">
                ${warningText}
            </div>
        </div>
        <div style="font-size: 12px; color: #9ca3af; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 8px;">
            Confidence: ${probability}% • ANN Model Analysis
        </div>
    `;
}

// Update tooltip status
function updateTooltipStatus(tooltip, message, type = 'info') {
    const statusElement = tooltip.querySelector('.tooltip-status');
    statusElement.className = `tooltip-status ${type}`;
    statusElement.textContent = message;
}

// Removed flagUrl function

// Removed renderFlagState function

// Removed unflagUrl function

// Handle link clicks - DISABLED to prevent random warnings
async function handleLinkClick(event) {
    // Temporarily disable click interception to prevent random warnings
    return;
    
    if (!isExtensionEnabled) return;
    
    const url = safeExtractUrlFromEvent(event);
    
    if (url) {
        await checkUrlSafetyForNavigation(url, event);
    }
}

// Check URL safety before navigation
async function checkUrlSafetyForNavigation(url, event) {
    try {
        const result = await checkUrlSafety(url);
        
        if (result.prediction.toLowerCase() === 'phishing') {
            event.preventDefault();
            showPhishingWarning(url, result);
        }
    } catch (error) {
        console.error('Error checking URL safety for navigation:', error);
        // Don't block navigation if there's an error
    }
}

// Show phishing warning
function showPhishingWarning(url, result) {
    const warning = document.createElement('div');
    warning.className = 'phishing-warning';
    warning.innerHTML = `
        <div class="warning-header">
            <span class="warning-icon">🚨</span>
            <span class="warning-title">Phishing Warning!</span>
        </div>
        <div class="warning-content">
            <p>This URL has been flagged as potentially dangerous:</p>
            <p class="warning-url">${url}</p>
            <p>Confidence: ${Math.round(result.probability * 100)}%</p>
        </div>
        <div class="warning-actions">
            <button class="btn-safe" onclick="this.parentElement.parentElement.remove()">Stay Safe</button>
            <button class="btn-proceed" onclick="proceedToUrl('${url}')">Proceed Anyway</button>
        </div>
    `;
    
    document.body.appendChild(warning);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
        if (warning.parentElement) {
            warning.remove();
        }
    }, 10000);
}

// Proceed to URL (user choice)
function proceedToUrl(url) {
    window.location.href = url;
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `phishing-notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'scanPage') {
        // Scan current page for suspicious links
        scanCurrentPage().then(result => {
            sendResponse({ success: true, result: result });
        }).catch(error => {
            console.error('Error scanning page:', error);
            sendResponse({ success: false, error: error.message });
        });
        return true; // Indicates asynchronous response
    }
});

// Scan current page for suspicious links
async function scanCurrentPage() {
    const links = document.querySelectorAll('a[href], [data-url], [data-href]');
    let suspiciousCount = 0;
    let totalCount = 0;
    
    const promises = Array.from(links).slice(0, 10).map(async (link) => {
        const url = extractUrlFromElement(link);
        if (url && url.startsWith('http')) {
            totalCount++;
            try {
                const result = await checkUrlSafety(url);
                if (result.prediction === 'Phishing' || result.prediction === 'Suspicious') {
                    suspiciousCount++;
                }
            } catch (error) {
                console.error('Error checking link:', url, error);
            }
        }
    });
    
    await Promise.all(promises);
    
    return {
        totalLinks: totalCount,
        suspiciousLinks: suspiciousCount,
        prediction: suspiciousCount > 0 ? 'Suspicious' : 'Safe',
        probability: suspiciousCount / Math.max(totalCount, 1)
    };
}

// Listen for runtime messages to update state across tabs
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
	if (request.action === 'updateExtensionState') {
		isExtensionEnabled = !!request.extensionEnabled;
		isHoverDetectionEnabled = !!request.hoverDetectionEnabled;
		if (isHoverDetectionEnabled) { 
			setupEventListeners(); 
		} else { 
			hideTooltip(); 
		}
	}
	if (request.action === 'toggleExtension') {
		isExtensionEnabled = !!request.enabled;
		if (!isExtensionEnabled) { 
			hideTooltip(); 
		} else { 
			setupEventListeners(); 
		}
	}
	if (request.action === 'toggleHoverDetection') {
		isHoverDetectionEnabled = !!request.enabled;
		if (isHoverDetectionEnabled) { 
			setupEventListeners(); 
		} else { 
			hideTooltip(); 
		}
	}
});

// Conservative URL extraction from event target
function safeExtractUrlFromEvent(event) {
    try {
        const target = event.target;
        
        // Only check direct target and immediate parent to avoid false positives
        let url = extractUrlFromElement(target);
        if (url && isValidUrl(url)) {
            return url;
        }
        
        // Check only immediate parent (reduced from 3 levels to 1)
        const parent = target.parentElement;
        if (parent) {
            url = extractUrlFromElement(parent);
            if (url && isValidUrl(url)) {
                return url;
            }
        }
        
        return null;
    } catch (e) {
        console.error('safeExtractUrlFromEvent: Error extracting URL:', e);
        return null;
    }
}

// Initialize when DOM is ready
console.log('🚀 ScamiFy content script loaded');

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeContentScript);
} else {
    initializeContentScript();
} 