// ScamiFy - Ultra Simple Content Script
console.log('🚀 SCAMIFY: Loading content script...');

let tooltip = null;
let urlCache = new Map();

// Check URL safety using backend
async function checkUrlSafety(url) {
    try {
        // Check cache first
        if (urlCache.has(url)) {
            console.log('💾 SCAMIFY: Using cached result for:', url);
            return urlCache.get(url);
        }

        console.log('🔍 SCAMIFY: Checking URL with backend:', url);
        
        const response = await fetch('http://127.0.0.1:5000/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }

        const result = await response.json();
        console.log('📊 SCAMIFY: Backend result:', result);
        
        // Cache the result
        urlCache.set(url, result);
        
        return result;
    } catch (error) {
        console.error('❌ SCAMIFY: Error checking URL:', error);
        // Return default safe result if backend fails
        return {
            prediction: 'safe',
            probability: 0.5
        };
    }
}

// Create test tooltip
function createTestTooltip() {
    console.log('🧪 SCAMIFY: Creating test tooltip...');
    
    // Remove existing test tooltip
    const existing = document.getElementById('scamify-test-tooltip');
    if (existing) {
        existing.remove();
    }
    
    // Create test element
    const testTooltip = document.createElement('div');
    testTooltip.id = 'scamify-test-tooltip';
    testTooltip.textContent = 'TEST TOOLTIP WORKING!';
    testTooltip.style.cssText = `
        position: fixed;
        top: 50px;
        right: 50px;
        background: red !important;
        color: white !important;
        padding: 10px !important;
        border: 3px solid yellow !important;
        font-size: 16px !important;
        z-index: 999999 !important;
        pointer-events: none !important;
    `;
    
    document.body.appendChild(testTooltip);
    
    console.log('✅ SCAMIFY: Test tooltip created');
    
    // Remove after 5 seconds
    setTimeout(() => {
        if (testTooltip.parentNode) {
            testTooltip.remove();
            console.log('🗑️ SCAMIFY: Test tooltip removed');
        }
    }, 5000);
}

// Extract URL from element or its parents
function extractUrlFromElement(element) {
    // Check direct href
    if (element.href) {
        return element.href;
    }
    
    // Check data attributes
    if (element.dataset) {
        if (element.dataset.url) return element.dataset.url;
        if (element.dataset.href) return element.dataset.href;
        if (element.dataset.link) return element.dataset.link;
    }
    
    // Check common URL attributes
    const urlAttrs = ['data-url', 'data-href', 'data-link', 'href', 'src'];
    for (const attr of urlAttrs) {
        const value = element.getAttribute(attr);
        if (value && (value.startsWith('http') || value.startsWith('//'))) {
            return value.startsWith('//') ? 'https:' + value : value;
        }
    }
    
    // Check text content for URLs
    const text = element.textContent || element.innerText || '';
    const urlMatch = text.match(/(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/i);
    if (urlMatch) {
        return urlMatch[1];
    }
    
    return null;
}

// Handle hover on any element with URL
function handleHover(event) {
    const target = event.target;
    let url = extractUrlFromElement(target);
    
    // If no URL found on target, check parent elements
    if (!url) {
        let parent = target.parentElement;
        let depth = 0;
        while (parent && depth < 3) { // Check up to 3 levels up
            url = extractUrlFromElement(parent);
            if (url) break;
            parent = parent.parentElement;
            depth++;
        }
    }
    
    if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
        console.log('🎯 SCAMIFY: Hovering over URL:', url);
        showTooltipWithAnalysis(event, url);
    }
}

// Handle mouse leave
function handleLeave(event) {
    // Always hide tooltip when mouse leaves any element
    hideTooltip();
}

// Show tooltip with phishing analysis
async function showTooltipWithAnalysis(event, url) {
    console.log('💬 SCAMIFY: Showing tooltip with analysis for:', url);
    
    // Remove existing
    hideTooltip();
    
    // Create new tooltip
    tooltip = document.createElement('div');
    tooltip.id = 'scamify-tooltip';
    
    // Calculate position to avoid going off screen
    const x = Math.min(event.clientX + 10, window.innerWidth - 350);
    const y = Math.min(event.clientY + 10, window.innerHeight - 80);
    
    // Initial tooltip with loading state
    tooltip.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 4px;">🔍 ScamiFy Analysis</div>
        <div style="font-size: 11px; color: #ccc; margin-bottom: 8px;">${url}</div>
        <div style="color: #ffa500;">⏳ Analyzing...</div>
    `;
    
    tooltip.style.cssText = `
        position: fixed !important;
        background: #2a2a2a !important;
        color: white !important;
        padding: 12px !important;
        border-radius: 8px !important;
        font-size: 12px !important;
        font-family: Arial, sans-serif !important;
        max-width: 320px !important;
        word-wrap: break-word !important;
        z-index: 2147483647 !important;
        pointer-events: none !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.4) !important;
        border: 1px solid #555 !important;
        top: ${y}px !important;
        left: ${x}px !important;
        display: block !important;
        visibility: visible !important;
        line-height: 1.4 !important;
    `;
    
    document.body.appendChild(tooltip);
    console.log('✅ SCAMIFY: Initial tooltip displayed');
    
    // Get analysis result
    try {
        const result = await checkUrlSafety(url);
        
        // Update tooltip with results
        if (tooltip && tooltip.parentNode) {
            const prediction = result.prediction || 'safe';
            const probability = Math.round((result.probability || 0) * 100);
            
            let statusColor, statusIcon, statusText;
            
            if (prediction === 'malicious' || prediction === 'phishing') {
                statusColor = '#ff4444';
                statusIcon = '🚨';
                statusText = 'PHISHING';
            } else if (prediction === 'suspicious') {
                statusColor = '#ffa500';
                statusIcon = '⚠️';
                statusText = 'SUSPICIOUS';
            } else {
                statusColor = '#44ff44';
                statusIcon = '✅';
                statusText = 'SAFE';
            }
            
            tooltip.innerHTML = `
                <div style="font-weight: bold; margin-bottom: 4px;">🔍 ScamiFy Analysis</div>
                <div style="font-size: 11px; color: #ccc; margin-bottom: 8px;">${url}</div>
                <div style="color: ${statusColor}; font-weight: bold;">
                    ${statusIcon} ${statusText} (${probability}%)
                </div>
            `;
            
            console.log('✅ SCAMIFY: Tooltip updated with analysis result:', statusText);
        }
    } catch (error) {
        console.error('❌ SCAMIFY: Error updating tooltip:', error);
        if (tooltip && tooltip.parentNode) {
            tooltip.innerHTML = `
                <div style="font-weight: bold; margin-bottom: 4px;">🔍 ScamiFy Analysis</div>
                <div style="font-size: 11px; color: #ccc; margin-bottom: 8px;">${url}</div>
                <div style="color: #ffa500;">⚠️ Analysis Failed</div>
            `;
        }
    }
}

// Hide tooltip
function hideTooltip() {
    if (tooltip && tooltip.parentNode) {
        tooltip.remove();
        tooltip = null;
        console.log('🗑️ SCAMIFY: Tooltip hidden');
    }
}

// Setup listeners
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

// Start immediately
console.log('🚀 SCAMIFY: Starting initialization...');

// Setup listeners (no test tooltip)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupListeners);
} else {
    setupListeners();
}

console.log('🎯 SCAMIFY: Initialization complete');