 // background.js - Handles communication between content scripts and other parts of the extension

// Function to broadcast current extension state to all content scripts
async function broadcastExtensionState() {
    const settings = await chrome.storage.local.get(['extension_enabled', 'hover_detection']);
    const extensionEnabled = settings.extension_enabled !== false;
    const hoverDetectionEnabled = settings.hover_detection !== false;

    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            if (tab.id) {
                chrome.tabs.sendMessage(tab.id, {
                    action: 'updateExtensionState',
                    extensionEnabled: extensionEnabled,
                    hoverDetectionEnabled: hoverDetectionEnabled
                }).catch(error => {
                    console.warn(`Could not send state update to content script in tab ${tab.id}. It might not be injected yet or has terminated.`, error);
                });
            }
        });
    });
}

// On extension installed or updated
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ extension_enabled: true, hover_detection: true }); // Default to enabled on install
    broadcastExtensionState();
});

// Listen for messages from popup script to toggle content script behavior
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'toggleHoverDetection') {
        chrome.storage.local.set({ hover_detection: request.enabled }, () => {
            broadcastExtensionState();
            sendResponse({ status: 'success', enabled: request.enabled });
        });
        return true; // Indicates asynchronous response
    } else if (request.action === 'toggleExtension') {
        chrome.storage.local.set({ extension_enabled: request.enabled }, () => {
            broadcastExtensionState();
            sendResponse({ status: 'success', enabled: request.enabled });
        });
        return true;
    } else if (request.action === 'updateExtensionState') {
        // Accept an explicit update request (from popup.saveSettings) and broadcast it
        const extEnabled = request.extensionEnabled !== undefined ? !!request.extensionEnabled : true;
        const hoverEnabled = request.hoverDetectionEnabled !== undefined ? !!request.hoverDetectionEnabled : true;
        chrome.storage.local.set({ extension_enabled: extEnabled, hover_detection: hoverEnabled }, () => {
            broadcastExtensionState();
            sendResponse({ status: 'updated', extension_enabled: extEnabled, hover_detection: hoverEnabled });
        });
        return true;
    } else if (request.action === 'proxyFetch') {
        // Proxy fetch to backend from extension background (avoids mixed-content blocking in page context)
        const url = request.url;
        const method = request.method || 'GET';
        const headers = request.headers || {};
        const body = request.body;

        console.log('[BACKGROUND] proxyFetch ->', method, url);

        fetch(url, {
            method,
            headers,
            body: body && typeof body === 'string' ? body : (body ? JSON.stringify(body) : undefined),
            credentials: 'same-origin'
        }).then(async (resp) => {
            const text = await resp.text();
            let json = null;
            try { json = JSON.parse(text); } catch (e) { /* not json */ }
            sendResponse({ ok: resp.ok, status: resp.status, statusText: resp.statusText, bodyText: text, bodyJson: json });
        }).catch((err) => {
            console.error('[BACKGROUND] proxyFetch error', err);
            sendResponse({ ok: false, error: err.message });
        });
        return true;
    }
});

// Immediately broadcast state when background script starts up
broadcastExtensionState(); 