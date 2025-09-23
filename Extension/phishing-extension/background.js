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
    }
});

// Immediately broadcast state when background script starts up
broadcastExtensionState(); 