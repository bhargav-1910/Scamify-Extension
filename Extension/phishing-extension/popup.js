// DOM Elements
const authContainer = document.getElementById('authContainer');
const newMainContainer = document.getElementById('newMainContainer'); // Updated from mainContainer
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const showRegister = document.getElementById('showRegister');
const showLogin = document.getElementById('showLogin');
const loadingSpinner = document.getElementById('loadingSpinner');

// Sidebar Navigation Elements
const navDashboard = document.getElementById('navDashboard');
const navUrlChecker = document.getElementById('navUrlChecker');
const navGlobalStats = document.getElementById('navGlobalStats');
const navFeatures = document.getElementById('navFeatures');
const navPremium = document.getElementById('navPremium');
const navSettings = document.getElementById('navSettings');

// Content Views
const dashboardView = document.getElementById('dashboardView');
const urlCheckerView = document.getElementById('urlCheckerView');
const globalStatsView = document.getElementById('globalStatsView');
const featuresView = document.getElementById('featuresView');
const premiumViewDashboard = document.getElementById('premiumViewDashboard');
const settingsView = document.getElementById('settingsView');
const premiumView = document.getElementById('premiumView'); // Keep for compatibility
const contentHeaderTitle = document.getElementById('contentHeaderTitle');
const currentUsername = document.getElementById('currentUsername');
const newLogoutBtn = document.getElementById('newLogoutBtn');

// Change Password View Elements
const changePasswordView = document.getElementById('changePasswordView');
const changePasswordForm = document.getElementById('changePasswordForm');
const oldPasswordInput = document.getElementById('oldPassword');
const newPasswordInput = document.getElementById('newPassword');
const confirmNewPasswordInput = document.getElementById('confirmNewPassword');
const backToSettingsFromChangePasswordBtn = document.getElementById('backToSettingsFromChangePassword');

// Email Notifications View Elements
const emailNotificationsView = document.getElementById('emailNotificationsView');
const emailPhishingAlertsToggle = document.getElementById('emailPhishingAlertsToggle');
const emailWeeklyReportToggle = document.getElementById('emailWeeklyReportToggle');
const emailPromotionalOffersToggle = document.getElementById('emailPromotionalOffersToggle');
const backToSettingsFromEmailNotificationsBtn = document.getElementById('backToSettingsFromEmailNotifications');

// Dashboard View Elements
const powerButton = document.getElementById('powerButton');
const connectionStatus = document.getElementById('connectionStatus');
const totalScannedElement = document.getElementById('totalScanned');
const threatsBlockedElement = document.getElementById('threatsBlocked');

// Dashboard Feature Toggles (Reintroduced)
const extensionToggle = document.getElementById('extensionToggle');
const featureNotifToggle = document.getElementById('featureNotifToggle');
const downloadProtectionToggle = document.getElementById('downloadProtectionToggle');
const hoverDetectionToggle = document.getElementById('hoverDetectionToggle');

// Manual URL Checker Elements
const manualUrlInput = document.getElementById('manualUrlInput');
const checkUrlBtn = document.getElementById('checkUrlBtn');
const urlCheckResult = document.getElementById('urlCheckResult');
const resultTitle = document.getElementById('resultTitle');
const resultDescription = document.getElementById('resultDescription');
// const resultConfidence = document.getElementById('resultConfidence'); // Removed confidence display

// Premium purchase buttons
const purchasePremiumBtns = document.querySelectorAll('.btn-primary.btn-large');

// Global Statistics Buttons
const globalStatsBtn = document.getElementById('globalStatsBtn');
const globalStatsNewTabBtn = document.getElementById('globalStatsNewTabBtn');

// Settings View Elements (for User Profile)
// Removed old elements: extensionToggle, downloadProtection, hoverDetection, notificationsEnabled, statusBadge, statusIndicator, totalScanned, safeCount, suspiciousCount, phishingCount, activityList, username, logoutBtn

// State
let currentUser = null;
let authToken = null;
let currentStats = {
    total: 0,
    safe: 0,
    suspicious: 0,
    phishing: 0
};
let chartInstances = {};
let extensionSettings = {
    extension_enabled: true, // Set to true by default for better UX
    download_protection: true,
    hover_detection: true,
    notifications_enabled: true,
    email_phishing_alerts: true,
    email_weekly_report: true,
    email_promotional_offers: true,
};

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    initializeExtension();
});

// Helper to show/hide views
function showView(viewId) {
    const views = [authContainer, newMainContainer, dashboardView, urlCheckerView, featuresView, premiumViewDashboard, settingsView, premiumView, changePasswordView, emailNotificationsView];
    views.forEach(view => {
        if (view) view.style.display = 'none';
    });

    const targetView = document.getElementById(viewId);
    if (targetView) {
        targetView.style.display = 'block';
    }
    
    // Header title is now fixed as "PhishX" - no dynamic updates needed

    // Update active state of sidebar navigation links
    document.querySelectorAll('.sidebar-menu .nav-link, .sidebar-footer .nav-link').forEach(link => {
        link.classList.remove('active');
    });

    let activeLinkId;
    if (viewId === 'dashboardView') activeLinkId = 'navMain';
    else if (viewId === 'settingsView') activeLinkId = 'navSettings';
    else if (viewId === 'changePasswordView') activeLinkId = 'navSettings'; 
    else if (viewId === 'emailNotificationsView') activeLinkId = 'navSettings'; // Stays on settings visually
    else if (viewId === 'premiumView') activeLinkId = 'navPremium';

    const activeLink = document.getElementById(activeLinkId);
    if (activeLink) activeLink.classList.add('active');
    
    // Specific actions for views
    if (viewId === 'settingsView') {
        loadSettings();
    } else if (viewId === 'dashboardView') {
        // No specific action needed currently
    } else if (viewId === 'changePasswordView') {
        if (changePasswordForm) changePasswordForm.reset();
    } else if (viewId === 'emailNotificationsView') {
        // Load current email notification settings
        loadEmailNotificationSettings();
    }
    // Always show newMainContainer when not in auth
    if (viewId !== 'authContainer' && newMainContainer) {
        newMainContainer.style.display = 'flex';
    } else if (viewId === 'authContainer' && newMainContainer) {
        newMainContainer.style.display = 'none';
    }
}

// Navigation handler for main views
function showMainView(viewId) {
    // Hide all main views
    const mainViews = [dashboardView, urlCheckerView, featuresView, premiumViewDashboard, settingsView, changePasswordView, emailNotificationsView];
    mainViews.forEach(view => {
        if (view) view.style.display = 'none';
    });

    // Show target view
    const targetView = document.getElementById(viewId);
    if (targetView) {
        targetView.style.display = 'block';
    }

    // Update navigation active states
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => link.classList.remove('active'));
    
    // Set active nav based on view
    const navMap = {
        'dashboardView': navDashboard,
        'urlCheckerView': navUrlChecker,
        'featuresView': navFeatures,
        'premiumViewDashboard': navPremium,
        'settingsView': navSettings
    };
    
    if (navMap[viewId]) {
        navMap[viewId].classList.add('active');
    }

    // Header title is now fixed as "PhishX" - no dynamic updates needed

    // Initialize specific views
    if (viewId === 'dashboardView') {
        updateDashboardStats();
        // Set power button to active if extension is enabled
        if (powerButton && extensionSettings.extension_enabled) {
            powerButton.classList.add('active');
            if (connectionStatus) {
                connectionStatus.textContent = 'Connection is ON';
            }
        } else if (powerButton) {
            powerButton.classList.remove('active');
            if (connectionStatus) {
                connectionStatus.textContent = 'Connection is OFF';
            }
        }
    } else if (viewId === 'featuresView') {
        loadSettings();
    } else if (viewId === 'settingsView') {
        loadSettings();
    }
}



// Update dashboard statistics
function updateDashboardStats() {
    if (totalScannedElement) {
        totalScannedElement.textContent = currentStats.total.toLocaleString();
    }
    if (threatsBlockedElement) {
        const threatsBlocked = currentStats.phishing + currentStats.suspicious;
        threatsBlockedElement.textContent = threatsBlocked.toLocaleString();
    }
}

// Initialize extension
function initializeExtension() {
    // Check authentication status
    checkAuthStatus();
    
    // Set up event listeners
    setupEventListeners();
    
    // Removed ensureStableDimensions as it's no longer necessary
    
    // Load extension settings and apply them
    loadExtensionSettings();
    
    // Load initial data if authenticated
    if (authToken) {
        loadInitialData();
    }
    // Load and apply email settings on initialization
    chrome.storage.local.get(['email_phishing_alerts', 'email_weekly_report', 'email_promotional_offers'], (data) => {
        // Set initial state for email notification toggles
        extensionSettings.email_phishing_alerts = !!data.email_phishing_alerts;
        extensionSettings.email_weekly_report = !!data.email_weekly_report;
        extensionSettings.email_promotional_offers = !!data.email_promotional_offers;

        if (emailPhishingAlertsToggle) emailPhishingAlertsToggle.checked = extensionSettings.email_phishing_alerts;
        if (emailWeeklyReportToggle) emailWeeklyReportToggle.checked = extensionSettings.email_weekly_report;
        if (emailPromotionalOffersToggle) emailPromotionalOffersToggle.checked = extensionSettings.email_promotional_offers;

    });
}



// Set up event listeners
function setupEventListeners() {
    // Authentication form events
    loginForm.addEventListener('submit', handleLogin);
    registerForm.addEventListener('submit', handleRegister);
    showRegister.addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm('register');
    });
    showLogin.addEventListener('click', (e) => {
        e.preventDefault();
        showAuthForm('login');
    });
    
    // Sidebar navigation events
    if (navDashboard) navDashboard.addEventListener('click', (e) => {
        e.preventDefault();
        showMainView('dashboardView');
    });
    if (navUrlChecker) navUrlChecker.addEventListener('click', (e) => {
        e.preventDefault();
        showMainView('urlCheckerView');
    });
    if (navGlobalStats) navGlobalStats.addEventListener('click', (e) => {
        e.preventDefault();
        // Directly open global statistics in new tab
        openGlobalStatsNewTab();
    });
    if (navFeatures) navFeatures.addEventListener('click', (e) => {
        e.preventDefault();
        showMainView('featuresView');
    });
    if (navPremium) navPremium.addEventListener('click', (e) => {
        e.preventDefault();
        showMainView('premiumViewDashboard');
    });
    if (navSettings) navSettings.addEventListener('click', (e) => {
        e.preventDefault();
        showMainView('settingsView');
    });

    // Dashboard view events
    if (powerButton) powerButton.addEventListener('click', handlePowerToggle);
    
    // Dashboard Feature Toggles events
    if (extensionToggle) extensionToggle.addEventListener('change', saveSettings);
    if (featureNotifToggle) featureNotifToggle.addEventListener('change', saveSettings);
    if (downloadProtectionToggle) downloadProtectionToggle.addEventListener('change', () => {
        saveSettings();
        showNotification(`Download Protection is ${downloadProtectionToggle.checked ? 'ON' : 'OFF'}`, 'info');
    });
    if (hoverDetectionToggle) hoverDetectionToggle.addEventListener('change', () => {
        saveSettings();
        chrome.runtime.sendMessage({ action: 'toggleHoverDetection', enabled: hoverDetectionToggle.checked });
        showNotification(`Hover Detection is ${hoverDetectionToggle.checked ? 'ON' : 'OFF'}`, 'info');
    });
    
    // Premium purchase button events
    purchasePremiumBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            showNotification('Premium purchase feature coming soon!', 'info');
        });
    });

    // Global Statistics Button events
    if (globalStatsBtn) globalStatsBtn.addEventListener('click', openGlobalStats);
    if (globalStatsNewTabBtn) globalStatsNewTabBtn.addEventListener('click', openGlobalStatsNewTab);

    // Manual URL Checker event
    if (checkUrlBtn) checkUrlBtn.addEventListener('click', handleManualUrlCheck);
    if (manualUrlInput) {
        manualUrlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleManualUrlCheck();
            }
        });
    }

    // Manual URL Checker event
    if (checkUrlBtn) checkUrlBtn.addEventListener('click', handleManualUrlCheck);
    if (manualUrlInput) manualUrlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleManualUrlCheck();
        }
    });

    // Settings View - User Profile actions
    const changePasswordSetting = document.getElementById('changePasswordSetting');
    if (changePasswordSetting) changePasswordSetting.addEventListener('click', () => showView('changePasswordView'));
    const manageEmailNotificationsSetting = document.getElementById('manageEmailNotificationsSetting');
    if (manageEmailNotificationsSetting) manageEmailNotificationsSetting.addEventListener('click', () => showView('emailNotificationsView'));
    const deleteAccountSetting = document.getElementById('deleteAccountSetting');
    if (deleteAccountSetting) deleteAccountSetting.addEventListener('click', handleDeleteAccount);

    // Change Password View events
    if (changePasswordForm) changePasswordForm.addEventListener('submit', handleChangePasswordSubmit);
    if (backToSettingsFromChangePasswordBtn) backToSettingsFromChangePasswordBtn.addEventListener('click', () => showView('settingsView'));

    // Email Notifications View events
    if (emailPhishingAlertsToggle) emailPhishingAlertsToggle.addEventListener('change', saveEmailNotificationSettings);
    if (emailWeeklyReportToggle) emailWeeklyReportToggle.addEventListener('change', saveEmailNotificationSettings);
    if (emailPromotionalOffersToggle) emailPromotionalOffersToggle.addEventListener('change', saveEmailNotificationSettings);
    if (backToSettingsFromEmailNotificationsBtn) backToSettingsFromEmailNotificationsBtn.addEventListener('click', () => showView('settingsView'));

    // Logout event
    if (newLogoutBtn) newLogoutBtn.addEventListener('click', handleLogout);
}

// Check authentication status
function checkAuthStatus() {
    chrome.storage.local.get(['authToken', 'currentUser'], function(result) {
        if (result.authToken && result.currentUser) {
            authToken = result.authToken;
            currentUser = result.currentUser;
            if (currentUsername) currentUsername.textContent = currentUser.username;
            showView('newMainContainer');
            showMainView('dashboardView');
            loadInitialData();
        } else {
            showView('authContainer');
        }
    });
}

// Show authentication interface
function showAuthInterface() {
    authContainer.style.display = 'flex';
    newMainContainer.style.display = 'none';
    showAuthForm('login');
}

// Show specific auth form
function showAuthForm(formType) {
    if (formType === 'login') {
        loginForm.style.display = 'flex';
        registerForm.style.display = 'none';
    } else {
        loginForm.style.display = 'none';
        registerForm.style.display = 'flex';
    }
}

// Handle power button toggle
async function handlePowerToggle() {
    extensionSettings.extension_enabled = !extensionSettings.extension_enabled;
    await updateExtensionSettings();
    updateExtensionControls();
    
    // Update power button and connection status in dashboard
    if (powerButton) {
        if (extensionSettings.extension_enabled) {
            powerButton.classList.add('active');
            if (connectionStatus) {
                connectionStatus.textContent = 'Connection is ON';
            }
            showNotification('AI Protection enabled', 'success');
        } else {
            powerButton.classList.remove('active');
            if (connectionStatus) {
                connectionStatus.textContent = 'Connection is OFF';
            }
            showNotification('AI Protection disabled', 'info');
        }
    }
}

// Handle Adblock toggle (placeholder for now)
async function handleAdblockToggle() {
    // This function will likely be removed or repurposed if adblock is removed from features
    // For now, it remains a placeholder.
    const enabled = extensionSettings.adblock_enabled; 
    await updateExtensionSettings();
    showNotification(`AdBlock ${enabled ? 'enabled' : 'disabled'}`, enabled ? 'success' : 'info');
}

// Manual URL Checker function
async function handleManualUrlCheck() {
    console.log('🔍 Manual URL check triggered');
    const url = manualUrlInput.value.trim();
    
    if (!url) {
        showNotification('Please enter a URL to check', 'warning');
        return;
    }

    // Add http:// if no protocol specified
    let processedUrl = url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        processedUrl = 'https://' + url;
    }

    // Basic URL validation
    try {
        new URL(processedUrl);
        console.log('✅ URL validated:', processedUrl);
    } catch (e) {
        console.error('❌ Invalid URL:', e);
        showNotification('Please enter a valid URL', 'warning');
        return;
    }
    
    // Show loading state
    urlCheckResult.style.display = 'block';
    urlCheckResult.className = 'url-check-result';
    
    const resultIcon = urlCheckResult.querySelector('.result-icon');
    if (resultTitle) resultTitle.textContent = 'Scanning...';
    if (resultDescription) resultDescription.textContent = 'Analyzing URL for threats using AI...';
    // if (resultConfidence) resultConfidence.textContent = '--'; // Removed confidence display
    if (resultIcon) {
        resultIcon.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        resultIcon.className = 'result-icon';
    }
    
    checkUrlBtn.disabled = true;
    checkUrlBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
    
    try {
        console.log('📡 Testing backend connection...');
        
        // First, test if backend is available with a quick health check
        const healthController = new AbortController();
        const healthTimeoutId = setTimeout(() => healthController.abort(), 3000); // 3 second timeout for health check
        
        try {
            const healthResponse = await fetch('http://127.0.0.1:5000/', {
                method: 'GET',
                signal: healthController.signal
            });
            clearTimeout(healthTimeoutId);
            console.log('✅ Backend is available, status:', healthResponse.status);
        } catch (healthError) {
            clearTimeout(healthTimeoutId);
            console.warn('⚠️ Backend health check failed, proceeding anyway:', healthError.message);
        }
        
        console.log('📡 Making API call to backend for:', processedUrl);
        
        // Create AbortController for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout for analysis
        
        // Make API call to backend with timeout
        const response = await fetch('http://127.0.0.1:5000/predict_url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: processedUrl }),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId); // Clear timeout if request completes
        console.log('📡 API response status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text().catch(() => 'Unknown error');
            console.error('❌ API error response:', errorText);
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }
        
        const result = await response.json();
        console.log('📊 Manual URL check result:', result);
        
        // Validate response structure
        if (!result.prediction || result.probability === undefined) {
            console.error('❌ Invalid response structure:', result);
            throw new Error('Invalid response format from server');
        }
        
        // Update UI with results
        displayUrlCheckResult(result);
        
        console.log('✅ Manual URL check completed successfully');
        
    } catch (error) {
        console.error('❌ Manual URL check error:', error);
        
        // Provide specific error messages
        let errorMessage = 'Unable to analyze URL. ';
        if (error.name === 'AbortError') {
            errorMessage += 'Request timed out. The server may be busy - please try again.';
        } else if (error.message.includes('Failed to fetch') || error.message.includes('fetch')) {
            errorMessage += 'Cannot connect to the AI backend server.\n\nPlease ensure:\n• Backend server is running\n• Server is accessible at http://127.0.0.1:5000\n• No firewall is blocking the connection';
        } else if (error.message.includes('NetworkError')) {
            errorMessage += 'Network connection error. Please check your internet connection and try again.';
        } else if (error.message.includes('Invalid response')) {
            errorMessage += 'The AI model returned an invalid response format. Please check the backend logs.';
        } else {
            errorMessage += error.message;
        }
        
        displayUrlCheckError(errorMessage);
    }
    
    // Reset button state
    checkUrlBtn.disabled = false;
    checkUrlBtn.innerHTML = '<i class="fas fa-shield-alt"></i> Check URL';
}

// Display error in URL check result
function displayUrlCheckError(message) {
    console.log('❌ Displaying error:', message);
    
    if (!urlCheckResult) {
        console.error('❌ urlCheckResult element not found for error display');
        return;
    }
    
    urlCheckResult.style.display = 'block';
    urlCheckResult.className = 'url-check-result error';
    
    const resultIcon = urlCheckResult.querySelector('.result-icon');
    if (resultTitle) {
        resultTitle.textContent = 'Error';
        resultTitle.style.color = '#ef4444';
    }
    if (resultDescription) {
        resultDescription.textContent = message;
        resultDescription.style.color = '#f87171';
    }
    // if (resultConfidence) {
    //     resultConfidence.textContent = '--'; // Removed confidence display
    // }
    if (resultIcon) {
        resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
        resultIcon.className = 'result-icon error';
        resultIcon.style.color = '#ef4444';
    }
    
    console.log('❌ Error displayed to user');
}

function displayUrlCheckResult(result) {
    if (!urlCheckResult) {
        console.error('❌ urlCheckResult element not found');
        return;
    }

    const resultIcon = urlCheckResult.querySelector('.result-icon');
    
    // Map backend predictions to frontend format
    let prediction = result.prediction.toLowerCase();
    if (prediction === 'legitimate') prediction = 'safe';
    if (prediction === 'malicious') prediction = 'phishing';
    // 'suspicious' stays the same
    
    const confidence = Math.round(result.probability * 100);
    
    console.log('📊 Displaying result:', prediction, 'with', confidence, '% confidence');
    
    // Update result classes and content
    urlCheckResult.className = `url-check-result ${prediction}`;
    if (resultIcon) resultIcon.className = `result-icon ${prediction}`;
    
    // Update content based on prediction
    switch (prediction) {
        case 'safe':
            if (resultIcon) resultIcon.innerHTML = '<i class="fas fa-check-circle"></i>';
            if (resultTitle) resultTitle.textContent = 'Safe URL';
            if (resultDescription) resultDescription.textContent = 'This URL appears to be legitimate and safe to visit.';
            break;
        case 'phishing':
            if (resultIcon) resultIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            if (resultTitle) resultTitle.textContent = 'Phishing Detected!';
            if (resultDescription) resultDescription.textContent = 'This URL has been identified as a phishing threat. Avoid visiting this site.';
            break;
        case 'suspicious':
            if (resultIcon) resultIcon.innerHTML = '<i class="fas fa-question-circle"></i>';
            if (resultTitle) resultTitle.textContent = 'Suspicious URL';
            if (resultDescription) resultDescription.textContent = 'This URL shows suspicious characteristics. Exercise caution.';
            break;
        default:
            if (resultIcon) resultIcon.innerHTML = '<i class="fas fa-shield-alt"></i>';
            if (resultTitle) resultTitle.textContent = 'Analysis Complete';
            if (resultDescription) resultDescription.textContent = 'URL analysis completed.';
    }
    
    // if (resultConfidence) resultConfidence.textContent = `${confidence}%`; // Removed confidence display
    
    console.log('✅ Result displayed successfully');
}

function displayUrlCheckError(message) {
    const resultIcon = urlCheckResult.querySelector('.result-icon');
    
    urlCheckResult.className = 'url-check-result';
    resultIcon.className = 'result-icon';
    resultIcon.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
    
    resultTitle.textContent = 'Error';
    resultDescription.textContent = message;
    // resultConfidence.textContent = '--'; // Removed confidence display
}

// Placeholder functions for new settings actions
// function handleChangePassword() { 
//     showNotification('You will be redirected to the password change page. (Not yet implemented)', 'info');
//     console.log('Change Password clicked');
//     // In a real application, you would open a new modal or a new tab for password change
// }

async function handleChangePasswordSubmit(e) {
    e.preventDefault();

    const oldPassword = oldPasswordInput.value;
    const newPassword = newPasswordInput.value;
    const confirmNewPassword = confirmNewPasswordInput.value;

    if (!oldPassword || !newPassword || !confirmNewPassword) {
        showNotification('Please fill in all password fields.', 'error');
        return;
    }

    if (newPassword !== confirmNewPassword) {
        showNotification('New passwords do not match.', 'error');
        return;
    }

    if (newPassword.length < 6) {
        showNotification('New password must be at least 6 characters long.', 'error');
        return;
    }

    showLoading(true);
    try {
        // Simulate success
        await new Promise(resolve => setTimeout(resolve, 1000)); 
        showNotification('Password changed successfully! (Simulated)', 'success');
        if (changePasswordForm) changePasswordForm.reset();
        showView('settingsView'); // Go back to settings view after success

    } catch (error) {
        console.error('Change password error:', error);
        showNotification(error.message || 'Failed to change password.', 'error');
    } finally {
        showLoading(false);
    }
}

// function handleManageEmailNotifications() {
//     showNotification('Managing email notification preferences (Not yet implemented)', 'info');
//     console.log('Manage Email Notifications clicked');
//     // In a real application, you would navigate to a detailed email settings view
// }

async function loadEmailNotificationSettings() {
    try {
        // Simulate loading from chrome.storage.local
        const data = await chrome.storage.local.get(['email_phishing_alerts', 'email_weekly_report', 'email_promotional_offers']);
        extensionSettings.email_phishing_alerts = !!data.email_phishing_alerts;
        extensionSettings.email_weekly_report = !!data.email_weekly_report;
        extensionSettings.email_promotional_offers = !!data.email_promotional_offers;

        if (emailPhishingAlertsToggle) emailPhishingAlertsToggle.checked = extensionSettings.email_phishing_alerts;
        if (emailWeeklyReportToggle) emailWeeklyReportToggle.checked = extensionSettings.email_weekly_report;
        if (emailPromotionalOffersToggle) emailPromotionalOffersToggle.checked = extensionSettings.email_promotional_offers;

    } catch (error) {
        console.error('Error loading email notification settings:', error);
        showNotification('Failed to load email notification settings.', 'error');
    }
}

async function saveEmailNotificationSettings() {
    const body = {
        email_phishing_alerts: emailPhishingAlertsToggle ? emailPhishingAlertsToggle.checked : extensionSettings.email_phishing_alerts,
        email_weekly_report: emailWeeklyReportToggle ? emailWeeklyReportToggle.checked : extensionSettings.email_weekly_report,
        email_promotional_offers: emailPromotionalOffersToggle ? emailPromotionalOffersToggle.checked : extensionSettings.email_promotional_offers,
    };
    try {
        // Simulate saving to chrome.storage.local
        await chrome.storage.local.set(body);
        extensionSettings.email_phishing_alerts = body.email_phishing_alerts;
        extensionSettings.email_weekly_report = body.email_weekly_report;
        extensionSettings.email_promotional_offers = body.email_promotional_offers;
        showNotification('Email notification settings saved!', 'success');
    } catch (e) {
        console.error('Error saving email notification settings:', e);
        showNotification('Failed to save email notification settings.', 'error');
    }
}

async function handleDeleteAccount() {
    const passwordConfirmation = prompt("To confirm account deletion, please enter your password:");

    if (passwordConfirmation === null) { // User clicked cancel on the prompt
        showNotification('Account deletion cancelled.', 'info');
        console.log('Delete Account cancelled by user.');
        return;
    }

    if (!passwordConfirmation) {
        showNotification('Password is required to confirm account deletion.', 'error');
        return;
    }

    showLoading(true);
    try {
        // Simulate a successful deletion after a delay
        await new Promise(resolve => setTimeout(resolve, 1500));

        showNotification('Account deleted successfully! (Simulated)', 'success');
        console.log('Delete Account confirmed and simulated.');
        handleLogout(); // Log out and clear local storage
        showView('authContainer'); // Redirect to login/register screen
    } catch (error) {
        console.error('Account deletion error:', error);
        showNotification(error.message || 'Failed to delete account.', 'error');
    } finally {
        showLoading(false);
    }
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    if (!email || !password) {
        showNotification('Please fill in all fields', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Simulate login success
        await new Promise(resolve => setTimeout(resolve, 500));

        authToken = 'simulated_token'; // Dummy token
        currentUser = { username: email.split('@')[0], email: email }; // Dummy user
        
        chrome.storage.local.set({
            authToken: authToken,
            currentUser: currentUser
        });
        
        if (currentUsername) currentUsername.textContent = currentUser.username; 
        showView('newMainContainer');
        showMainView('dashboardView');
        showNotification('Login successful! (Simulated)', 'success');
        loadInitialData(); 
    } catch (error) {
        console.error('Simulated login error:', error);
        showNotification('Simulated login failed.', 'error');
    } finally {
        showLoading(false);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (!username || !email || !password || !confirmPassword) {
        showNotification('Please fill in all fields', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showNotification('Passwords do not match', 'error');
        return;
    }
    
    if (password.length < 6) {
        showNotification('Password must be at least 6 characters', 'error');
        return;
    }
    
    showLoading(true);
    
    try {
        // Simulate registration success
        await new Promise(resolve => setTimeout(resolve, 500));

        showNotification('Registration successful! Please login. (Simulated)', 'success');
        showAuthForm('login');
        
        registerForm.reset();
    } catch (error) {
        console.error('Simulated registration error:', error);
        showNotification('Simulated registration failed.', 'error');
    } finally {
        showLoading(false);
    }
}

function handleLogout() {
    authToken = null;
    currentUser = null;
    
    chrome.storage.local.remove(['authToken', 'currentUser']);
    
    resetUI();
    
    showView('authContainer');
    
    showNotification('Logged out successfully', 'info');
}

function resetUI() {
    currentStats = { total: 0, safe: 0, suspicious: 0, phishing: 0 };
    updateUI();
    
    // Clear activity list
    // Removed old activityList
}

async function loadInitialData() {
    console.log('🔄 Loading initial data...');
    
    // Load settings from local storage
    await loadExtensionSettings();
    
    console.log('✅ Initial data loaded successfully');
}

async function loadExtensionSettings() {
    try {
        const settings = await chrome.storage.local.get(['extension_enabled', 'hover_detection', 'notifications_enabled', 'download_protection', 'email_phishing_alerts', 'email_weekly_report', 'email_promotional_offers']);
        
        // Update extensionSettings with stored values or use defaults (defaulting to true for better UX)
        extensionSettings.extension_enabled = settings.extension_enabled !== undefined ? settings.extension_enabled : true;
        extensionSettings.hover_detection = settings.hover_detection !== undefined ? settings.hover_detection : true;
        extensionSettings.notifications_enabled = settings.notifications_enabled !== undefined ? settings.notifications_enabled : true;
        extensionSettings.download_protection = settings.download_protection !== undefined ? settings.download_protection : true;
        extensionSettings.email_phishing_alerts = settings.email_phishing_alerts !== undefined ? settings.email_phishing_alerts : true;
        extensionSettings.email_weekly_report = settings.email_weekly_report !== undefined ? settings.email_weekly_report : true;
        extensionSettings.email_promotional_offers = settings.email_promotional_offers !== undefined ? settings.email_promotional_offers : true;
        
        updateExtensionControls();
    } catch (error) {
        console.error('Failed to load extension settings from local storage:', error);
    }
}

function updateExtensionControls() {
    if (extensionToggle) extensionToggle.checked = extensionSettings.extension_enabled;
    if (featureNotifToggle) featureNotifToggle.checked = extensionSettings.notifications_enabled;
    if (downloadProtectionToggle) downloadProtectionToggle.checked = extensionSettings.download_protection;
    if (hoverDetectionToggle) hoverDetectionToggle.checked = extensionSettings.hover_detection;
    // Email Notification Toggles
    if (emailPhishingAlertsToggle) emailPhishingAlertsToggle.checked = extensionSettings.email_phishing_alerts;
    if (emailWeeklyReportToggle) emailWeeklyReportToggle.checked = extensionSettings.email_weekly_report;
    if (emailPromotionalOffersToggle) emailPromotionalOffersToggle.checked = extensionSettings.email_promotional_offers;

    // Update power button and connection status
    if (powerButton) {
        if (extensionSettings.extension_enabled) {
            powerButton.classList.add('active');
            if (connectionStatus) connectionStatus.textContent = 'Connection is ON';
        } else {
            powerButton.classList.remove('active');
            if (connectionStatus) connectionStatus.textContent = 'Connection is OFF';
        }
    }
}

async function updateExtensionSettings() {
    // No backend call for now, directly update local storage
    try {
        await chrome.storage.local.set(extensionSettings);
    } catch (error) {
        console.error('Error updating extension settings in local storage:', error);
        showNotification('Failed to update settings locally', 'error');
    }
}

/*
async function loadUserStatistics() {
    console.log('📊 Loading real user statistics from backend...');
    
    if (!authToken || !currentUser) {
        console.log('⚠️ No user authenticated, showing default stats');
        currentStats = { total: 0, safe: 0, suspicious: 0, phishing: 0 };
        if (myStatsTotalScanned) myStatsTotalScanned.textContent = '0';
        if (myStatsPhishingDetected) myStatsPhishingDetected.textContent = '0';
        return;
    }

    try {
        console.log('🔄 Fetching user stats from backend API...');
        
        const response = await fetch('http://127.0.0.1:5000/get_user_stats', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (!response.ok) {
            console.warn('⚠️ Backend request failed, using cached stats');
            const cachedStats = await chrome.storage.local.get(['userStats']);
            if (cachedStats.userStats) {
                currentStats = cachedStats.userStats;
            } else {
                currentStats = { total: 0, safe: 0, suspicious: 0, phishing: 0 };
            }
        } else {
            const stats = await response.json();
            console.log('✅ Real user stats loaded:', stats);
            
            currentStats = {
                total: stats.total_scans || 0,
                safe: stats.safe_count || 0,
                suspicious: stats.suspicious_count || 0,
                phishing: stats.phishing_count || 0
            };
            
            // Cache the stats locally for offline use
            await chrome.storage.local.set({ userStats: currentStats });
        }

        // Update UI elements
        if (myStatsTotalScanned) myStatsTotalScanned.textContent = currentStats.total.toLocaleString();
        if (myStatsPhishingDetected) myStatsPhishingDetected.textContent = currentStats.phishing.toLocaleString();
        
        console.log('📊 User statistics updated in UI:', currentStats);
        
    } catch (error) {
        console.error('❌ Failed to load user statistics:', error);
        
        // Try to load cached stats
        const cachedStats = await chrome.storage.local.get(['userStats']);
        if (cachedStats.userStats) {
            currentStats = cachedStats.userStats;
        } else {
            currentStats = { total: 0, safe: 0, suspicious: 0, phishing: 0 };
        }
        
        if (myStatsTotalScanned) myStatsTotalScanned.textContent = currentStats.total.toLocaleString();
        if (myStatsPhishingDetected) myStatsPhishingDetected.textContent = currentStats.phishing.toLocaleString();
    }
}
*/

function updateUI() {
    // This function can be kept for future overall UI updates, but for now it's largely empty
}

function openGlobalStats() {
    // Open the phish-stats-globe page in dashboard view
    showGlobalStatsInDashboard();
}

function openGlobalStatsNewTab() {
    // Open the phish-stats-globe page in a new tab
    const url = chrome.runtime.getURL('globe-stats/index.html');
    chrome.tabs.create({ url: url, active: true });
}

function showGlobalStatsInDashboard() {
    // Hide all current views
    document.querySelectorAll('.view').forEach(view => view.classList.add('hidden'));
    
    // Create or show global stats iframe view
    let globalStatsView = document.getElementById('globalStatsView');
    if (!globalStatsView) {
        globalStatsView = document.createElement('div');
        globalStatsView.id = 'globalStatsView';
        globalStatsView.className = 'view';
        globalStatsView.innerHTML = `
            <div class="view-header">
                <button class="back-button" onclick="showDashboard()">
                    <i class="fas fa-arrow-left"></i> Back to Dashboard
                </button>
                <h3><i class="fas fa-globe"></i> Global Statistics</h3>
            </div>
            <div class="stats-container">
                <iframe src="${chrome.runtime.getURL('globe-stats/index.html')}" 
                        style="width: 100%; height: 400px; border: none; border-radius: 8px;">
                </iframe>
            </div>
        `;
        document.body.appendChild(globalStatsView);
    }
    
    // Show the global stats view
    globalStatsView.classList.remove('hidden');
}

/*
function showGlobalStatistics() {
    const url = chrome.runtime.getURL('globe-stats/index.html');
    chrome.tabs.create({ url, active: false }); // Open in new tab, keep extension open
}
*/

function hideGlobalStatistics() {
    if (typeof globalStatsModal !== 'undefined') {
        globalStatsModal.style.display = 'none';
    }
}

async function loadSettings() {
    try {
        const s = await chrome.storage.local.get(['extension_enabled', 'hover_detection', 'notifications_enabled', 'download_protection', 'email_phishing_alerts', 'email_weekly_report', 'email_promotional_offers']);
        // Features View toggles
        if (extensionToggle) extensionToggle.checked = !!s.extension_enabled;
        if (featureNotifToggle) featureNotifToggle.checked = !!s.notifications_enabled;
        if (downloadProtectionToggle) downloadProtectionToggle.checked = !!s.download_protection;
        if (hoverDetectionToggle) hoverDetectionToggle.checked = !!s.hover_detection;
        // Email Notification Toggles
        if (emailPhishingAlertsToggle) emailPhishingAlertsToggle.checked = !!s.email_phishing_alerts;
        if (emailWeeklyReportToggle) emailWeeklyReportToggle.checked = !!s.email_weekly_report;
        if (emailPromotionalOffersToggle) emailPromotionalOffersToggle.checked = !!s.email_promotional_offers;
    } catch (e) {
        console.error('Error loading settings from local storage:', e);
        showNotification('Failed to load settings locally.', 'error');
    }
}

async function saveSettings() {
    const body = {
        extension_enabled: extensionToggle ? extensionToggle.checked : extensionSettings.extension_enabled,
        notifications_enabled: featureNotifToggle ? featureNotifToggle.checked : extensionSettings.notifications_enabled,
        download_protection: downloadProtectionToggle ? downloadProtectionToggle.checked : extensionSettings.download_protection,
        hover_detection: hoverDetectionToggle ? hoverDetectionToggle.checked : extensionSettings.hover_detection,
        email_phishing_alerts: emailPhishingAlertsToggle ? emailPhishingAlertsToggle.checked : extensionSettings.email_phishing_alerts,
        email_weekly_report: emailWeeklyReportToggle ? emailWeeklyReportToggle.checked : extensionSettings.email_weekly_report,
        email_promotional_offers: emailPromotionalOffersToggle ? emailPromotionalOffersToggle.checked : extensionSettings.email_promotional_offers,
    };
    try {
        await chrome.storage.local.set(body);
        showNotification('Settings saved successfully!', 'success');
        // Update background script with latest state
        chrome.runtime.sendMessage({ action: 'updateExtensionState', extensionEnabled: body.extension_enabled, hoverDetectionEnabled: body.hover_detection });
    } catch (e) {
        console.error('Error saving settings to local storage:', e);
        showNotification('Failed to save settings locally.', 'error');
    }
}

/*
async function loadGlobalStatistics() {
    console.log('🌐 Loading real global statistics from backend...');
    
    try {
        console.log('🔄 Fetching global stats from backend API...');
        
        const response = await fetch('http://127.0.0.1:5000/get_global_stats', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            console.warn('⚠️ Backend request failed, using cached global stats');
            const cachedStats = await chrome.storage.local.get(['globalStats']);
            if (cachedStats.globalStats) {
                updateGlobalStatistics(cachedStats.globalStats);
                createGlobalCharts(cachedStats.globalStats);
                return;
            }
        } else {
            const stats = await response.json();
            console.log('✅ Real global stats loaded:', stats);
            
            // Transform backend data to expected format
            const globalStats = {
                total_urls_scanned: stats.total_scans || 0,
                total_phishing_detected: stats.phishing_count || 0,
                total_safe_urls: stats.safe_count || 0,
                total_suspicious_urls: stats.suspicious_count || 0,
                recent_activity: stats.recent_scans || [],
                top_domains: stats.top_flagged_domains || []
            };
            
            // Cache the stats locally for offline use
            await chrome.storage.local.set({ globalStats });
            updateGlobalStatistics(globalStats);
            createGlobalCharts(globalStats);
            return;
        }
        
    } catch (error) {
        console.error('❌ Failed to load global statistics:', error);
    }
    
    // Fallback: Show empty stats if everything fails
    console.log('📊 Using fallback empty global stats');
    const emptyStats = {
        total_urls_scanned: 0,
        total_phishing_detected: 0,
        total_safe_urls: 0,
        total_suspicious_urls: 0,
        recent_activity: [],
        top_domains: []
    };
    updateGlobalStatistics(emptyStats);
    createGlobalCharts(emptyStats);
}
*/

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

function showLoading(show) {
    loadingSpinner.style.display = show ? 'flex' : 'none';
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    let bgColor;
    let boxShadowColor;
    switch (type) {
        case 'success':
            bgColor = '#10b981'; // Green
            boxShadowColor = 'rgba(16, 185, 129, 0.4)';
            break;
        case 'error':
            bgColor = '#ef4444'; // Red
            boxShadowColor = 'rgba(239, 68, 68, 0.4)';
            break;
        case 'info':
        default:
            bgColor = '#667eea'; // Blue
            boxShadowColor = 'rgba(102, 126, 234, 0.4)';
            break;
    }

    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${bgColor};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 16px ${boxShadowColor};
        z-index: 10000;
        animation: slideIn 0.3s ease forwards;
        max-width: 300px;
        word-wrap: break-word;
        border: 1px solid rgba(255, 255, 255, 0.2);
    `;
    
    let style = document.querySelector('style#notification-slide-in-animation');
    if (!style) {
        style = document.createElement('style');
        style.id = 'notification-slide-in-animation';
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease forwards';
        notification.addEventListener('animationend', () => {
            notification.remove();
            if (!document.querySelectorAll('.notification').length && style) {
                style.remove();
            }
        });
    }, 3000);
    
    let slideOutStyle = document.querySelector('style#notification-slide-out-animation');
    if (!slideOutStyle) {
        slideOutStyle = document.createElement('style');
        slideOutStyle.id = 'notification-slide-out-animation';
        slideOutStyle.textContent = `
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(slideOutStyle);
    }
}

// Removed onMessage listener for updateStats

// Removed loadMyFlagged function

// Removed renderMyFlagged function

// Removed onMessage listener for refreshFlagged

/*
async function loadUserHistoryAndAnalytics() {
    console.log('📈 Loading real user history and analytics from backend...');
    
    try {
        if (!authToken || !currentUser) {
            console.log('⚠️ No user authenticated, showing empty history');
            const emptyAgg = { safe: 0, suspicious: 0, phishing: 0 };
            currentStats = { total: 0, safe: 0, suspicious: 0, phishing: 0 };
            if (myStatsTotalScanned) myStatsTotalScanned.textContent = '0';
            if (myStatsPhishingDetected) myStatsPhishingDetected.textContent = '0';
            return;
        }

        console.log('🔄 Fetching user history from backend API...');
        
        const response = await fetch('http://127.0.0.1:5000/get_user_history', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (!response.ok) {
            console.warn('⚠️ Backend request failed, using cached history');
            const cachedData = await chrome.storage.local.get(['userHistory']);
            const history = cachedData.userHistory || [];
            processUserHistory(history);
            return;
        }

        const historyData = await response.json();
        console.log('✅ Real user history loaded:', historyData);
        
        // Transform backend data to expected format
        const history = (historyData.scans || []).map(scan => ({
            prediction: scan.prediction,
            url: scan.url,
            scanned_at: new Date(scan.scanned_at).getTime()
        }));

        // Cache the history locally
        await chrome.storage.local.set({ userHistory: history });
        processUserHistory(history);
        
        console.log('📈 User history processed:', history.length, 'scans');
        
    } catch (error) {
        console.error('❌ Failed to load user history:', error);
        
        // Try to load cached history
        const cachedData = await chrome.storage.local.get(['userHistory']);
        const history = cachedData.userHistory || [];
        processUserHistory(history);
    }
}

function processUserHistory(history) {
    // Process history data to update statistics
    const agg = { safe: 0, suspicious: 0, phishing: 0 };
    history.forEach(h => {
        const p = (h.prediction || '').toLowerCase();
        if (p === 'safe' || p === 'legitimate') agg.safe++; 
        else if (p === 'suspicious') agg.suspicious++; 
        else if (p === 'phishing' || p === 'malicious') agg.phishing++;
    });

    // Update current stats
    currentStats = {
        total: history.length,
        safe: agg.safe,
        suspicious: agg.suspicious,
        phishing: agg.phishing
    };

    // Update UI elements
    if (myStatsTotalScanned) myStatsTotalScanned.textContent = currentStats.total.toLocaleString();
    if (myStatsPhishingDetected) myStatsPhishingDetected.textContent = currentStats.phishing.toLocaleString();
    
    console.log('📊 Statistics updated from history:', currentStats);
}
*/

/*
// Function to clear all cached dummy data
async function clearDummyDataCache() {
    console.log('🗑️ Clearing cached dummy data...');
    
    try {
        // Remove all cached dummy data
        await chrome.storage.local.remove([
            'userHistory',
            'flaggedUrls', 
            'globalStats',
            'userStats',
            'total',
            'safe', 
            'suspicious',
            'phishing'
        ]);
        
        // Reset current stats to zero
        currentStats = { total: 0, safe: 0, suspicious: 0, phishing: 0 };
        
        // Update UI to show clean state
        if (myStatsTotalScanned) myStatsTotalScanned.textContent = '0';
        if (myStatsPhishingDetected) myStatsPhishingDetected.textContent = '0';
        
        console.log('✅ Dummy data cache cleared successfully');
        
    } catch (error) {
        console.error('❌ Error clearing dummy data cache:', error);
    }
}

// Function to manually refresh all statistics (for testing/debugging)
async function refreshAllStatistics() {
    console.log('🔄 Manually refreshing all statistics...');
    
    try {
        await clearDummyDataCache();
        await loadUserStatistics();
        await loadUserHistoryAndAnalytics();  
        await loadMyFlagged();
        await loadGlobalStatistics();
        
        console.log('✅ All statistics refreshed successfully');
        
        // Show notification to user
        if (typeof showNotification === 'function') {
            showNotification('Statistics refreshed with real data!', 'success');
        }
        
    } catch (error) {
        console.error('❌ Error refreshing statistics:', error);
        if (typeof showNotification === 'function') {
            showNotification('Error refreshing statistics', 'error');
        }
    }
}

// Function to log URL scans to the backend
async function logUrlScan(url, prediction, probability, source = 'manual') {
    try {
        console.log('📝 Logging URL scan to backend:', { url, prediction, probability, source });
        
        const response = await fetch('http://127.0.0.1:5000/log_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url,
                prediction: prediction,
                probability: probability,
                source: source
            })
        });
        
        if (response.ok) {
            console.log('✅ URL scan logged successfully');
            // Refresh user statistics after logging
            setTimeout(() => {
                loadUserStatistics();
                loadMyFlagged();
                loadUserHistoryAndAnalytics();
            }, 500);
        } else {
            console.warn('⚠️ Failed to log URL scan:', response.status);
        }
        
    } catch (error) {
        console.warn('⚠️ Error logging URL scan:', error.message);
    }
}
*/

// Initialize the extension when DOM is ready
document.addEventListener('DOMContentLoaded', initializeExtension);