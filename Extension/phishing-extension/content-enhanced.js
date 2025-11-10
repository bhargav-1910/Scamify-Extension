// Enhanced ScamiFy Content Script - Dual Model (ANN + LSTM) Implementation
console.log('🚀 SCAMIFY: Enhanced dual-model content script starting');

// ---------------------------------------------------------------------------
// Configuration & State Management
// ---------------------------------------------------------------------------
const SCAMIFY_CONFIG = {
    ANN_ENDPOINT: 'http://127.0.0.1:5000/check',
    LSTM_ENDPOINT: 'http://127.0.0.1:5000/analyze_behavioral',
    CACHE_TTL: 5 * 60 * 1000, // 5 minutes
    DEBUG: true,
    TIMEOUTS: {
        ANN: 5000,      // 5 seconds for hover analysis
        LSTM: 30000     // 30 seconds for behavioral analysis
    }
};

// State management
let SC_STATE = {
    dialog: null,
    lastUrl: null,
    activeEl: null,
    fetching: false,
    hideTimer: null,
    // Start disabled until we verify user is logged in and extension toggle is ON
    enabled: false,
    hoverEnabled: false,
    clickInterceptionEnabled: true,
    cache: new Map(),
    pendingAnalysis: new Map(),
    blockingDialog: null
};

// Utility functions
const scLog = (...args) => SCAMIFY_CONFIG.DEBUG && console.log('[SCAMIFY]', ...args);
const scWarn = (...args) => SCAMIFY_CONFIG.DEBUG && console.warn('[SCAMIFY]', ...args);
const scNow = () => Date.now();
const scIsHttpUrl = (u) => typeof u === 'string' && /^https?:\/\//i.test(u);

// ---------------------------------------------------------------------------
// URL Extraction & Validation (Enhanced)
// ---------------------------------------------------------------------------
function scNormalizeUrl(raw, baseEl) {
    if (!raw) return null;
    try {
        if (/^https?:\/\//i.test(raw)) return new URL(raw).href;
        if (/^\/\//.test(raw)) return (location.protocol + raw);
        if (/^[./]/.test(raw)) return new URL(raw, location.href).href;
        return new URL(raw, location.href).href;
    } catch (e) {
        if (baseEl && baseEl.href) return baseEl.href;
        return null;
    }
}

function scExtractUrl(el) {
    if (!el) return null;
    if (el.tagName === 'A' && el.href) {
        const norm = scNormalizeUrl(el.getAttribute('href'), el) || el.href;
        if (scIsHttpUrl(norm)) return norm;
    }
    const attrs = ['data-url', 'data-href', 'data-link'];
    for (const a of attrs) {
        const val = el.getAttribute && el.getAttribute(a);
        if (val && scIsHttpUrl(val)) return val;
    }
    if (el.childElementCount === 0) {
        const txt = (el.textContent || '').trim();
        if (txt.length <= 300) {
            const m = txt.match(/https?:\/\/[^\s<>'\"]+/i);
            if (m && scIsHttpUrl(m[0])) return m[0];
        }
    }
    return null;
}

function scFindUrlFromElement(el) {
    let node = el, depth = 0;
    while (node && depth < 6) {
        const u = scExtractUrl(node);
        if (u) return u;
        node = node.parentElement;
        depth++;
    }
    
    if (el && el.querySelector) {
        try {
            const a = el.querySelector('a[href^="http"],a[href^="https"]');
            if (a) {
                const norm = scNormalizeUrl(a.getAttribute('href'), a) || a.href;
                if (scIsHttpUrl(norm)) return norm;
            }
            const poss = el.querySelector('[data-url],[data-href],[data-link]');
            if (poss) {
                for (const key of ['data-url', 'data-href', 'data-link']) {
                    const v = poss.getAttribute(key);
                    if (v) {
                        const norm = scNormalizeUrl(v, el);
                        if (scIsHttpUrl(norm)) return norm;
                    }
                }
            }
        } catch (e) {}
    }
    return null;
}

// ---------------------------------------------------------------------------
// API Communication Layer
// ---------------------------------------------------------------------------
class ScamifyAPI {
    static async fetchWithTimeout(url, options, timeout, externalController = null) {
        const controller = externalController instanceof AbortController ? externalController : new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            scWarn('Direct fetch failed, attempting background proxy:', error && error.message ? error.message : error);

            // Fallback: try proxying the request through the extension background script
            try {
                return await new Promise((resolve, reject) => {
                    try {
                        chrome.runtime.sendMessage({
                            action: 'proxyFetch',
                            url,
                            method: options && options.method ? options.method : 'GET',
                            headers: options && options.headers ? options.headers : {},
                            body: options && options.body ? options.body : undefined
                        }, (resp) => {
                            if (!resp) return reject(new Error('No response from background proxy'));
                            if (!resp.ok) {
                                const e = new Error(`Proxy fetch failed: ${resp.status} ${resp.statusText || ''}`);
                                e.responseText = resp.bodyText;
                                return reject(e);
                            }
                            // Create a Response-like object for caller compatibility
                            const fakeResponse = {
                                ok: resp.ok,
                                status: resp.status,
                                statusText: resp.statusText,
                                json: async () => resp.bodyJson,
                                text: async () => resp.bodyText
                            };
                            resolve(fakeResponse);
                        });
                    } catch (err) {
                        reject(err);
                    }
                });
            } catch (proxyError) {
                scWarn('Background proxy fetch also failed', proxyError && proxyError.message ? proxyError.message : proxyError);
                throw proxyError;
            }
        }
    }
    
    static async analyzeWithANN(url) {
        // Respect extension state: do not perform network calls when disabled
        if (!SC_STATE.enabled) {
            scWarn('ANN skipped - extension disabled', { url });
            return { prediction: 'disabled', probability: 0.0, ts: scNow(), model: 'ann_disabled' };
        }

        const cached = SC_STATE.cache.get(`ann_${url}`);
        if (cached && (scNow() - cached.ts) < SCAMIFY_CONFIG.CACHE_TTL) {
            scLog('ANN CACHE HIT', { url, prediction: cached.prediction });
            return cached;
        }
        
        scLog('ANN FETCH START', { url });
        try {
            const response = await this.fetchWithTimeout(
                SCAMIFY_CONFIG.ANN_ENDPOINT,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                },
                SCAMIFY_CONFIG.TIMEOUTS.ANN
            );
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const data = await response.json();
            
            const result = {
                prediction: (data.prediction || 'safe').toLowerCase(),
                probability: typeof data.probability === 'number' ? data.probability : 0.5,
                ts: scNow(),
                model: 'ann'
            };
            
            SC_STATE.cache.set(`ann_${url}`, result);
            scLog('ANN FETCH RESULT', { url, result });
            return result;
            
        } catch (error) {
            scWarn('ANN FETCH ERROR', { url, error: error.message });
            const fallback = { 
                prediction: 'safe', 
                probability: 0.5, 
                ts: scNow(), 
                model: 'ann_fallback',
                error: error.message
            };
            SC_STATE.cache.set(`ann_${url}`, fallback);
            return fallback;
        }
    }
    
    static async analyzeWithLSTM(url, abortController = null) {
        if (!SC_STATE.enabled) {
            scWarn('LSTM skipped - extension disabled', { url });
            return { prediction: 'disabled', probability: 0.0, recommendation: 'allow', confidence_level: 'low', model_used: 'lstm_disabled', behavioral_features: null, extraction_time: 0 };
        }

        scLog('LSTM FETCH START', { url });
        
        try {
            const response = await this.fetchWithTimeout(
                SCAMIFY_CONFIG.LSTM_ENDPOINT,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                },
                SCAMIFY_CONFIG.TIMEOUTS.LSTM,
                abortController
            );
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const data = await response.json();
            
            const result = {
                prediction: (data.prediction || 'safe').toLowerCase(),
                probability: typeof data.probability === 'number' ? data.probability : 0.5,
                recommendation: data.recommendation || 'proceed_with_caution',
                confidence_level: data.confidence_level || 'medium',
                model_used: data.model_used || 'lstm',
                behavioral_features: data.behavioral_features,
                extraction_time: data.extraction_time || 0,
                ts: scNow(),
                model: 'lstm'
            };
            
            scLog('LSTM FETCH RESULT', { url, result });
            return result;
            
        } catch (error) {
            scWarn('LSTM FETCH ERROR', { url, error: error.message });
            throw error;
        }
    }
}

// ---------------------------------------------------------------------------
// UI Components - Hover Tooltip
// ---------------------------------------------------------------------------
class ScamifyTooltip {
    static create() {
        if (SC_STATE.dialog) return SC_STATE.dialog;
        
        const d = document.createElement('div');
        d.id = 'scamify-tooltip';
        d.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            transform: translate(-9999px, -9999px);
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f1f5f9;
            font: 12px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            border: 1px solid #334155;
            border-radius: 10px;
            box-shadow: 0 8px 24px rgba(0,0,0,.45);
            padding: 10px 12px;
            max-width: 360px;
            z-index: 2147483647;
            pointer-events: none;
            backdrop-filter: blur(4px);
            transition: opacity 0.2s ease-in-out;
        `;
        
        document.documentElement.appendChild(d);
        SC_STATE.dialog = d;
        return d;
    }
    
    static renderLoading(url) {
        const d = this.create();
        d.innerHTML = `
            <div style="font-weight:600;margin-bottom:4px;color:#38bdf8;">
                🛡️ ScamiFy Scanning
            </div>
            <div style="font-size:10px;color:#94a3b8;margin-bottom:6px;word-break:break-all;">
                ${url}
            </div>
            <div style="color:#fbbf24;display:flex;align-items:center;gap:6px;">
                <div style="width:12px;height:12px;border:2px solid #fbbf24;border-top:2px solid transparent;border-radius:50%;animation:spin 1s linear infinite;"></div>
                Analyzing...
            </div>
            <style>
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>
        `;
    }
    
    static renderResult(url, result) {
        const d = this.create();
        // Normalize prediction to lowercase for comparison
        const predictionLower = (result.prediction || 'safe').toLowerCase();
        
        let color = '#10b981', icon = '✅', label = 'SAFE';
        
        if (['phishing', 'malicious'].includes(predictionLower)) {
            color = '#ef4444'; icon = '🚨'; label = 'PHISHING';
        } else if (predictionLower === 'suspicious') {
            color = '#f59e0b'; icon = '⚠️'; label = 'SUSPICIOUS';
        }
        
        // Show model info if available
        const modelInfo = result.model === 'ultra_enhanced_ann' ? 
            '<span style="color:#38bdf8;">Ultra-Enhanced ANN</span>' : 
            result.model ? result.model.toUpperCase() : 'ANN';
        
        d.innerHTML = `
            <div style="font-weight:600;margin-bottom:4px;color:#38bdf8;">
                🛡️ ScamiFy Scan
            </div>
            <div style="font-size:10px;color:#94a3b8;margin-bottom:6px;word-break:break-all;">
                ${url}
            </div>
            <div style="color:${color};font-weight:600;margin-bottom:4px;">
                ${icon} ${label}
            </div>
            <div style="font-size:10px;color:#64748b;margin-top:6px;border-top:1px solid #334155;padding-top:4px;">
                Model: ${modelInfo}
            </div>
        `;
    }
    
    static position(element) {
        if (!SC_STATE.dialog || !element) return;
        
        const rect = element.getBoundingClientRect();
        const dialogRect = SC_STATE.dialog.getBoundingClientRect();
        
        let x = rect.right + 12;
        let y = rect.top - 4;
        
        // Adjust for viewport boundaries
        if (x + dialogRect.width > window.innerWidth - 8) {
            x = rect.left - dialogRect.width - 12;
        }
        if (y + dialogRect.height > window.innerHeight - 8) {
            y = window.innerHeight - dialogRect.height - 8;
        }
        if (y < 8) y = 8;
        
        SC_STATE.dialog.style.transform = `translate(${Math.max(0, x)}px, ${Math.max(0, y)}px)`;
    }
    
    static hide(immediate = false) {
        if (!SC_STATE.dialog) return;
        
        if (immediate) {
            SC_STATE.dialog.style.transform = 'translate(-9999px, -9999px)';
            return;
        }
        
        if (SC_STATE.hideTimer) clearTimeout(SC_STATE.hideTimer);
        SC_STATE.hideTimer = setTimeout(() => {
            if (SC_STATE.dialog) {
                SC_STATE.dialog.style.transform = 'translate(-9999px, -9999px)';
            }
        }, 140);
    }
}

// ---------------------------------------------------------------------------
// UI Components - Blocking Dialog
// ---------------------------------------------------------------------------
class ScamifyBlockingDialog {
    static create(url, lstmResult) {
        if (SC_STATE.blockingDialog) {
            SC_STATE.blockingDialog.remove();
        }
        
        const overlay = document.createElement('div');
        overlay.id = 'scamify-blocking-dialog';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 2147483648;
            display: flex;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(4px);
            animation: scamifyFadeIn 0.3s ease-out;
        `;
        
        const dialog = document.createElement('div');
        dialog.style.cssText = `
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f1f5f9;
            font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6);
            padding: 24px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            border: 1px solid #334155;
        `;
        
        const probability = Math.round(lstmResult.probability * 100);
        const isHighRisk = lstmResult.recommendation === 'block';
        const isMediumRisk = lstmResult.recommendation === 'warn';
        
        let iconColor = '#ef4444', icon = '🚨', statusText = 'PHISHING DETECTED';
        if (isMediumRisk) {
            iconColor = '#f59e0b'; icon = '⚠️'; statusText = 'SUSPICIOUS ACTIVITY';
        }
        
        dialog.innerHTML = `
            <style>
                @keyframes scamifyFadeIn {
                    from { opacity: 0; transform: scale(0.9); }
                    to { opacity: 1; transform: scale(1); }
                }
                .scamify-btn {
                    padding: 10px 20px;
                    border: none;
                    border-radius: 8px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s;
                    font-size: 14px;
                }
                .scamify-btn:hover {
                    transform: translateY(-1px);
                }
                .scamify-btn-danger {
                    background: linear-gradient(135deg, #ef4444, #dc2626);
                    color: white;
                }
                .scamify-btn-warning {
                    background: linear-gradient(135deg, #f59e0b, #d97706);
                    color: white;
                }
                .scamify-btn-secondary {
                    background: #374151;
                    color: #d1d5db;
                    border: 1px solid #4b5563;
                }
            </style>
            
            <div style="text-align: center; margin-bottom: 20px;">
                <div style="font-size: 48px; margin-bottom: 8px;">${icon}</div>
                <div style="font-size: 20px; font-weight: 700; color: ${iconColor}; margin-bottom: 8px;">
                    ${statusText}
                </div>
                <div style="font-size: 16px; color: #94a3b8;">
                    ScamiFy Behavioral Analysis
                </div>
            </div>
            
            <div style="background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 16px; margin-bottom: 20px;">
                <div style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;">Destination URL:</div>
                <div style="word-break: break-all; font-family: monospace; font-size: 13px; color: #e2e8f0;">
                    ${url}
                </div>
            </div>
            
            <div style="margin-bottom: 20px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 16px;">
                    <div style="text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${iconColor};">${probability}%</div>
                        <div style="font-size: 12px; color: #94a3b8;">Risk Score</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 14px; font-weight: 600; color: #e2e8f0;">
                            ${lstmResult.confidence_level.toUpperCase()}
                        </div>
                        <div style="font-size: 12px; color: #94a3b8;">Confidence</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 14px; font-weight: 600; color: #e2e8f0;">
                            ${lstmResult.model_used.toUpperCase()}
                        </div>
                        <div style="font-size: 12px; color: #94a3b8;">Model</div>
                    </div>
                </div>
                
                ${this.renderBehavioralFeatures(lstmResult.behavioral_features)}
            </div>
            
            <div style="margin-bottom: 20px; padding: 12px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px;">
                <div style="font-size: 12px; color: #fca5a5; font-weight: 600; margin-bottom: 4px;">
                    ⚠️ SECURITY WARNING
                </div>
                <div style="font-size: 13px; color: #fecaca;">
                    ${isHighRisk 
                        ? 'This website shows strong indicators of phishing. Proceeding may compromise your personal information and security.'
                        : 'This website shows suspicious behavior patterns. Exercise extreme caution if you choose to proceed.'
                    }
                </div>
            </div>
            
            <div style="display: flex; gap: 12px; justify-content: center;">
                ${isHighRisk ? `
                    <button class="scamify-btn scamify-btn-danger" id="scamify-block-btn">
                        🛡️ Stay Safe (Recommended)
                    </button>
                    <button class="scamify-btn scamify-btn-secondary" id="scamify-proceed-btn">
                        ⚠️ Proceed Anyway
                    </button>
                ` : `
                    <button class="scamify-btn scamify-btn-warning" id="scamify-block-btn">
                        🛡️ Go Back (Recommended)
                    </button>
                    <button class="scamify-btn scamify-btn-secondary" id="scamify-proceed-btn">
                        ⚠️ Continue to Site
                    </button>
                `}
            </div>
            
            <div style="margin-top: 16px; text-align: center; font-size: 11px; color: #64748b;">
                Analysis completed in ${(lstmResult.extraction_time || 0).toFixed(1)}s
            </div>
        `;
        
        overlay.appendChild(dialog);
        document.documentElement.appendChild(overlay);
        SC_STATE.blockingDialog = overlay;
        
        // Add event handlers
        const blockBtn = dialog.querySelector('#scamify-block-btn');
        const proceedBtn = dialog.querySelector('#scamify-proceed-btn');
        
        blockBtn?.addEventListener('click', () => {
            this.close();
        });
        
        proceedBtn?.addEventListener('click', () => {
            this.close();
            // Actually navigate to URL
            window.location.href = url;
        });
        
        // Close on escape key
        const handleKeyPress = (e) => {
            if (e.key === 'Escape') {
                this.close();
                document.removeEventListener('keydown', handleKeyPress);
            }
        };
        document.addEventListener('keydown', handleKeyPress);
        
        return overlay;
    }
    
    static renderBehavioralFeatures(features) {
        if (!features) return '';
        
        const riskFeatures = [];
        
        if (features.ssl_invalid > 0) riskFeatures.push(`🔓 SSL Issues (${features.ssl_invalid})`);
        if (features.suspicious_keywords > 0) riskFeatures.push(`📝 Suspicious Keywords (${features.suspicious_keywords})`);
        if (features.password_fields > 0) riskFeatures.push(`🔑 Password Fields (${features.password_fields})`);
        if (features.redirects > 2) riskFeatures.push(`🔄 Multiple Redirects (${features.redirects})`);
        if (features.external_requests > 10) riskFeatures.push(`🌐 External Requests (${features.external_requests})`);
        if (features.has_errors > 0) riskFeatures.push(`❌ Loading Errors`);
        
        if (riskFeatures.length === 0) return '';
        
        return `
            <div style="margin-bottom: 16px;">
                <div style="font-size: 12px; color: #94a3b8; margin-bottom: 8px; font-weight: 600;">
                    Risk Indicators Detected:
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                    ${riskFeatures.map(feature => 
                        `<span style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 500;">
                            ${feature}
                        </span>`
                    ).join('')}
                </div>
            </div>
        `;
    }
    
    static close() {
        if (SC_STATE.blockingDialog) {
            SC_STATE.blockingDialog.remove();
            SC_STATE.blockingDialog = null;
        }
    }
}

// ---------------------------------------------------------------------------
// Main Logic - Hover Analysis (ANN Model)
// ---------------------------------------------------------------------------
async function analyzeElementHover(element, url) {
    if (!url) return;
    
    if (url === SC_STATE.lastUrl && !SC_STATE.fetching) {
        ScamifyTooltip.position(element);
        return;
    }
    
    SC_STATE.lastUrl = url;
    SC_STATE.activeEl = element;
    SC_STATE.fetching = true;
    
    ScamifyTooltip.renderLoading(url);
    ScamifyTooltip.position(element);
    
    const result = await ScamifyAPI.analyzeWithANN(url);
    
    if (SC_STATE.lastUrl === url && SC_STATE.activeEl === element) {
        ScamifyTooltip.renderResult(url, result);
        ScamifyTooltip.position(element);
    }
    
    SC_STATE.fetching = false;
}

function resolveUrlFromTarget(target) {
    if (!target) return null;
    
    const a = target.closest && target.closest('a[href]');
    if (a) {
        const norm = scNormalizeUrl(a.getAttribute('href'), a) || a.href;
        if (scIsHttpUrl(norm)) return { el: a, url: norm };
    }
    
    let node = target, depth = 0;
    while (node && depth < 5) {
        const u = scExtractUrl(node);
        if (u) return { el: node, url: u };
        node = node.parentElement;
        depth++;
    }
    
    return null;
}

// ---------------------------------------------------------------------------
// Main Logic - Click Interception (LSTM Model)
// ---------------------------------------------------------------------------
async function handleClickInterception(event, url) {
    // Only perform click interception when extension is enabled
    if (!SC_STATE.enabled || !SC_STATE.clickInterceptionEnabled) return;
    
    scLog('CLICK INTERCEPTED', { url });
    
    // Prevent default navigation
    event.preventDefault();
    event.stopPropagation();
    
    let loadingDialog = null;
    let skipRequested = false;

    const showSafeToast = (safeUrl, statusText = 'Safe to open') => {
        const existing = document.getElementById('scamify-safe-toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.id = 'scamify-safe-toast';
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: rgba(16, 185, 129, 0.92);
            color: #0f172a;
            padding: 12px 16px;
            border-radius: 12px;
            box-shadow: 0 12px 24px rgba(16, 185, 129, 0.35);
            font: 13px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            z-index: 2147483647;
            animation: scamifyToastIn 0.25s ease-out;
        `;

        const hostname = (() => {
            try {
                return new URL(safeUrl).hostname;
            } catch {
                return safeUrl;
            }
        })();

        toast.innerHTML = `
            <div style="font-weight: 600;">${statusText}</div>
            <div style="font-size: 11px; opacity: 0.85;">${hostname}</div>
            <style>
                @keyframes scamifyToastIn {
                    from { opacity: 0; transform: translateY(12px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            </style>
        `;

        document.documentElement.appendChild(toast);
        setTimeout(() => {
            toast.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(12px)';
            setTimeout(() => toast.remove(), 220);
        }, 2200);
    };

    try {
        const abortController = new AbortController();

        // Show loading state
        loadingDialog = document.createElement('div');
        loadingDialog.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f1f5f9;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5);
            z-index: 2147483647;
            text-align: center;
            font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
        `;
        
        loadingDialog.innerHTML = `
            <div style="color: #38bdf8; font-size: 16px; font-weight: 600; margin-bottom: 12px;">
                🧠 Analyzing Behavioral Features
            </div>
            <div style="color: #94a3b8; font-size: 12px; margin-bottom: 16px;">
                Please wait while we scan for threats...
            </div>
            <div style="width: 32px; height: 32px; border: 3px solid #334155; border-top: 3px solid #38bdf8; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 16px auto;"></div>
            <button id="scamify-skip-analysis" style="margin-top: 4px; padding: 8px 16px; border-radius: 8px; border: 1px solid #334155; background: rgba(59,130,246,0.1); color: #93c5fd; font-weight: 600; cursor: pointer;">
                Skip scan and open now
            </button>
            <style>
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>
        `;
        
        document.documentElement.appendChild(loadingDialog);

        const skipBtn = loadingDialog.querySelector('#scamify-skip-analysis');
        skipBtn?.addEventListener('click', () => {
            skipRequested = true;
            abortController.abort();
            loadingDialog?.remove();
            loadingDialog = null;
            window.location.href = url;
        }, { once: true });
        
        // Perform LSTM analysis
        const lstmResult = await ScamifyAPI.analyzeWithLSTM(url, abortController);
        
        // Remove loading dialog
        loadingDialog.remove();
        loadingDialog = null;
        
        // Handle result based on recommendation
        if (lstmResult.recommendation === 'allow') {
            scLog('LSTM RECOMMENDATION: ALLOW', { url });
            showSafeToast(url);
            setTimeout(() => (window.location.href = url), 300);
        } else if (lstmResult.recommendation === 'proceed_with_caution') {
            scLog('LSTM RECOMMENDATION: PROCEED WITH CAUTION', { url });
            // For low-risk sites, proceed after brief delay
            showSafeToast(url, 'Proceed with caution');
            setTimeout(() => (window.location.href = url), 700);
        } else {
            scLog('LSTM RECOMMENDATION: BLOCK/WARN', { url, recommendation: lstmResult.recommendation });
            // Show blocking dialog for high-risk or suspicious sites
            ScamifyBlockingDialog.create(url, lstmResult);
        }
        
    } catch (error) {
        if (error.name === 'AbortError') {
            scLog('LSTM analysis aborted', { url, skipRequested });
            if (skipRequested) return;
        }
        scWarn('LSTM ANALYSIS FAILED', { url, error: error.message });
        
        // Remove loading dialog if still present
        if (loadingDialog) {
            loadingDialog.remove();
            loadingDialog = null;
        }
        
        // Fallback: proceed with caution
        const proceed = confirm(
            `ScamiFy behavioral analysis failed.\n\n` +
            `URL: ${url}\n\n` +
            `Do you still want to proceed? This may not be safe.`
        );
        
        if (proceed) {
            window.location.href = url;
        }
    }
}

// ---------------------------------------------------------------------------
// Event Handlers
// ---------------------------------------------------------------------------
function onMouseOver(event) {
    if (!SC_STATE.enabled || !SC_STATE.hoverEnabled) return;
    
    const resolved = resolveUrlFromTarget(event.target);
    if (!resolved) {
        ScamifyTooltip.hide();
        return;
    }
    
    analyzeElementHover(resolved.el, resolved.url);
}

function onMouseMove(event) {
    if (!SC_STATE.activeEl) return;
    ScamifyTooltip.position(SC_STATE.activeEl);
}

function onMouseOut(event) {
    if (!SC_STATE.activeEl) return;
    
    const rel = event.relatedTarget;
    if (rel && (SC_STATE.activeEl === rel || SC_STATE.activeEl.contains(rel))) return;
    if (SC_STATE.dialog && (SC_STATE.dialog === rel || SC_STATE.dialog.contains(rel))) return;
    
    SC_STATE.activeEl = null;
    SC_STATE.lastUrl = null;
    ScamifyTooltip.hide();
}

function onClick(event) {
    // Only intercept clicks on links
    const resolved = resolveUrlFromTarget(event.target);
    if (!resolved) return;
    
    // Skip if it's an internal link or same domain
    const currentDomain = window.location.hostname;
    const targetDomain = new URL(resolved.url).hostname;
    
    if (targetDomain === currentDomain) return;
    
    // Intercept external links for LSTM analysis
    handleClickInterception(event, resolved.url);
}

function onScroll() {
    if (SC_STATE.activeEl) {
        ScamifyTooltip.position(SC_STATE.activeEl);
    }
}

function onWindowBlur() {
    ScamifyTooltip.hide(true);
}

// ---------------------------------------------------------------------------
// Initialization & Setup
// ---------------------------------------------------------------------------
function setupEventListeners() {
    document.addEventListener('mouseover', onMouseOver, true);
    document.addEventListener('mousemove', onMouseMove, true);
    document.addEventListener('mouseout', onMouseOut, true);
    document.addEventListener('click', onClick, true);
    document.addEventListener('scroll', onScroll, true);
    window.addEventListener('blur', onWindowBlur);
    
    scLog('Event listeners attached successfully');
}

function teardownEventListeners() {
    document.removeEventListener('mouseover', onMouseOver, true);
    document.removeEventListener('mousemove', onMouseMove, true);
    document.removeEventListener('mouseout', onMouseOut, true);
    document.removeEventListener('click', onClick, true);
    document.removeEventListener('scroll', onScroll, true);
    window.removeEventListener('blur', onWindowBlur);
    scLog('Event listeners removed');
}

function showActivationBanner() {
    try {
        if (document.getElementById('scamify-activation-banner')) return;
        
        const banner = document.createElement('div');
        banner.id = 'scamify-activation-banner';
        banner.textContent = 'ScamiFy Enhanced Protection Active';
        banner.style.cssText = `
            position: fixed;
            bottom: 12px;
            left: 12px;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            font: 12px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            padding: 8px 12px;
            border: 1px solid #334155;
            border-radius: 6px;
            z-index: 2147483647;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.3s;
        `;
        
        document.documentElement.appendChild(banner);
        requestAnimationFrame(() => banner.style.opacity = '1');
        
        setTimeout(() => {
            banner.style.opacity = '0';
            setTimeout(() => banner.remove(), 400);
        }, 3000);
        
    } catch (error) {
        scWarn('Activation banner failed', error);
    }
}

function initialize() {
    if (window.__SCAMIFY_ENHANCED_READY) return;
    window.__SCAMIFY_ENHANCED_READY = true;
    
    // Read storage to decide whether to enable features (require login + toggle)
    try {
        chrome.storage.local.get(['authToken', 'currentUser', 'extension_enabled', 'hover_detection'], (res) => {
            const hasAuth = !!(res.authToken && res.currentUser);
            // Default to ON when the stored value is missing (undefined) to provide a better UX
            const enabled = res.extension_enabled !== undefined ? !!res.extension_enabled : true;
            const hover = res.hover_detection !== undefined ? !!res.hover_detection : true;

            SC_STATE.enabled = hasAuth && enabled;
            SC_STATE.hoverEnabled = SC_STATE.enabled && hover;

            scLog('Initialization storage state', { hasAuth, enabled, hover, effectiveEnabled: SC_STATE.enabled, effectiveHover: SC_STATE.hoverEnabled });

            if (SC_STATE.enabled) {
                setupEventListeners();
                showActivationBanner();
                scLog('ScamiFy Enhanced (ANN + LSTM) initialized successfully');
                console.log('🎯 SCAMIFY: Enhanced protection active - Hover for ANN analysis, Click for LSTM behavioral analysis');
            } else {
                scLog('ScamiFy Enhanced initialized in INACTIVE mode (login required or protection disabled)');
                console.log('⚠️ SCAMIFY: Enhanced protection is inactive - login and enable protection to activate');
            }
        });
    } catch (e) {
        scWarn('Failed to read storage during initialize', e);
        // Fallback: keep disabled
    }
}

// Handle different document ready states
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}

// Message handling from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'updateExtensionState') {
        // Respect user auth: only enable if user is logged in
            chrome.storage.local.get(['authToken', 'currentUser'], (res) => {
            const hasAuth = !!(res.authToken && res.currentUser);
            // Treat missing requested flags as ON by default
            const requestedEnabled = request.extensionEnabled !== undefined ? !!request.extensionEnabled : true;
            const requestedHover = request.hoverDetectionEnabled !== undefined ? !!request.hoverDetectionEnabled : true;

            SC_STATE.enabled = requestedEnabled && hasAuth;
            SC_STATE.hoverEnabled = requestedHover && SC_STATE.enabled;

            scLog('Extension state updated (message)', {
                requestedEnabled: request.extensionEnabled,
                requestedHover: request.hoverDetectionEnabled,
                hasAuth,
                effectiveEnabled: SC_STATE.enabled,
                effectiveHover: SC_STATE.hoverEnabled
            });

            // Attach or detach listeners based on effective state
            if (SC_STATE.enabled) {
                setupEventListeners();
                showActivationBanner();
            } else {
                teardownEventListeners();
                ScamifyTooltip.hide(true);
            }

            sendResponse({ status: 'updated' });
        });
    }
});

// React to storage changes (auth login/logout or settings changes)
chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;

    // If auth changed, re-evaluate effective state
    if (changes.authToken || changes.currentUser || changes.extension_enabled || changes.hover_detection) {
            chrome.storage.local.get(['authToken', 'currentUser', 'extension_enabled', 'hover_detection'], (res) => {
            const hasAuth = !!(res.authToken && res.currentUser);
            // Default missing stored toggles to ON
            const requestedEnabled = res.extension_enabled !== undefined ? !!res.extension_enabled : true;
            const requestedHover = res.hover_detection !== undefined ? !!res.hover_detection : true;

            const effectiveEnabled = requestedEnabled && hasAuth;
            const effectiveHover = effectiveEnabled && requestedHover;

            scLog('Storage change -> recompute effective state', { hasAuth, requestedEnabled, requestedHover, effectiveEnabled, effectiveHover });

            if (effectiveEnabled && !SC_STATE.enabled) {
                SC_STATE.enabled = true;
                SC_STATE.hoverEnabled = effectiveHover;
                setupEventListeners();
                showActivationBanner();
            } else if (!effectiveEnabled && SC_STATE.enabled) {
                SC_STATE.enabled = false;
                SC_STATE.hoverEnabled = false;
                teardownEventListeners();
                ScamifyTooltip.hide(true);
            } else {
                // update hover flag only
                SC_STATE.hoverEnabled = effectiveHover;
            }
        });
    }
});

console.log('🚀 SCAMIFY: Enhanced dual-model content script loaded');