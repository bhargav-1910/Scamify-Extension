// ScamiFy Content Script - Simplified Mouseover Hover Engine
console.log('🚀 SCAMIFY: Simple hover engine starting');

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let SC_DIALOG = null;         // Floating dialog element
let SC_LAST_URL = null;       // Last analyzed URL
let SC_ACTIVE_EL = null;      // Current element (anchor / container)
let SC_FETCHING = false;      // In-flight analysis
let SC_HIDE_TIMER = null;     // Hide timer
let SC_ENABLED = true;        // Future: chrome.storage toggle
let SC_HOVER_ENABLED = true;  // Future: chrome.storage toggle
const SC_CACHE = new Map();   // url -> { prediction, probability, ts }
const SC_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const SC_DEBUG = true;        // Debug flag

function scLog(...args){ if (SC_DEBUG) console.log('[SCAMIFY]', ...args); }
function scWarn(...args){ if (SC_DEBUG) console.warn('[SCAMIFY]', ...args); }

// ---------------------------------------------------------------------------
// Utilities & URL Extraction
// ---------------------------------------------------------------------------
const scNow = () => Date.now();
const scIsHttpUrl = (u) => typeof u === 'string' && /^https?:\/\//i.test(u);

function scNormalizeUrl(raw, baseEl){
  if (!raw) return null;
  try {
    // If already absolute http(s)
    if (/^https?:\/\//i.test(raw)) return new URL(raw).href;
    // Protocol-relative
    if (/^\/\//.test(raw)) return (location.protocol + raw);
    // Relative path
    if (/^[./]/.test(raw)) return new URL(raw, location.href).href;
    // Fallback: attempt constructing
    return new URL(raw, location.href).href;
  } catch(e){
    if (baseEl && baseEl.href) return baseEl.href; // anchor.href is normalized by browser
    return null;
  }
}

function scExtractUrl(el) {
  if (!el) return null;
  if (el.tagName === 'A' && el.href) {
    const norm = scNormalizeUrl(el.getAttribute('href'), el) || el.href;
    if (scIsHttpUrl(norm)) return norm;
  }
  const attrs = ['data-url','data-href','data-link'];
  for (const a of attrs) {
    const val = el.getAttribute && el.getAttribute(a);
    if (val && scIsHttpUrl(val)) return val;
  }
  if (el.childElementCount === 0) {
    const txt = (el.textContent||'').trim();
    if (txt.length <= 300) {
      const m = txt.match(/https?:\/\/[^\s<>'\"]+/i);
      if (m && scIsHttpUrl(m[0])) return m[0];
    }
  }
  return null;
}

function scFindUrlFromElement(el) {
  // 1. Direct / ancestor search (depth 6)
  let node = el, depth = 0;
  while (node && depth < 6) {
    const u = scExtractUrl(node);
    if (u) return u;
    node = node.parentElement;
    depth++;
  }
  // 2. Descendant quick search (anchors first)
  if (el && el.querySelector) {
    try {
      const a = el.querySelector('a[href^="http"],a[href^="https"]');
      if (a) {
        const norm = scNormalizeUrl(a.getAttribute('href'), a) || a.href;
        if (scIsHttpUrl(norm)) return norm;
      }
      const poss = el.querySelector('[data-url],[data-href],[data-link]');
      if (poss) {
        for (const key of ['data-url','data-href','data-link']) {
          const v = poss.getAttribute(key);
          if (v) {
            const norm = scNormalizeUrl(v, el);
            if (scIsHttpUrl(norm)) return norm;
          }
        }
      }
    } catch(e){}
  }
  return null;
}

function scFindUrlAtPoint(x,y) {
  const els = document.elementsFromPoint(x,y);
  for (const el of els) {
    const u = scFindUrlFromElement(el);
    if (u) { scLog('URL via elementsFromPoint', u); return { url: u, element: el }; }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Backend Fetch with Caching
// ---------------------------------------------------------------------------
async function scFetchAnalysis(url) {
  const cached = SC_CACHE.get(url);
  if (cached && (scNow() - cached.ts) < SC_CACHE_TTL) {
    scLog('CACHE HIT', { url, prediction: cached.prediction, probability: cached.probability });
    return cached;
  }
  scLog('FETCH START', { url });
  try {
    const res = await fetch('http://127.0.0.1:5000/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error('HTTP '+res.status);
    const data = await res.json();
    const norm = {
      prediction: (data.prediction||'safe').toLowerCase(),
      probability: (typeof data.probability === 'number') ? data.probability : 0.5,
      ts: scNow()
    };
    SC_CACHE.set(url, norm);
    scLog('FETCH RESULT', { url, prediction: norm.prediction, probability: norm.probability });
    return norm;
  } catch (e) {
    scWarn('FETCH ERROR', url, e);
    const fb = { prediction: 'safe', probability: 0.5, ts: scNow() };
    SC_CACHE.set(url, fb);
    return fb;
  }
}

// ---------------------------------------------------------------------------
// Tooltip Rendering
// ---------------------------------------------------------------------------
function scCreateDialog() {
  if (SC_DIALOG) return SC_DIALOG;
  const d = document.createElement('div');
  d.id = 'scamify-dialog';
  d.style.cssText = 'position:fixed;top:0;left:0;transform:translate(-9999px,-9999px);background:#0f172a;color:#f1f5f9;font:12px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;border:1px solid #334155;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.45);padding:10px 12px;max-width:360px;z-index:2147483647;pointer-events:none;backdrop-filter:blur(4px);';
  d.innerHTML = '';
  document.documentElement.appendChild(d);
  SC_DIALOG = d;
  return d;
}

function scRenderLoading(url) {
  const d = scCreateDialog();
  d.innerHTML = `<div style="font-weight:600;margin-bottom:4px;color:#38bdf8;">🛡️ ScamiFy Scan</div><div style="font-size:10px;color:#94a3b8;margin-bottom:6px;">${url}</div><div style="color:#fbbf24;">Analyzing...</div>`;
}

function scRenderResult(url,res){
  const d = scCreateDialog();
  const prob = Math.round(res.probability*100);
  let color='#10b981', icon='✅', label='SAFE';
  if (['phishing','malicious'].includes(res.prediction)) { color='#ef4444'; icon='🚨'; label='PHISHING'; }
  else if (res.prediction==='suspicious') { color='#f59e0b'; icon='⚠️'; label='SUSPICIOUS'; }
  d.innerHTML = `<div style="font-weight:600;margin-bottom:4px;color:#38bdf8;">🛡️ ScamiFy Scan</div><div style="font-size:10px;color:#94a3b8;margin-bottom:6px;">${url}</div><div style="color:${color};font-weight:600;">${icon} ${label} (${prob}%)</div><div style="font-size:10px;color:#64748b;margin-top:6px;border-top:1px solid #334155;padding-top:4px;">ANN Model Result</div>`;
}

function scPositionDialogForElement(el) {
  if (!SC_DIALOG || !el) return;
  const r = el.getBoundingClientRect();
  const dRect = SC_DIALOG.getBoundingClientRect();
  let x = r.right + 12;
  let y = r.top - 4;
  if (x + dRect.width > window.innerWidth - 8) x = r.left - dRect.width - 12;
  if (y + dRect.height > window.innerHeight - 8) y = window.innerHeight - dRect.height - 8;
  if (y < 8) y = 8;
  SC_DIALOG.style.transform = `translate(${Math.max(0,x)}px,${Math.max(0,y)}px)`;
}

function scHideDialog(immediate=false){
  if (!SC_DIALOG) return;
  if (immediate){ SC_DIALOG.style.transform='translate(-9999px,-9999px)'; return; }
  if (SC_HIDE_TIMER) clearTimeout(SC_HIDE_TIMER);
  SC_HIDE_TIMER = setTimeout(()=>{ if (SC_DIALOG) SC_DIALOG.style.transform='translate(-9999px,-9999px)'; },140);
}

// ---------------------------------------------------------------------------
// Hover Handling
// ---------------------------------------------------------------------------
async function scAnalyzeElement(el, url){
  if (!url) return;
  if (url === SC_LAST_URL && !SC_FETCHING) { scPositionDialogForElement(el); return; }
  SC_LAST_URL = url;
  SC_ACTIVE_EL = el;
  SC_FETCHING = true;
  scRenderLoading(url);
  scPositionDialogForElement(el);
  const result = await scFetchAnalysis(url);
  if (SC_LAST_URL === url && SC_ACTIVE_EL === el) {
    scRenderResult(url,result);
    scPositionDialogForElement(el);
  }
  SC_FETCHING = false;
}

function scResolveUrlFromTarget(target){
  if (!target) return null;
  // Direct anchor or closest anchor
  const a = target.closest && target.closest('a[href]');
  if (a) {
    const norm = scNormalizeUrl(a.getAttribute('href'), a) || a.href;
    if (scIsHttpUrl(norm)) return { el: a, url: norm };
  }
  // Data-* wrappers
  let node = target; let depth = 0;
  while (node && depth < 5) {
    const u = scExtractUrl(node);
    if (u) return { el: node, url: u };
    node = node.parentElement; depth++;
  }
  return null;
}

function scOnMouseOver(ev){
  if (!SC_ENABLED || !SC_HOVER_ENABLED) return;
  const resolved = scResolveUrlFromTarget(ev.target);
  if (!resolved){ scHideDialog(); return; }
  scAnalyzeElement(resolved.el, resolved.url);
}

function scOnMouseMove(ev){
  if (!SC_ACTIVE_EL) return; // nothing active
  scPositionDialogForElement(SC_ACTIVE_EL);
}

function scOnMouseOut(ev){
  if (!SC_ACTIVE_EL) return;
  const rel = ev.relatedTarget;
  if (rel && (SC_ACTIVE_EL === rel || SC_ACTIVE_EL.contains(rel))) return;
  if (SC_DIALOG && (SC_DIALOG === rel || SC_DIALOG.contains(rel))) return;
  SC_ACTIVE_EL = null; SC_LAST_URL = null; scHideDialog();
}

// Legacy handlers removed in rewrite

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
function scSetup(){
  document.addEventListener('mouseover', scOnMouseOver, true);
  document.addEventListener('mousemove', scOnMouseMove, true);
  document.addEventListener('mouseout', scOnMouseOut, true);
  document.addEventListener('scroll', () => { if (SC_ACTIVE_EL) scPositionDialogForElement(SC_ACTIVE_EL); }, true);
  window.addEventListener('blur', () => scHideDialog(true));
  console.log('✅ SCAMIFY: Simple hover listeners active');
  scShowActivationBanner();
}

// Activation banner to confirm script injected
function scShowActivationBanner(){
  try {
    if (document.getElementById('scamify-activation-banner')) return;
    const b = document.createElement('div');
    b.id='scamify-activation-banner';
    b.textContent='ScamiFy active';
    b.style.cssText='position:fixed;bottom:12px;left:12px;background:#0f172a;color:#e2e8f0;font:12px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:6px 10px;border:1px solid #334155;border-radius:6px;z-index:2147483647;box-shadow:0 4px 12px rgba(0,0,0,.4);pointer-events:none;opacity:0;transition:opacity .3s';
    document.documentElement.appendChild(b);
    requestAnimationFrame(()=>{ b.style.opacity='1'; });
    setTimeout(()=>{ b.style.opacity='0'; setTimeout(()=> b.remove(),400); }, 1800);
  } catch(e){ scWarn('Activation banner failed', e); }
}


function scInit() {
  if (window.__SCAMIFY_READY) return;
  window.__SCAMIFY_READY = true;
  scSetup();
  console.log('🚀 SCAMIFY: Initialized');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', scInit);
} else {
  scInit();
}

console.log('🎯 SCAMIFY: Simple hover engine loaded');