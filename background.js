// Service worker : analyse les requêtes réseau, reçoit les événements des sondes,
// corrèle les signaux par cadre et tient le compteur d'alertes de chaque onglet.
import { IOC_DOMAINS, DOH_HOSTS, TRUSTED_SCRIPT_DOMAINS } from './iocs.js';
import { initRecorder, startSession, logEvent, storeCapture, handleRecorderMessage } from './recorder.js';

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const BADGE_COLOR = { low: '#607d8b', medium: '#f9a825', high: '#e65100', critical: '#b00020' };
const MAX_ALERTS = 300;
const BLOCK_RULE_ID = 1;

const FINGERPRINT_TYPES = new Set(['canvas-fp', 'webgl-fp', 'battery-fp', 'behavior-tracking']);
const CONTROL_TYPES = new Set(['dynamic-code', 'websocket', 'wasm', 'blob-worker']);
// Comportements qu'un script de confiance peut avoir légitimement.
const TRUSTABLE_TYPES = new Set([...FINGERPRINT_TYPES, 'cookie-read']);

// tabId -> Promise<{ alerts: [], frames: {} }>, recopié dans storage.session
// pour survivre à la mise en veille du service worker.
const tabStates = new Map();
const storageKey = (tabId) => `tab:${tabId}`;

function getState(tabId) {
  if (!tabStates.has(tabId)) {
    const key = storageKey(tabId);
    tabStates.set(tabId, chrome.storage.session.get(key)
      .then((r) => r[key] || { alerts: [], frames: {} }));
  }
  return tabStates.get(tabId);
}

async function resetTab(tabId) {
  tabStates.set(tabId, Promise.resolve({ alerts: [], frames: {} }));
  await chrome.storage.session.remove(storageKey(tabId));
  await updateBadge(tabId, []);
}

async function addAlert(tabId, alert) {
  if (tabId < 0) return;
  const state = await getState(tabId);
  // Une alerte = un type + une source : le même script qui recommence n'en crée pas de nouvelle.
  const key = alert.key || `${alert.type}|${alert.source}`;
  const existing = state.alerts.find((a) => a.key === key);
  if (existing) {
    existing.count += 1;
    existing.detail = alert.detail;
    existing.lastTs = Date.now();
  } else {
    state.alerts.push({ ...alert, key, count: 1, ts: alert.ts || Date.now(), lastTs: Date.now() });
    if (state.alerts.length > MAX_ALERTS) state.alerts.shift();
    if (alert.severity === 'critical') notifyCritical(tabId, state, alert);
    logEvent(tabId, {
      kind: 'alert', frameId: alert.frameId, alertType: alert.type, severity: alert.severity,
      detail: alert.detail, source: alert.source, trusted: alert.trusted
    });
  }
  await chrome.storage.session.set({ [storageKey(tabId)]: state });
  await updateBadge(tabId, state.alerts);
}

// Une seule notification système par type d'alerte critique et par page.
function notifyCritical(tabId, state, alert) {
  state.notified = state.notified || [];
  if (state.notified.includes(alert.type)) return;
  state.notified.push(alert.type);
  chrome.notifications.create(`adsentinel-${tabId}-${alert.type}`, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'AdSentinel : alerte critique',
    message: alert.detail,
    priority: 2
  }).catch(() => {});
}

async function updateBadge(tabId, alerts) {
  try {
    const counted = alerts.filter((a) => !a.trusted);
    const worst = counted.reduce((w, a) =>
      (SEVERITY_RANK[a.severity] > SEVERITY_RANK[w] ? a.severity : w), 'low');
    await chrome.action.setBadgeText({ tabId, text: counted.length ? String(counted.length) : '' });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLOR[worst] });
  } catch {
    // L'onglet a pu être fermé entre-temps.
  }
}

// --- Analyse réseau ---------------------------------------------------------

function matchesDomain(host, list) {
  return list.find((d) => host === d || host.endsWith('.' + d));
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

// Approximation du domaine enregistrable : "a.b.example.com" -> "example.com"
function baseDomain(host) {
  return host.split('.').slice(-2).join('.');
}

function isPublicIPv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return !(a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || a === 0);
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function analyzeRequest(details) {
  const { tabId, url, type, frameId, initiator } = details;
  if (tabId < 0 || (initiator && initiator.startsWith('chrome-extension://'))) return;
  if (type === 'main_frame') {
    // Nouvelle page : on repart de zéro avant d'analyser la requête elle-même.
    Promise.all([resetTab(tabId), startSession(tabId, url)]).then(() => {
      logRequest(details);
      checkUrl(details);
    });
    return;
  }
  logRequest(details);
  checkUrl({ tabId, url, type, frameId, initiator });
}

function logRequest({ tabId, url, type, frameId, parentFrameId, method, initiator }) {
  logEvent(tabId, { kind: 'request', frameId, parentFrameId, url, type, method, initiator });
}

function checkUrl({ tabId, url, type, frameId, initiator }) {
  let u;
  try { u = new URL(url); } catch { return; }
  const host = u.hostname;
  const base = { source: url.slice(0, 300), frame: `cadre #${frameId}`, frameId, inFrame: frameId !== 0, origin: 'réseau' };
  // Côté réseau, on regroupe par type + hôte (les URL changent à chaque requête).
  const raise = (alertType, severity, detail) =>
    addAlert(tabId, { ...base, type: alertType, severity, detail, key: `${alertType}|${host}` });

  const ioc = matchesDomain(host, IOC_DOMAINS);
  if (ioc) {
    raise('ioc-domain', 'critical', `Requête vers un domaine de l'infrastructure Discover-Tech / Candiru : ${host}`);
  }

  if (/\/getAd\b/i.test(u.pathname)) {
    raise('ad-loader', 'medium', `Chargeur publicitaire /getAd (schéma Discover-Tech) sur ${host}`);
  }

  if (matchesDomain(host, DOH_HOSTS) || u.pathname === '/dns-query' ||
      (host === 'dns.google' && u.pathname.startsWith('/resolve'))) {
    raise('doh-from-page', 'high', `Résolution DNS chiffrée lancée par la page : ${host}${u.pathname}`);
  }

  if (isPublicIPv4(host) && type !== 'main_frame') {
    let pageHost = '';
    try { pageHost = initiator ? new URL(initiator).hostname : ''; } catch {}
    if (!isPublicIPv4(pageHost)) {
      raise('raw-ip', 'high', `Contact direct d'une adresse IP sans nom de domaine : ${host}`);
    }
  }

  const query = safeDecode(u.search);
  if (/[?&]cookies?=/i.test(u.search) &&
      (query.includes('~~~') || /(_ga|_gid|__gads|_pbjs|sess|token|jwt)/i.test(query))) {
    raise('cookie-exfil', 'high', `Cookies de la page envoyés dans une URL vers ${host}`);
  }

  if (host.endsWith('.cloudfront.net') && type === 'sub_frame' && !ioc) {
    raise('cloudfront-frame', 'low', `Cadre chargé depuis un hôte CloudFront anonyme : ${host}`);
  }
}

chrome.webRequest.onBeforeRequest.addListener(analyzeRequest, { urls: ['<all_urls>'] });
initRecorder();

// --- Événements des sondes et corrélation -----------------------------------

async function onPageEvent(evt, sender) {
  const tabId = sender.tab ? sender.tab.id : -1;
  if (tabId < 0 || !SEVERITY_RANK[evt.severity]) return;
  const frameId = sender.frameId || 0;
  const sourceHost = hostOf(evt.source);
  const trusted = TRUSTABLE_TYPES.has(evt.type) && Boolean(matchesDomain(sourceHost, TRUSTED_SCRIPT_DOMAINS));
  await addAlert(tabId, { ...evt, origin: 'page', frameId, ...(trusted && { severity: 'low', trusted: true }) });
  if (trusted) return;

  const state = await getState(tabId);
  await checkUnknownProfiler(tabId, state, evt, sourceHost, sender);

  // Corrélation : empreinte + exécution de code distant dans le même cadre
  // = comportement typique du SDK décrit par Confiant.
  const frame = state.frames[frameId] || (state.frames[frameId] = { types: [], flagged: false });
  if (!frame.types.includes(evt.type)) frame.types.push(evt.type);
  const fp = frame.types.filter((t) => FINGERPRINT_TYPES.has(t));
  const control = frame.types.filter((t) => CONTROL_TYPES.has(t));
  if (!frame.flagged && evt.inFrame && fp.length >= 2 && control.length >= 1) {
    frame.flagged = true;
    await addAlert(tabId, {
      type: 'spy-sdk-pattern',
      severity: 'critical',
      detail: `Un cadre combine empreinte de l'appareil (${fp.join(', ')}) et contrôle à distance (${control.join(', ')})`,
      source: evt.source,
      frame: evt.frame,
      inFrame: true,
      origin: 'corrélation'
    });
  }
}

// Un script d'un domaine tiers qui prend l'empreinte de l'appareil ET lit les cookies
// du site construit un profil de l'utilisateur, même sans canal C2.
async function checkUnknownProfiler(tabId, state, evt, sourceHost, sender) {
  const pageHost = hostOf(sender.tab && sender.tab.url);
  if (!sourceHost || !pageHost || baseDomain(sourceHost) === baseDomain(pageHost)) return;

  state.sources = state.sources || {};
  const src = state.sources[sourceHost] || (state.sources[sourceHost] = { types: [], flagged: false });
  if (!src.types.includes(evt.type)) src.types.push(evt.type);
  const fp = src.types.filter((t) => FINGERPRINT_TYPES.has(t));
  if (src.flagged || fp.length === 0 || !src.types.includes('cookie-read')) return;

  src.flagged = true;
  await addAlert(tabId, {
    type: 'unknown-profiler',
    severity: 'high',
    detail: `Le script tiers ${sourceHost} prend l'empreinte de l'appareil (${fp.join(', ')}) et lit les cookies de ${pageHost}`,
    source: evt.source,
    frame: evt.frame,
    inFrame: evt.inFrame,
    inheritsOrigin: evt.inheritsOrigin,
    origin: 'corrélation',
    key: `unknown-profiler|${sourceHost}`
  });
}

// --- Blocage optionnel des IOC ----------------------------------------------

async function setBlocking(enabled) {
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [BLOCK_RULE_ID],
    addRules: enabled ? [{
      id: BLOCK_RULE_ID,
      priority: 1,
      action: { type: 'block' },
      condition: { requestDomains: IOC_DOMAINS }
    }] : []
  });
  await chrome.storage.local.set({ blocking: enabled });
}

async function handleMessage(msg, sender) {
  switch (msg && msg.kind) {
    case 'page-event':
      return onPageEvent(msg.evt, sender);
    case 'get-alerts':
      return (await getState(msg.tabId)).alerts;
    case 'clear':
      return resetTab(msg.tabId);
    case 'get-blocking':
      return (await chrome.storage.local.get('blocking')).blocking === true;
    case 'set-blocking':
      return setBlocking(Boolean(msg.enabled));
    case 'page-capture':
      return onPageCapture(msg.cap, sender);
    case 'page-trace':
      return sender.tab && logEvent(sender.tab.id, { ...msg.trace, frameId: sender.frameId || 0 });
    default:
      return handleRecorderMessage(msg);
  }
}

// Code reçu par la page (corps de new Function, module WebAssembly, script de Worker) :
// enregistré avec son SHA-256, et signalé quand c'est un cadre qui le reçoit.
async function onPageCapture(cap, sender) {
  const tabId = sender.tab ? sender.tab.id : -1;
  if (tabId < 0 || !cap) return undefined;
  const stored = await storeCapture(tabId, { ...cap, frameId: sender.frameId || 0 }, sender.tab.url);
  if (stored && cap.inFrame) {
    await addAlert(tabId, {
      type: 'payload-captured',
      severity: 'high',
      detail: `Code reçu par un cadre et enregistré (${cap.kind}, ${Math.round(stored.size / 1024)} Ko, SHA-256 ${stored.sha256.slice(0, 16)}…)`,
      source: cap.source,
      frame: cap.frame,
      inFrame: true,
      frameId: sender.frameId || 0,
      origin: 'capture',
      key: `payload-captured|${stored.sha256}`
    });
  }
  return stored;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse, () => sendResponse(undefined));
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
  chrome.storage.session.remove(storageKey(tabId));
});
