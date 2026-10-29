// Service worker : analyse les requêtes réseau, reçoit les événements des sondes,
// corrèle les signaux par cadre et tient le compteur d'alertes de chaque onglet.
import { IOC_DOMAINS, DOH_HOSTS } from './iocs.js';

const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const BADGE_COLOR = { low: '#607d8b', medium: '#f9a825', high: '#e65100', critical: '#b00020' };
const MAX_ALERTS = 300;
const BLOCK_RULE_ID = 1;

const FINGERPRINT_TYPES = new Set(['canvas-fp', 'webgl-fp', 'battery-fp', 'behavior-tracking']);
const CONTROL_TYPES = new Set(['dynamic-code', 'websocket']);

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
  const existing = state.alerts.find((a) => a.type === alert.type && a.detail === alert.detail);
  if (existing) {
    existing.count += 1;
    existing.lastTs = Date.now();
  } else {
    state.alerts.push({ ...alert, count: 1, ts: alert.ts || Date.now(), lastTs: Date.now() });
    if (state.alerts.length > MAX_ALERTS) state.alerts.shift();
  }
  await chrome.storage.session.set({ [storageKey(tabId)]: state });
  await updateBadge(tabId, state.alerts);
}

async function updateBadge(tabId, alerts) {
  try {
    const worst = alerts.reduce((w, a) =>
      (SEVERITY_RANK[a.severity] > SEVERITY_RANK[w] ? a.severity : w), 'low');
    await chrome.action.setBadgeText({ tabId, text: alerts.length ? String(alerts.length) : '' });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLOR[worst] });
  } catch {
    // L'onglet a pu être fermé entre-temps.
  }
}

// --- Analyse réseau ---------------------------------------------------------

function matchesDomain(host, list) {
  return list.find((d) => host === d || host.endsWith('.' + d));
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
    resetTab(tabId).then(() => checkUrl(details));
    return;
  }
  checkUrl({ tabId, url, type, frameId, initiator });
}

function checkUrl({ tabId, url, type, frameId, initiator }) {
  let u;
  try { u = new URL(url); } catch { return; }
  const host = u.hostname;
  const base = { source: url.slice(0, 300), frame: `cadre #${frameId}`, inFrame: frameId !== 0, origin: 'réseau' };

  const ioc = matchesDomain(host, IOC_DOMAINS);
  if (ioc) {
    addAlert(tabId, { ...base, type: 'ioc-domain', severity: 'critical',
      detail: `Requête vers un domaine de l'infrastructure Discover-Tech / Candiru : ${host}` });
  }

  if (/\/getAd\b/i.test(u.pathname)) {
    addAlert(tabId, { ...base, type: 'ad-loader', severity: 'medium',
      detail: `Chargeur publicitaire /getAd (schéma Discover-Tech) sur ${host}` });
  }

  if (matchesDomain(host, DOH_HOSTS) || u.pathname === '/dns-query' ||
      (host === 'dns.google' && u.pathname.startsWith('/resolve'))) {
    addAlert(tabId, { ...base, type: 'doh-from-page', severity: 'high',
      detail: `Résolution DNS chiffrée lancée par la page : ${host}${u.pathname}` });
  }

  if (isPublicIPv4(host) && type !== 'main_frame') {
    let pageHost = '';
    try { pageHost = initiator ? new URL(initiator).hostname : ''; } catch {}
    if (!isPublicIPv4(pageHost)) {
      addAlert(tabId, { ...base, type: 'raw-ip', severity: 'high',
        detail: `Contact direct d'une adresse IP sans nom de domaine : ${host}` });
    }
  }

  const query = safeDecode(u.search);
  if (/[?&]cookies?=/i.test(u.search) &&
      (query.includes('~~~') || /(_ga|_gid|__gads|_pbjs|sess|token|jwt)/i.test(query))) {
    addAlert(tabId, { ...base, type: 'cookie-exfil', severity: 'high',
      detail: `Cookies de la page envoyés dans une URL vers ${host}` });
  }

  if (host.endsWith('.cloudfront.net') && type === 'sub_frame' && !ioc) {
    addAlert(tabId, { ...base, type: 'cloudfront-frame', severity: 'low',
      detail: `Cadre chargé depuis un hôte CloudFront anonyme : ${host}` });
  }
}

chrome.webRequest.onBeforeRequest.addListener(analyzeRequest, { urls: ['<all_urls>'] });

// --- Événements des sondes et corrélation -----------------------------------

async function onPageEvent(evt, sender) {
  const tabId = sender.tab ? sender.tab.id : -1;
  if (tabId < 0 || !SEVERITY_RANK[evt.severity]) return;
  const frameId = sender.frameId || 0;
  await addAlert(tabId, { ...evt, origin: 'page', frameId });

  // Corrélation : empreinte + exécution de code distant dans le même cadre
  // = comportement typique du SDK décrit par Confiant.
  const state = await getState(tabId);
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
    default:
      return undefined;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender).then(sendResponse, () => sendResponse(undefined));
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
  chrome.storage.session.remove(storageKey(tabId));
});
