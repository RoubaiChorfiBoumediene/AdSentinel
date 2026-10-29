// Enregistreur forensique : journal complet de chaque visite (requêtes, redirections,
// réponses, arbre des cadres, pop-ups, alertes, messages WebSocket) et captures du code
// reçu par les cadres (new Function, WebAssembly, Workers), identifiées par leur SHA-256.
//
// Le journal n'est tenu qu'en « mode enquête » ; les captures de code sont toujours gardées,
// car le code d'un exploit n'est envoyé qu'une fois.

const MAX_EVENTS = 5000;
const MAX_SESSIONS = 30;
const MAX_CAPTURES = 200;
const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const SAVE_DELAY = 1000;

let recording = false;
const settingsReady = chrome.storage.local.get('recording')
  .then((r) => { recording = r.recording === true; });

// tabId -> session en cours { id, tabId, url, startedAt, events, frames, dropped }
const sessions = new Map();
const saveTimers = new Map();

// --- Sessions et journal ----------------------------------------------------

export async function startSession(tabId, url) {
  await settingsReady;
  if (!recording || tabId < 0) return;
  const startedAt = Date.now();
  const session = { id: `${tabId}-${startedAt}`, tabId, url, startedAt, events: [], frames: {}, dropped: 0 };
  session.frames[0] = { parentFrameId: -1, url, t: 0 };
  sessions.set(tabId, session);
  const { sessionIndex = [] } = await chrome.storage.local.get('sessionIndex');
  sessionIndex.unshift(summarize(session));
  const removed = sessionIndex.splice(MAX_SESSIONS);
  if (removed.length) await chrome.storage.local.remove(removed.map((s) => `journal:${s.id}`));
  await chrome.storage.local.set({ sessionIndex });
}

export async function logEvent(tabId, evt) {
  await settingsReady;
  const session = sessions.get(tabId);
  if (!recording || !session) return;
  if (session.events.length >= MAX_EVENTS) {
    session.dropped += 1;
    return;
  }
  session.events.push({ t: Date.now() - session.startedAt, ...evt });
  if (evt.kind === 'frame' && evt.frameId !== undefined && !session.frames[evt.frameId]) {
    session.frames[evt.frameId] = { parentFrameId: evt.parentFrameId, url: evt.url, t: Date.now() - session.startedAt };
  }
  scheduleSave(session);
}

function summarize(s) {
  return {
    id: s.id,
    tabId: s.tabId,
    url: s.url,
    startedAt: s.startedAt,
    events: s.events.length,
    alerts: s.events.filter((e) => e.kind === 'alert').length,
    captures: s.events.filter((e) => e.kind === 'capture').length
  };
}

function scheduleSave(session) {
  if (saveTimers.has(session.id)) return;
  saveTimers.set(session.id, setTimeout(() => {
    saveTimers.delete(session.id);
    saveSession(session);
  }, SAVE_DELAY));
}

async function saveSession(session) {
  const { sessionIndex = [] } = await chrome.storage.local.get('sessionIndex');
  const i = sessionIndex.findIndex((s) => s.id === session.id);
  if (i >= 0) sessionIndex[i] = summarize(session);
  await chrome.storage.local.set({ [`journal:${session.id}`]: session, sessionIndex });
}

// --- Captures ---------------------------------------------------------------

async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function toBytes(body, encoding) {
  if (encoding === 'base64') return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return new TextEncoder().encode(body);
}

// Enregistre le code reçu, dédoublonné par empreinte SHA-256 (celle que VirusTotal affiche).
export async function storeCapture(tabId, cap, pageUrl) {
  if (typeof cap.body !== 'string' || !cap.body) return null;
  const bytes = toBytes(cap.body, cap.encoding);
  if (bytes.length > MAX_CAPTURE_BYTES) return null;
  const hash = await sha256(bytes);
  const key = `cap:${hash}`;
  const { [key]: existing, captureIndex = [] } = await chrome.storage.local.get([key, 'captureIndex']);
  const sighting = { tabId, pageUrl, frame: cap.frame, source: cap.source, ts: Date.now() };

  let meta;
  if (existing) {
    existing.count += 1;
    existing.lastSeen = Date.now();
    if (existing.sightings.length < 10) existing.sightings.push(sighting);
    meta = existing;
  } else {
    meta = {
      sha256: hash,
      kind: cap.kind,
      encoding: cap.encoding || 'text',
      size: bytes.length,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      count: 1,
      inFrame: Boolean(cap.inFrame),
      sightings: [sighting],
      body: cap.body
    };
    captureIndex.unshift(hash);
    const evicted = captureIndex.splice(MAX_CAPTURES);
    if (evicted.length) await chrome.storage.local.remove(evicted.map((h) => `cap:${h}`));
  }
  await chrome.storage.local.set({ [key]: meta, captureIndex });
  await logEvent(tabId, {
    kind: 'capture', frameId: cap.frameId, sha256: hash, captureKind: cap.kind,
    size: bytes.length, source: cap.source, isNew: !existing
  });
  return { sha256: hash, size: bytes.length, isNew: !existing };
}

// --- Écouteurs réseau et navigation -----------------------------------------

export function initRecorder() {
  const urls = { urls: ['<all_urls>'] };
  chrome.webRequest.onBeforeRedirect.addListener((d) => {
    logEvent(d.tabId, { kind: 'redirect', frameId: d.frameId, url: d.url, to: d.redirectUrl, status: d.statusCode });
  }, urls);
  chrome.webRequest.onCompleted.addListener((d) => {
    logEvent(d.tabId, {
      kind: 'response', frameId: d.frameId, url: d.url, type: d.type,
      status: d.statusCode, ip: d.ip, fromCache: d.fromCache
    });
  }, urls);
  chrome.webRequest.onErrorOccurred.addListener((d) => {
    logEvent(d.tabId, { kind: 'error', frameId: d.frameId, url: d.url, error: d.error });
  }, urls);
  chrome.webNavigation.onCommitted.addListener((d) => {
    if (d.frameId === 0) return;
    logEvent(d.tabId, { kind: 'frame', frameId: d.frameId, parentFrameId: d.parentFrameId, url: d.url });
  });
  // Un pop-up ou un onglet ouvert par une pub : typique des redirections forcées.
  chrome.webNavigation.onCreatedNavigationTarget.addListener((d) => {
    logEvent(d.sourceTabId, {
      kind: 'popup', frameId: d.sourceFrameId, url: d.url, newTabId: d.tabId
    });
  });
  chrome.tabs.onRemoved.addListener((tabId) => {
    const session = sessions.get(tabId);
    if (session) saveSession(session);
    sessions.delete(tabId);
  });
}

// --- Accès depuis le popup et la page Enregistreur ---------------------------

export async function handleRecorderMessage(msg) {
  switch (msg.kind) {
    case 'get-recording':
      await settingsReady;
      return recording;
    case 'set-recording':
      recording = Boolean(msg.enabled);
      await chrome.storage.local.set({ recording });
      return recording;
    case 'list-sessions': {
      for (const s of sessions.values()) await saveSession(s);
      return (await chrome.storage.local.get('sessionIndex')).sessionIndex || [];
    }
    case 'get-session': {
      const live = [...sessions.values()].find((s) => s.id === msg.id);
      if (live) return live;
      const key = `journal:${msg.id}`;
      return (await chrome.storage.local.get(key))[key] || null;
    }
    case 'list-captures': {
      const { captureIndex = [] } = await chrome.storage.local.get('captureIndex');
      const all = await chrome.storage.local.get(captureIndex.map((h) => `cap:${h}`));
      return captureIndex.map((h) => all[`cap:${h}`]).filter(Boolean)
        .map(({ body, ...meta }) => meta);
    }
    case 'get-capture': {
      const key = `cap:${msg.sha256}`;
      return (await chrome.storage.local.get(key))[key] || null;
    }
    case 'clear-records': {
      const all = await chrome.storage.local.get(null);
      const keys = Object.keys(all).filter((k) => /^(journal:|cap:)/.test(k));
      await chrome.storage.local.remove([...keys, 'sessionIndex', 'captureIndex']);
      sessions.clear();
      return true;
    }
    default:
      return undefined;
  }
}
