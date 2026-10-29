// Faux objet `chrome` minimal pour exécuter background.js sous Node.

// Zone de stockage qui se comporte comme chrome.storage : get par clé, liste de clés ou
// null (tout), valeurs copiées à l'écriture et à la lecture.
function storageArea() {
  const data = {};
  const pick = (keys) => {
    if (keys === null || keys === undefined) return structuredClone(data);
    const list = Array.isArray(keys) ? keys : [keys];
    const out = {};
    for (const k of list) if (k in data) out[k] = structuredClone(data[k]);
    return out;
  };
  return {
    data,
    get: async (keys) => pick(keys),
    set: async (o) => { for (const [k, v] of Object.entries(o)) data[k] = structuredClone(v); },
    remove: async (keys) => { for (const k of [].concat(keys)) delete data[k]; }
  };
}

export function installChromeStub() {
  const listener = (name) => ({ addListener: (f) => { stub.listeners[name] = f; } });
  const stub = {
    listeners: {},
    badges: {},
    sentNotifications: [],
    dynamicRules: null,
    storage: { session: storageArea(), local: storageArea() },
    action: {
      setBadgeText: async ({ tabId, text }) => { (stub.badges[tabId] ||= {}).text = text; },
      setBadgeBackgroundColor: async ({ tabId, color }) => { (stub.badges[tabId] ||= {}).color = color; }
    },
    webRequest: {
      onBeforeRequest: listener('request'),
      onBeforeRedirect: listener('redirect'),
      onCompleted: listener('completed'),
      onErrorOccurred: listener('error')
    },
    webNavigation: {
      onCommitted: listener('committed'),
      onCreatedNavigationTarget: listener('navigationTarget')
    },
    runtime: { onMessage: listener('message') },
    tabs: { onRemoved: listener('removed'), create: async () => ({}) },
    notifications: {
      create: async (id, opts) => { stub.sentNotifications.push({ id, ...opts }); return id; }
    },
    declarativeNetRequest: {
      updateDynamicRules: async (r) => { stub.dynamicRules = r; }
    }
  };
  globalThis.chrome = stub;
  return stub;
}

export const tick = (ms = 10) => new Promise((r) => setTimeout(r, ms));

export function sendMessage(stub, msg, sender = {}) {
  return new Promise((resolve) => stub.listeners.message(msg, sender, resolve));
}
