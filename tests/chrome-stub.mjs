// Faux objet `chrome` minimal pour exécuter background.js sous Node.
export function installChromeStub() {
  const session = {};
  const stub = {
    listeners: {},
    badges: {},
    sentNotifications: [],
    dynamicRules: null,
    storage: {
      session: {
        get: async (k) => ({ [k]: session[k] }),
        set: async (o) => { Object.assign(session, o); },
        remove: async (k) => { delete session[k]; }
      },
      local: { get: async () => ({}), set: async () => {} }
    },
    action: {
      setBadgeText: async ({ tabId, text }) => { (stub.badges[tabId] ||= {}).text = text; },
      setBadgeBackgroundColor: async ({ tabId, color }) => { (stub.badges[tabId] ||= {}).color = color; }
    },
    webRequest: { onBeforeRequest: { addListener: (f) => { stub.listeners.request = f; } } },
    runtime: { onMessage: { addListener: (f) => { stub.listeners.message = f; } } },
    tabs: { onRemoved: { addListener: (f) => { stub.listeners.removed = f; } } },
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

export const tick = () => new Promise((r) => setTimeout(r, 10));

export function sendMessage(stub, msg, sender = {}) {
  return new Promise((resolve) => stub.listeners.message(msg, sender, resolve));
}
