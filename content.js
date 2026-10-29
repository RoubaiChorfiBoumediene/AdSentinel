// Relais entre les sondes de la page (inject.js, world MAIN) et le service worker.
// Trois canaux : les alertes, les captures de code et les traces du journal (messages WebSocket).
const KINDS = { alert: 'page-event', capture: 'page-capture', trace: 'page-trace' };

document.addEventListener('__adsentinel', (e) => {
  let evt;
  try {
    evt = JSON.parse(e.detail);
  } catch {
    return;
  }
  if (!evt || typeof evt !== 'object') return;
  const channel = evt.channel || 'alert';
  if (channel === 'alert' && typeof evt.type !== 'string') return;
  const kind = KINDS[channel];
  if (!kind) return;
  const msg = channel === 'alert' ? { kind, evt } : channel === 'capture' ? { kind, cap: evt } : { kind, trace: evt };
  chrome.runtime.sendMessage(msg).catch(() => {});
});
