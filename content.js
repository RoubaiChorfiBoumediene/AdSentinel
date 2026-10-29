// Relais entre les sondes de la page (inject.js, world MAIN) et le service worker.
document.addEventListener('__adsentinel', (e) => {
  let evt;
  try {
    evt = JSON.parse(e.detail);
  } catch {
    return;
  }
  if (!evt || typeof evt.type !== 'string') return;
  chrome.runtime.sendMessage({ kind: 'page-event', evt }).catch(() => {});
});
