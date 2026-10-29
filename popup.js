const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const SEVERITY_LABEL = { low: 'Faible', medium: 'Moyen', high: 'Élevé', critical: 'Critique' };
const SEVERITY_COLOR = { low: '#607d8b', medium: '#b7860b', high: '#e65100', critical: '#b00020' };

const TYPE_INFO = {
  'ioc-domain': {
    label: 'Domaine malveillant connu',
    why: 'Ce domaine figure dans les indicateurs publiés par Confiant et le Citizen Lab.'
  },
  'spy-sdk-pattern': {
    label: 'Comportement de SDK espion',
    why: 'Un même cadre relève l\'empreinte de l\'appareil puis exécute ou reçoit du code à distance : c\'est le schéma du SDK Discover-Tech.'
  },
  'cookie-exfil': {
    label: 'Exfiltration de cookies',
    why: 'Les cookies de la page partent dans l\'URL d\'un tiers ; ils peuvent contenir des sessions connectées.'
  },
  'doh-from-page': {
    label: 'DNS chiffré depuis la page',
    why: 'Une page n\'a pas besoin de faire ses propres requêtes DNS : cela sert à cacher un domaine aux filtres DNS.'
  },
  'raw-ip': {
    label: 'Contact d\'une IP brute',
    why: 'Joindre une IP sans nom de domaine évite les listes de blocage et la surveillance DNS.'
  },
  'dynamic-code': {
    label: 'Code exécuté dynamiquement',
    why: 'new Function() permet d\'exécuter du code reçu d\'un serveur, par exemple un exploit envoyé par un C2.'
  },
  'websocket': {
    label: 'Canal WebSocket',
    why: 'Un canal persistant permet à un serveur d\'envoyer des ordres en continu, hors des requêtes HTTP classiques.'
  },
  'webrtc': {
    label: 'Connexion WebRTC',
    why: 'WebRTC peut révéler la vraie IP derrière un VPN ou servir de canal discret.'
  },
  'cookie-read': {
    label: 'Lecture des cookies',
    why: 'Un script tiers ou un cadre publicitaire lit les cookies du site.'
  },
  'canvas-fp': {
    label: 'Empreinte canvas',
    why: 'Le rendu graphique sert à identifier l\'appareil de façon unique.'
  },
  'webgl-fp': {
    label: 'Empreinte WebGL',
    why: 'Le modèle exact de carte graphique aide à identifier l\'appareil et à choisir un exploit adapté.'
  },
  'battery-fp': {
    label: 'Empreinte batterie',
    why: 'L\'état de la batterie est un signal d\'empreinte utilisé par le SDK.'
  },
  'behavior-tracking': {
    label: 'Surveillance du comportement',
    why: 'Suivre souris, clavier et défilement depuis une pub permet de distinguer un humain d\'un robot d\'analyse.'
  },
  'ad-loader': {
    label: 'Chargeur /getAd',
    why: 'Chemin utilisé par les serveurs NOAS de Discover-Tech ; courant aussi chez des régies légitimes.'
  },
  'cloudfront-frame': {
    label: 'Cadre CloudFront anonyme',
    why: 'Candiru livrait son code via des hôtes CloudFront renouvelés tous les quelques jours.'
  },
  'unknown-profiler': {
    label: 'Script tiers qui profile',
    why: 'Un domaine extérieur au site relève l\'empreinte de l\'appareil et lit les cookies : il peut te reconnaître d\'un site à l\'autre.'
  },
  'payload-captured': {
    label: 'Code capturé',
    why: 'Le code reçu par ce cadre est enregistré avec son SHA-256 : ouvre l\'enregistreur pour l\'analyser ou le soumettre à VirusTotal.'
  },
  'wasm': {
    label: 'Module WebAssembly',
    why: 'Beaucoup d\'exploits de navigateur récents passent par WebAssembly ; le module est capturé.'
  },
  'heap-spray': {
    label: 'Pulvérisation mémoire',
    why: 'Des centaines de grands tampons alloués en rafale : technique classique pour exploiter une faille mémoire.'
  },
  'blob-worker': {
    label: 'Worker généré',
    why: 'Un thread lancé depuis du code fabriqué à la volée ; son script est capturé.'
  },
  'shared-memory': {
    label: 'Mémoire partagée',
    why: 'SharedArrayBuffer sert à certaines attaques de concurrence entre threads.'
  }
};

const INHERITED_ORIGIN_NOTE =
  'Ce cadre about:blank hérite de l\'origine du site : le code de la pub voit les cookies et le stockage du site, comme décrit par Confiant.';

const $ = (id) => document.getElementById(id);
let currentTab;
let currentAlerts = [];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function render(alerts) {
  currentAlerts = alerts || [];
  // Les scripts de confiance passent en dernier ; ils ne comptent pas dans le verdict.
  const sorted = [...currentAlerts].sort((a, b) =>
    Number(Boolean(a.trusted)) - Number(Boolean(b.trusted)) ||
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.lastTs - a.lastTs);

  const list = $('alerts');
  list.replaceChildren();
  for (const a of sorted) {
    const info = TYPE_INFO[a.type] || { label: a.type, why: '' };
    const li = el('li', a.trusted ? 'low trusted' : a.severity);
    const title = el('div', 'title');
    title.append(el('span', '', info.label + (a.count > 1 ? ` ×${a.count}` : '')),
      el('span', 'sev', a.trusted ? 'Confiance' : SEVERITY_LABEL[a.severity] || a.severity));
    li.append(title, el('div', 'detail', a.detail));
    if (info.why && !a.trusted) li.append(el('div', 'why', info.why));
    if (a.trusted) li.append(el('div', 'why', 'Script connu et légitime : signalé pour information seulement.'));
    if (a.inheritsOrigin) li.append(el('div', 'why', INHERITED_ORIGIN_NOTE));
    const time = new Date(a.lastTs || a.ts).toLocaleTimeString('fr-FR');
    const where = a.inheritsOrigin ? a.frame : a.inFrame ? 'dans un cadre' : 'page principale';
    li.append(el('div', 'meta', `${time} · ${a.origin || 'page'} · ${where} · source : ${a.source || '?'}`));
    list.append(li);
  }

  const counted = sorted.filter((a) => !a.trusted);
  $('empty').hidden = sorted.length > 0;

  const worst = counted.length ? counted[0].severity : null;
  const verdict = $('verdict');
  verdict.textContent = worst ? `${counted.length} alerte${counted.length > 1 ? 's' : ''} · ${SEVERITY_LABEL[worst]}` : 'RAS';
  verdict.style.background = worst ? SEVERITY_COLOR[worst] : '#2e7d32';
}

async function refresh() {
  render(await chrome.runtime.sendMessage({ kind: 'get-alerts', tabId: currentTab.id }));
}

async function init() {
  [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try {
    $('host').textContent = new URL(currentTab.url).host || currentTab.url;
  } catch {
    $('host').textContent = '';
  }

  $('blocking').checked = await chrome.runtime.sendMessage({ kind: 'get-blocking' });
  $('blocking').addEventListener('change', (e) =>
    chrome.runtime.sendMessage({ kind: 'set-blocking', enabled: e.target.checked }));

  $('clear').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ kind: 'clear', tabId: currentTab.id });
    render([]);
  });

  $('export').addEventListener('click', () => {
    const report = { page: currentTab.url, exportedAt: new Date().toISOString(), alerts: currentAlerts };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `adsentinel-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  $('recording').checked = await chrome.runtime.sendMessage({ kind: 'get-recording' });
  $('recording').addEventListener('change', (e) =>
    chrome.runtime.sendMessage({ kind: 'set-recording', enabled: e.target.checked }));
  $('open-recorder').addEventListener('click', () =>
    chrome.tabs.create({ url: chrome.runtime.getURL('recorder.html') }));

  await refresh();
  // Les alertes continuent d'arriver pendant que le popup est ouvert.
  setInterval(refresh, 1500);
}

init();
