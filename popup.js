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
  }
};

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
  const sorted = [...currentAlerts].sort((a, b) =>
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.lastTs - a.lastTs);

  const list = $('alerts');
  list.replaceChildren();
  for (const a of sorted) {
    const info = TYPE_INFO[a.type] || { label: a.type, why: '' };
    const li = el('li', a.severity);
    const title = el('div', 'title');
    title.append(el('span', '', info.label + (a.count > 1 ? ` ×${a.count}` : '')),
      el('span', 'sev', SEVERITY_LABEL[a.severity] || a.severity));
    li.append(title, el('div', 'detail', a.detail));
    if (info.why) li.append(el('div', 'why', info.why));
    const time = new Date(a.lastTs || a.ts).toLocaleTimeString('fr-FR');
    li.append(el('div', 'meta',
      `${time} · ${a.origin || 'page'} · ${a.inFrame ? 'dans un cadre' : 'page principale'} · source : ${a.source || '?'}`));
    list.append(li);
  }
  $('empty').hidden = sorted.length > 0;

  const worst = sorted.length ? sorted[0].severity : null;
  const verdict = $('verdict');
  verdict.textContent = worst ? `${sorted.length} alerte${sorted.length > 1 ? 's' : ''} · ${SEVERITY_LABEL[worst]}` : 'RAS';
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

  await refresh();
  // Les alertes continuent d'arriver pendant que le popup est ouvert.
  setInterval(refresh, 1500);
}

init();
