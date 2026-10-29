// Page Enregistreur : rejoue le journal d'une visite (chronologie, arbre des cadres)
// et donne accès au code capturé. Tout ce qui vient des sites est affiché en texte brut.
const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

const KIND_LABEL = {
  request: 'Requête', redirect: 'Redirection', response: 'Réponse', error: 'Erreur',
  frame: 'Cadre', popup: 'Pop-up', alert: 'Alerte', capture: 'Capture', ws: 'WebSocket'
};

let currentSession = null;
let currentCapture = null;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatTime(ts) {
  return new Date(ts).toLocaleString('fr-FR');
}

function formatSize(n) {
  return n >= 1024 ? `${(n / 1024).toFixed(1)} Ko` : `${n} o`;
}

function download(name, data, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([data], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// --- Visites ----------------------------------------------------------------

async function loadSessions() {
  const sessions = await send({ kind: 'list-sessions' });
  const list = $('session-list');
  list.replaceChildren();
  $('no-session').hidden = sessions.length > 0;
  for (const s of sessions) {
    const li = el('li');
    li.append(el('div', '', s.url));
    li.append(el('div', 'meta',
      `${formatTime(s.startedAt)} · ${s.events} événements · ${s.alerts} alertes · ${s.captures} captures`));
    if (currentSession && currentSession.id === s.id) li.classList.add('active');
    li.addEventListener('click', () => openSession(s.id));
    list.append(li);
  }
}

async function openSession(id) {
  currentSession = await send({ kind: 'get-session', id });
  for (const li of $('session-list').children) li.classList.remove('active');
  await loadSessions();
  renderSession();
}

function frameLabel(frames, frameId) {
  if (frameId === undefined || frameId === null) return '';
  return frameId === 0 ? 'page' : `cadre #${frameId}`;
}

function renderFrameTree(frames) {
  const byParent = {};
  for (const [id, f] of Object.entries(frames)) {
    (byParent[f.parentFrameId] ||= []).push({ id: Number(id), ...f });
  }
  const build = (parentId) => {
    const children = byParent[parentId] || [];
    if (!children.length) return null;
    const ul = el('ul', 'tree');
    for (const f of children) {
      const li = el('li');
      li.append(el('span', 'fid', `#${f.id} `), el('span', 'mono', f.url || '(sans URL)'));
      const sub = build(f.id);
      if (sub) li.append(sub);
      ul.append(li);
    }
    return ul;
  };
  return build(-1) || el('p', 'muted', 'Aucun cadre enregistré.');
}

function describeEvent(e) {
  switch (e.kind) {
    case 'request': return [e.url, `${e.method || ''} ${e.type || ''}`.trim()];
    case 'redirect': return [`${e.url}  →  ${e.to}`, `HTTP ${e.status}`];
    case 'response': return [e.url, `HTTP ${e.status}${e.ip ? ` · ${e.ip}` : ''}${e.fromCache ? ' · cache' : ''}`];
    case 'error': return [e.url, e.error];
    case 'frame': return [e.url, `cadre #${e.frameId} dans #${e.parentFrameId}`];
    case 'popup': return [e.url, `nouvel onglet #${e.newTabId}`];
    case 'alert': return [e.detail, `${e.alertType} · ${e.severity}${e.source ? ` · ${e.source}` : ''}`];
    case 'capture': return [`${e.captureKind} · ${formatSize(e.size)} · ${e.sha256}`, e.source || ''];
    case 'ws': return [`${e.direction === 'in' ? 'reçu de' : 'envoyé à'} ${e.url} · ${formatSize(e.size)}`, e.preview || ''];
    default: return [JSON.stringify(e), ''];
  }
}

function renderSession() {
  const s = currentSession;
  const root = $('session-detail');
  root.replaceChildren();
  if (!s) {
    root.append(el('p', 'muted empty', 'Visite introuvable.'));
    return;
  }

  root.append(el('h2', '', s.url));
  const stats = el('div', 'stats');
  const count = (k) => s.events.filter((e) => e.kind === k).length;
  for (const [label, value] of [
    ['Événements', s.events.length], ['Cadres', Object.keys(s.frames).length], ['Alertes', count('alert')],
    ['Captures', count('capture')], ['Redirections', count('redirect')], ['Pop-ups', count('popup')]
  ]) {
    const d = el('div');
    d.append(el('strong', '', String(value)), el('span', 'muted', label));
    stats.append(d);
  }
  root.append(stats);
  if (s.dropped) root.append(el('p', 'muted', `${s.dropped} événements au-delà de la limite n'ont pas été gardés.`));

  const exportBtn = el('button', '', 'Exporter la visite (JSON)');
  exportBtn.addEventListener('click', exportSession);
  root.append(exportBtn);

  root.append(el('h2', '', 'Arbre des cadres'), renderFrameTree(s.frames));

  root.append(el('h2', '', 'Chronologie'));
  const filters = el('div', 'filters');
  const kinds = Object.keys(KIND_LABEL);
  const checks = {};
  for (const k of kinds) {
    const label = el('label');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = k !== 'response';
    checks[k] = box;
    label.append(box, document.createTextNode(KIND_LABEL[k]));
    filters.append(label);
  }
  const frameSelect = document.createElement('select');
  frameSelect.append(new Option('Tous les cadres', 'all'), new Option('Cadres uniquement (hors page)', 'frames'));
  for (const id of Object.keys(s.frames).map(Number).sort((a, b) => a - b)) {
    frameSelect.append(new Option(frameLabel(s.frames, id), String(id)));
  }
  const search = document.createElement('input');
  search.type = 'search';
  search.placeholder = 'Filtrer (domaine, mot…)';
  filters.append(frameSelect, search);
  root.append(filters);

  const table = el('table', 'grid');
  const head = el('thead');
  const hr = el('tr');
  for (const h of ['+ms', 'Cadre', 'Type', 'Détail', '']) hr.append(el('th', '', h));
  head.append(hr);
  const body = el('tbody');
  table.append(head, body);
  root.append(table);

  const draw = () => {
    body.replaceChildren();
    const q = search.value.trim().toLowerCase();
    const frameFilter = frameSelect.value;
    let shown = 0;
    for (const e of s.events) {
      if (!checks[e.kind] || !checks[e.kind].checked) continue;
      if (frameFilter === 'frames' && !e.frameId) continue;
      if (frameFilter !== 'all' && frameFilter !== 'frames' && String(e.frameId) !== frameFilter) continue;
      const [main, extra] = describeEvent(e);
      if (q && !`${main} ${extra}`.toLowerCase().includes(q)) continue;
      if (++shown > 2000) break;
      const tr = el('tr', e.kind === 'alert' ? `alert ${e.severity}` : e.kind === 'capture' ? 'capture' : '');
      tr.append(el('td', 'mono', String(e.t)), el('td', '', frameLabel(s.frames, e.frameId)),
        el('td', 'kind', KIND_LABEL[e.kind] || e.kind));
      const td = el('td', 'url');
      td.append(el('div', 'mono', main || ''));
      if (extra) td.append(el('div', 'muted', extra));
      tr.append(td);
      const action = el('td');
      if (e.kind === 'capture') {
        const b = el('button', '', 'Voir');
        b.addEventListener('click', () => { showView('captures'); openCapture(e.sha256); });
        action.append(b);
      }
      tr.append(action);
      body.append(tr);
    }
    if (!shown) {
      const tr = el('tr');
      const td = el('td', 'muted', 'Aucun événement pour ces filtres.');
      td.colSpan = 5;
      tr.append(td);
      body.append(tr);
    }
  };
  for (const box of Object.values(checks)) box.addEventListener('change', draw);
  frameSelect.addEventListener('change', draw);
  search.addEventListener('input', draw);
  draw();
}

async function exportSession() {
  const s = currentSession;
  const hashes = [...new Set(s.events.filter((e) => e.kind === 'capture').map((e) => e.sha256))];
  const captures = [];
  for (const h of hashes) {
    const c = await send({ kind: 'get-capture', sha256: h });
    if (c) captures.push(c);
  }
  const report = { tool: 'AdSentinel', exportedAt: new Date().toISOString(), session: s, captures };
  download(`adsentinel-visite-${s.id}.json`, JSON.stringify(report, null, 2), 'application/json');
}

// --- Captures ---------------------------------------------------------------

async function loadCaptures() {
  const captures = await send({ kind: 'list-captures' });
  const rows = $('capture-rows');
  rows.replaceChildren();
  $('no-capture').hidden = captures.length > 0;
  for (const c of captures) {
    const tr = el('tr');
    const page = (c.sightings[0] && c.sightings[0].pageUrl) || '';
    tr.append(el('td', 'kind', c.kind), el('td', '', formatSize(c.size)), el('td', 'mono', c.sha256),
      el('td', '', `${c.count}×`), el('td', '', formatTime(c.firstSeen)), el('td', 'url', page));
    const td = el('td');
    const b = el('button', '', 'Voir');
    b.addEventListener('click', () => openCapture(c.sha256));
    td.append(b);
    tr.append(td);
    rows.append(tr);
  }
}

function hexDump(bytes, limit = 1024) {
  const lines = [];
  for (let i = 0; i < Math.min(bytes.length, limit); i += 16) {
    const chunk = bytes.subarray(i, i + 16);
    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (bytes.length > limit) lines.push(`… ${bytes.length - limit} octets de plus (télécharge le fichier pour tout voir)`);
  return lines.join('\n');
}

function captureBytes(c) {
  return c.encoding === 'base64'
    ? Uint8Array.from(atob(c.body), (ch) => ch.charCodeAt(0))
    : new TextEncoder().encode(c.body);
}

async function openCapture(sha256) {
  const c = await send({ kind: 'get-capture', sha256 });
  if (!c) return;
  currentCapture = c;
  $('capture-view').hidden = false;
  $('capture-title').textContent = `${c.kind} · ${formatSize(c.size)} · ${c.sha256}`;
  $('capture-vt').href = `https://www.virustotal.com/gui/file/${encodeURIComponent(c.sha256)}`;
  $('capture-body').textContent = c.encoding === 'base64' ? hexDump(captureBytes(c)) : c.body;
  $('capture-view').scrollIntoView({ behavior: 'smooth' });
}

function downloadCapture() {
  const c = currentCapture;
  if (!c) return;
  const ext = c.kind === 'wasm' ? 'wasm' : c.encoding === 'base64' ? 'bin' : 'js.txt';
  // Extension .js.txt : le fichier ne s'exécute pas par un double-clic.
  download(`capture-${c.kind}-${c.sha256.slice(0, 16)}.${ext}`, captureBytes(c), 'application/octet-stream');
}

// --- Navigation et commandes ------------------------------------------------

function showView(name) {
  for (const b of document.querySelectorAll('.tabs button')) b.classList.toggle('active', b.dataset.view === name);
  $('view-sessions').hidden = name !== 'sessions';
  $('view-captures').hidden = name !== 'captures';
  if (name === 'captures') loadCaptures();
}

async function init() {
  for (const b of document.querySelectorAll('.tabs button')) b.addEventListener('click', () => showView(b.dataset.view));
  $('recording').checked = await send({ kind: 'get-recording' });
  $('recording').addEventListener('change', (e) => send({ kind: 'set-recording', enabled: e.target.checked }));
  $('refresh').addEventListener('click', async () => {
    await loadSessions();
    if (currentSession) await openSession(currentSession.id);
    if (!$('view-captures').hidden) await loadCaptures();
  });
  $('clear-all').addEventListener('click', async () => {
    if (!confirm('Effacer toutes les visites enregistrées et tout le code capturé ?')) return;
    await send({ kind: 'clear-records' });
    currentSession = null;
    $('session-detail').replaceChildren(el('p', 'muted empty', 'Choisis une visite à gauche.'));
    $('capture-view').hidden = true;
    await loadSessions();
    await loadCaptures();
  });
  $('capture-download').addEventListener('click', downloadCapture);
  $('capture-close').addEventListener('click', () => { $('capture-view').hidden = true; });
  await loadSessions();
}

init();
