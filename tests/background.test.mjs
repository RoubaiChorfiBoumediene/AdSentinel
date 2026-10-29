import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installChromeStub, tick, sendMessage } from './chrome-stub.mjs';

const chrome = installChromeStub();
await import('../background.js');

let nextTab = 100;

// Ouvre une nouvelle page dans un onglet neuf, puis envoie des requêtes depuis un cadre.
async function visit(urls, { type = 'xmlhttprequest', frameId = 3 } = {}) {
  const tabId = nextTab++;
  chrome.listeners.request({ tabId, url: 'http://localhost:8000/page.html', type: 'main_frame', frameId: 0 });
  await tick();
  for (const url of urls) {
    chrome.listeners.request({ tabId, url, type, frameId, initiator: 'http://localhost:8000' });
  }
  await tick();
  return tabId;
}

async function alertTypes(tabId) {
  const alerts = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  return alerts.map((a) => a.type);
}

test('un domaine IOC déclenche une alerte critique, sous-domaines compris', async () => {
  const tabId = await visit(['https://noas.mtrtb.com/getAd?x=1']);
  const types = await alertTypes(tabId);
  assert.ok(types.includes('ioc-domain'));
  assert.ok(types.includes('ad-loader'));
  assert.equal(chrome.badges[tabId].color, '#b00020');
});

test('les cookies envoyés dans une URL sont détectés', async () => {
  const jar = encodeURIComponent('_ga=GA1.2.1~~~session_id=abc');
  const tabId = await visit([`https://pixel.example.invalid/p?cookie=${jar}`]);
  assert.deepEqual(await alertTypes(tabId), ['cookie-exfil']);
});

test('DNS chiffré et IP publique brute sont détectés', async () => {
  const tabId = await visit([
    'https://doh.example.invalid/dns-query?name=c2.example&type=A',
    'https://203.0.113.10/ping'
  ]);
  assert.deepEqual((await alertTypes(tabId)).sort(), ['doh-from-page', 'raw-ip']);
});

test('aucune alerte pour une IP privée ou une URL ordinaire', async () => {
  const tabId = await visit([
    'https://192.168.1.1/admin',
    'https://www.google.com/search?q=cookie',
    'https://cdn.example.com/app.js'
  ]);
  assert.deepEqual(await alertTypes(tabId), []);
  assert.equal(chrome.badges[tabId].text, '');
});

test('empreinte + contrôle à distance dans un cadre = motif de SDK espion', async () => {
  const tabId = await visit([]);
  const sender = { tab: { id: tabId }, frameId: 5 };
  for (const type of ['canvas-fp', 'webgl-fp', 'dynamic-code']) {
    await sendMessage(chrome, {
      kind: 'page-event',
      evt: { type, severity: 'high', detail: type, inFrame: true, source: 'about:srcdoc' }
    }, sender);
  }
  assert.ok((await alertTypes(tabId)).includes('spy-sdk-pattern'));
});

test('pas de motif SDK sans exécution de code distant', async () => {
  const tabId = await visit([]);
  const sender = { tab: { id: tabId }, frameId: 5 };
  for (const type of ['canvas-fp', 'webgl-fp', 'battery-fp']) {
    await sendMessage(chrome, {
      kind: 'page-event',
      evt: { type, severity: 'low', detail: type, inFrame: true }
    }, sender);
  }
  assert.ok(!(await alertTypes(tabId)).includes('spy-sdk-pattern'));
});

test('une seule notification par type critique et par page', async () => {
  const before = chrome.sentNotifications.length;
  const tabId = await visit([
    'https://noas.mtrtb.com/getAd?a=1',
    'https://cookie-sync.xyz/sync',
    'https://tracookiepixel.xyz/p'
  ]);
  const sent = chrome.sentNotifications.slice(before);
  assert.equal(sent.length, 1);
  assert.match(sent[0].id, new RegExp(`adsentinel-${tabId}-ioc-domain`));
});

test('les alertes identiques sont regroupées avec un compteur', async () => {
  const tabId = await visit(['https://203.0.113.10/a', 'https://203.0.113.10/a']);
  const alerts = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].count, 2);
});

test('côté réseau, des URL différentes vers le même hôte font une seule alerte', async () => {
  const tabId = await visit(['https://203.0.113.10/a?x=1', 'https://203.0.113.10/b?y=2']);
  const alerts = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].count, 2);
});

// Événements de page tels que les envoie inject.js sur https://anime-sama.to/
async function pageEvents(events, pageUrl = 'https://anime-sama.to/') {
  const tabId = await visit([]);
  for (const { frameId = 0, ...evt } of events) {
    await sendMessage(chrome, { kind: 'page-event', evt },
      { tab: { id: tabId, url: pageUrl }, frameId });
  }
  return tabId;
}

const GTM = 'https://www.googletagmanager.com/gtag/js?id=G-TEST';
const POPUNDER = 'https://chagnougroalry.net/5/7809940/?bnr=1&dmn=a-zzz.com';

test('un même script qui relit les cookies ne crée qu\'une alerte', async () => {
  const tabId = await pageEvents([
    { type: 'cookie-read', severity: 'medium', detail: 'Lecture (1 cookies)', source: 'https://tiers.example/a.js', inFrame: false },
    { type: 'cookie-read', severity: 'medium', detail: 'Lecture (2 cookies)', source: 'https://tiers.example/a.js', inFrame: false }
  ]);
  const alerts = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].count, 2);
  assert.equal(alerts[0].detail, 'Lecture (2 cookies)');
});

test('Google Tag Manager passe en confiance et ne compte pas dans le badge', async () => {
  const tabId = await pageEvents([
    { type: 'cookie-read', severity: 'medium', detail: 'gtm', source: GTM, inFrame: false }
  ]);
  const [alert] = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  assert.equal(alert.trusted, true);
  assert.equal(alert.severity, 'low');
  assert.equal(chrome.badges[tabId].text, '');
});

test('un script de confiance ne bénéficie pas de la confiance pour du code dynamique', async () => {
  const tabId = await pageEvents([
    { type: 'dynamic-code', severity: 'high', detail: 'fn', source: GTM, inFrame: true }
  ]);
  const [alert] = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  assert.equal(alert.trusted, undefined);
  assert.equal(alert.severity, 'high');
});

test('cas anime-sama : un popunder qui prend l\'empreinte et lit les cookies est signalé', async () => {
  const tabId = await pageEvents([
    { type: 'webgl-fp', severity: 'low', detail: 'webgl', source: 'https://acscdn.com/script/aclib.js', inFrame: false },
    { type: 'battery-fp', severity: 'low', detail: 'batterie', source: POPUNDER, inFrame: true, inheritsOrigin: true, frameId: 177 },
    { type: 'cookie-read', severity: 'high', detail: 'cookies', source: POPUNDER, inFrame: true, inheritsOrigin: true, frameId: 177 }
  ]);
  const alerts = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  const profilers = alerts.filter((a) => a.type === 'unknown-profiler');
  assert.equal(profilers.length, 1, 'acscdn (empreinte seule) ne doit pas être signalé');
  assert.match(profilers[0].detail, /chagnougroalry\.net/);
  assert.equal(profilers[0].severity, 'high');
  assert.equal(profilers[0].inheritsOrigin, true);
});

test('un script du site lui-même n\'est pas un profileur tiers', async () => {
  const tabId = await pageEvents([
    { type: 'canvas-fp', severity: 'low', detail: 'c', source: 'https://cdn.anime-sama.to/app.js', inFrame: false },
    { type: 'cookie-read', severity: 'medium', detail: 'k', source: 'https://cdn.anime-sama.to/app.js', inFrame: false }
  ]);
  assert.ok(!(await alertTypes(tabId)).includes('unknown-profiler'));
});

test('le blocage installe une règle DNR sur la liste IOC', async () => {
  await sendMessage(chrome, { kind: 'set-blocking', enabled: true });
  const rule = chrome.dynamicRules.addRules[0];
  assert.equal(rule.action.type, 'block');
  assert.ok(rule.condition.requestDomains.includes('mtrtb.com'));
  await sendMessage(chrome, { kind: 'set-blocking', enabled: false });
  assert.deepEqual(chrome.dynamicRules.addRules, []);
});
