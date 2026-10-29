import { test } from 'node:test';
import assert from 'node:assert/strict';
import { installChromeStub, tick, sendMessage } from './chrome-stub.mjs';

const chrome = installChromeStub();
await import('../background.js');

const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
let nextTab = 500;

async function setRecording(enabled) {
  await sendMessage(chrome, { kind: 'set-recording', enabled });
}

async function newVisit(url = 'https://journal.example/article') {
  const tabId = nextTab++;
  chrome.listeners.request({ tabId, url, type: 'main_frame', frameId: 0, parentFrameId: -1, method: 'GET' });
  await tick();
  return tabId;
}

async function sessionOf(tabId) {
  const list = await sendMessage(chrome, { kind: 'list-sessions' });
  const summary = list.find((s) => s.tabId === tabId);
  return summary && sendMessage(chrome, { kind: 'get-session', id: summary.id });
}

test('sans mode enquête, aucune visite n\'est journalisée', async () => {
  await setRecording(false);
  const tabId = await newVisit();
  assert.equal(await sessionOf(tabId), undefined);
});

test('en mode enquête, la chaîne d\'une pub est journalisée : requête, redirection, cadre, réponse, pop-up', async () => {
  await setRecording(true);
  const tabId = await newVisit();
  chrome.listeners.request({ tabId, url: 'https://noas.mtrtb.com/getAd?impid=1', type: 'sub_frame', frameId: 7, parentFrameId: 0, method: 'GET', initiator: 'https://journal.example' });
  chrome.listeners.redirect({ tabId, frameId: 7, url: 'https://noas.mtrtb.com/getAd?impid=1', redirectUrl: 'https://d23625plpxg1yn.cloudfront.net/iframe', statusCode: 302 });
  chrome.listeners.committed({ tabId, frameId: 7, parentFrameId: 0, url: 'https://d23625plpxg1yn.cloudfront.net/iframe' });
  chrome.listeners.completed({ tabId, frameId: 7, url: 'https://d23625plpxg1yn.cloudfront.net/iframe', type: 'sub_frame', statusCode: 200, ip: '203.0.113.5', fromCache: false });
  chrome.listeners.navigationTarget({ sourceTabId: tabId, sourceFrameId: 7, tabId: 999, url: 'https://arnaque.example/' });
  await tick();

  const s = await sessionOf(tabId);
  const kinds = s.events.map((e) => e.kind);
  for (const k of ['request', 'redirect', 'frame', 'response', 'popup', 'alert']) {
    assert.ok(kinds.includes(k), `événement « ${k} » attendu, reçu : ${kinds.join(', ')}`);
  }
  assert.equal(s.frames[7].parentFrameId, 0);
  assert.match(s.frames[7].url, /cloudfront\.net/);
  const redirect = s.events.find((e) => e.kind === 'redirect');
  assert.equal(redirect.status, 302);
  assert.ok(s.events.every((e, i) => i === 0 || e.t >= s.events[i - 1].t), 'chronologie ordonnée');
});

test('le code reçu par un cadre est capturé avec son SHA-256 et signalé', async () => {
  await setRecording(true);
  const tabId = await newVisit();
  const sender = { tab: { id: tabId, url: 'https://journal.example/article' }, frameId: 7 };
  const cap = { kind: 'new-function', body: 'abc', encoding: 'text', source: 'https://pagead.trustlayersdk.com/sdk.js', inFrame: true };

  const first = await sendMessage(chrome, { kind: 'page-capture', cap }, sender);
  assert.equal(first.sha256, SHA256_ABC);
  assert.equal(first.isNew, true);
  const again = await sendMessage(chrome, { kind: 'page-capture', cap }, sender);
  assert.equal(again.isNew, false);

  const stored = await sendMessage(chrome, { kind: 'get-capture', sha256: SHA256_ABC });
  assert.equal(stored.body, 'abc');
  assert.equal(stored.count, 2);

  const alerts = await sendMessage(chrome, { kind: 'get-alerts', tabId });
  const captured = alerts.filter((a) => a.type === 'payload-captured');
  assert.equal(captured.length, 1);
  assert.equal(captured[0].count, 2);

  const s = await sessionOf(tabId);
  assert.ok(s.events.some((e) => e.kind === 'capture' && e.sha256 === SHA256_ABC));
});

test('un module WebAssembly en base64 est haché sur ses octets', async () => {
  const tabId = await newVisit();
  const bytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const expected = Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString('hex');
  const cap = { kind: 'wasm', body: Buffer.from(bytes).toString('base64'), encoding: 'base64', inFrame: false };
  const stored = await sendMessage(chrome, { kind: 'page-capture', cap }, { tab: { id: tabId, url: 'https://x.example/' }, frameId: 0 });
  assert.equal(stored.sha256, expected);
  assert.equal(stored.size, 8);
  const list = await sendMessage(chrome, { kind: 'list-captures' });
  const meta = list.find((c) => c.sha256 === expected);
  assert.equal(meta.kind, 'wasm');
  assert.equal(meta.body, undefined, 'la liste ne renvoie pas les corps');
});

test('les messages WebSocket sont journalisés', async () => {
  await setRecording(true);
  const tabId = await newVisit();
  await sendMessage(chrome, { kind: 'page-trace', trace: { kind: 'ws', direction: 'in', url: 'wss://c2.example/', size: 4096, preview: '8f 2a' } },
    { tab: { id: tabId }, frameId: 7 });
  await tick();
  const s = await sessionOf(tabId);
  const ws = s.events.find((e) => e.kind === 'ws');
  assert.equal(ws.size, 4096);
  assert.equal(ws.frameId, 7);
});

test('tout effacer supprime visites et captures', async () => {
  await sendMessage(chrome, { kind: 'clear-records' });
  assert.deepEqual(await sendMessage(chrome, { kind: 'list-sessions' }), []);
  assert.deepEqual(await sendMessage(chrome, { kind: 'list-captures' }), []);
});
