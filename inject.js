// Sondes exécutées dans le contexte de la page (world MAIN), dans chaque cadre.
// Elles enveloppent les API utilisées par le SDK Discover-Tech et signalent leur usage
// au script isolé (content.js) via un événement DOM.
(() => {
  'use strict';
  const FLAG = Symbol.for('adsentinel.installed');
  if (window[FLAG]) return;
  window[FLAG] = true;

  const inFrame = window !== window.top;
  // Un cadre about:blank ou srcdoc hérite de l'origine du site : il voit ses cookies et son stockage.
  // location.origin vaut "null" dans about:blank ; self.origin donne l'origine réellement héritée.
  const inheritsOrigin = inFrame && /^about:(blank|srcdoc)/.test(location.href);
  const pageOrigin = self.origin;
  let pageHost = '';
  try { pageHost = new URL(pageOrigin).hostname; } catch {}
  const frameLabel = inheritsOrigin
    ? `${location.href.split('#')[0]} (origine héritée : ${pageOrigin})`
    : location.href.slice(0, 200);
  const counts = Object.create(null);
  const MAX_PER_TYPE = 5;

  // Retrouve l'URL du script appelant à partir de la pile d'appels
  // (les cadres chrome-extension:// de nos propres sondes sont ignorés).
  function callerScript() {
    const stack = new Error().stack || '';
    const match = stack.match(/(?:https?:\/\/|about:srcdoc|file:\/\/\/)[^\s)]*/);
    return match ? match[0].replace(/:\d+(?::\d+)?$/, '') : '(inconnu)';
  }

  // Approximation du domaine enregistrable : "a.b.example.com" -> "example.com"
  function baseDomain(host) {
    return host.split('.').slice(-2).join('.');
  }

  function isThirdParty(src) {
    try {
      const host = new URL(src).hostname;
      return host !== '' && baseDomain(host) !== baseDomain(pageHost);
    } catch {
      return false;
    }
  }

  function emit(channel, payload) {
    document.dispatchEvent(new CustomEvent('__adsentinel', { detail: JSON.stringify({ channel, ...payload }) }));
  }

  function report(type, severity, detail, source = callerScript()) {
    counts[type] = (counts[type] || 0) + 1;
    if (counts[type] > MAX_PER_TYPE) return;
    emit('alert', {
      type,
      severity,
      detail: String(detail).slice(0, 300),
      source,
      frame: frameLabel,
      inFrame,
      inheritsOrigin,
      ts: Date.now()
    });
  }

  // Captures : le code reçu est envoyé en entier au service worker, qui calcule son SHA-256.
  // C'est la seule trace d'un exploit livré une fois, puis effacé.
  const MAX_CAPTURE_CHARS = 3 * 1024 * 1024;
  const MAX_CAPTURES_PER_FRAME = 50;
  const capturedSigs = new Set();
  function capture(kind, body, encoding = 'text', source = callerScript()) {
    if (!body || body.length > MAX_CAPTURE_CHARS || capturedSigs.size >= MAX_CAPTURES_PER_FRAME) return;
    const sig = `${kind}:${body.length}:${body.slice(0, 64)}`;
    if (capturedSigs.has(sig)) return;
    capturedSigs.add(sig);
    emit('capture', { kind, body, encoding, source, frame: frameLabel, inFrame, ts: Date.now() });
  }

  function toBase64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  }

  function hexPreview(u8) {
    return Array.from(u8.subarray(0, 32), (b) => b.toString(16).padStart(2, '0')).join(' ');
  }

  // Dans un cadre (emplacement publicitaire typique), un comportement est plus suspect.
  const inFrameOr = (base) => (inFrame ? 'high' : base);

  function hookConstructor(owner, name, onCall) {
    const Native = owner[name];
    if (typeof Native !== 'function') return;
    owner[name] = new Proxy(Native, {
      construct(target, args, newTarget) {
        try { onCall(args); } catch {}
        return Reflect.construct(target, args, newTarget);
      }
    });
  }

  function hookMethod(proto, name, onCall) {
    const native = proto && proto[name];
    if (typeof native !== 'function') return;
    proto[name] = new Proxy(native, {
      apply(target, thisArg, args) {
        try { onCall(args, thisArg); } catch {}
        return Reflect.apply(target, thisArg, args);
      }
    });
  }

  // 1. Exécution de code distant : le SDK compile le code envoyé par le C2 avec new Function(...)
  const NativeFunction = Function;
  const onDynamicCode = (args) => {
    const body = String(args.length ? args[args.length - 1] : '');
    const src = callerScript();
    report('dynamic-code', inFrameOr(body.length > 500 ? 'medium' : 'low'),
      `new Function() — ${body.length} caractères : ${body.slice(0, 120)}`, src);
    if (inFrame || isThirdParty(src)) {
      const params = args.slice(0, -1).map(String).join(', ');
      capture('new-function', `function anonymous(${params}) {\n${body}\n}`, 'text', src);
    }
  };
  const FunctionProxy = new Proxy(NativeFunction, {
    apply(target, thisArg, args) {
      try { onDynamicCode(args); } catch {}
      return Reflect.apply(target, thisArg, args);
    },
    construct(target, args, newTarget) {
      try { onDynamicCode(args); } catch {}
      return Reflect.construct(target, args, newTarget);
    }
  });
  window.Function = FunctionProxy;
  NativeFunction.prototype.constructor = FunctionProxy;

  // 2. Canaux persistants vers un C2 (WebSocket, WebRTC).
  // Chaque message est journalisé ; un message volumineux est capturé (bloc chiffré, code).
  const MAX_WS_TRACES = 50;
  const BIG_MESSAGE = 1000;
  function logWs(direction, url, data) {
    const t = { channel: 'trace', kind: 'ws', direction, url: String(url).slice(0, 300) };
    if (typeof data === 'string') {
      emit('trace', { ...t, size: data.length, preview: data.slice(0, 200) });
      if (data.length >= BIG_MESSAGE) capture(`websocket-${direction}`, data);
      return;
    }
    let u8 = null;
    if (data instanceof ArrayBuffer) u8 = new Uint8Array(data);
    else if (ArrayBuffer.isView(data)) u8 = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (u8) {
      emit('trace', { ...t, size: u8.length, preview: hexPreview(u8), binary: true });
      if (u8.length >= BIG_MESSAGE) capture(`websocket-${direction}`, toBase64(u8), 'base64');
    } else if (data instanceof Blob) {
      emit('trace', { ...t, size: data.size, preview: '(Blob)', binary: true });
      if (data.size >= BIG_MESSAGE) {
        data.arrayBuffer().then((b) => capture(`websocket-${direction}`, toBase64(new Uint8Array(b)), 'base64')).catch(() => {});
      }
    }
  }
  const NativeWebSocket = window.WebSocket;
  if (typeof NativeWebSocket === 'function') {
    window.WebSocket = new Proxy(NativeWebSocket, {
      construct(target, args, newTarget) {
        const ws = Reflect.construct(target, args, newTarget);
        try {
          report('websocket', inFrameOr('medium'), `WebSocket ouvert vers ${args[0]}`);
          let n = 0;
          ws.addEventListener('message', (e) => { if (n++ < MAX_WS_TRACES) logWs('in', ws.url, e.data); });
        } catch {}
        return ws;
      }
    });
    let sent = 0;
    hookMethod(NativeWebSocket.prototype, 'send', (args, ws) => {
      if (sent++ < MAX_WS_TRACES) logWs('out', ws.url, args[0]);
    });
  }
  hookConstructor(window, 'RTCPeerConnection', () =>
    report('webrtc', inFrameOr('low'), 'Connexion WebRTC créée (canal caché ou fuite d\'IP derrière un VPN)'));

  // 3. Lecture des cookies par un script tiers ou depuis un cadre
  const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (cookieDesc && cookieDesc.get) {
    Object.defineProperty(Document.prototype, 'cookie', {
      ...cookieDesc,
      get() {
        const value = cookieDesc.get.call(this);
        if (value) {
          const src = callerScript();
          if (inFrame || isThirdParty(src)) {
            const n = value.split(';').length;
            report('cookie-read', inFrameOr('medium'), inheritsOrigin
              ? `Un cadre ${location.href.split('#')[0]} lit les ${n} cookies de ${pageOrigin} (même origine que le site) via ${src}`
              : `Lecture de document.cookie (${n} cookies) par ${src}`, src);
          }
        }
        return value;
      }
    });
  }

  // 4. Empreinte de l'appareil
  hookMethod(HTMLCanvasElement.prototype, 'toDataURL', () =>
    report('canvas-fp', 'low', 'Export d\'un canvas (empreinte graphique)'));
  const UNMASKED = new Set([0x9245, 0x9246]); // UNMASKED_VENDOR_WEBGL, UNMASKED_RENDERER_WEBGL
  const onGlParam = (args) => {
    if (UNMASKED.has(args[0])) report('webgl-fp', 'low', 'Lecture du modèle exact de carte graphique (WebGL)');
  };
  hookMethod(window.WebGLRenderingContext && WebGLRenderingContext.prototype, 'getParameter', onGlParam);
  hookMethod(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype, 'getParameter', onGlParam);
  hookMethod(Navigator.prototype, 'getBattery', () =>
    report('battery-fp', 'low', 'Lecture de l\'état de la batterie (navigator.getBattery)'));

  // 5. Signes d'exploitation d'une faille du navigateur.
  // WebAssembly : très utilisé par les exploits récents ; le module est capturé en entier.
  const Wasm = window.WebAssembly;
  if (Wasm) {
    const onWasm = (src, how) => {
      let u8 = null;
      if (src instanceof ArrayBuffer) u8 = new Uint8Array(src);
      else if (ArrayBuffer.isView(src)) u8 = new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
      if (!u8) return;
      report('wasm', inFrameOr('low'), `Module WebAssembly compilé (${how}, ${u8.length} octets)`);
      capture('wasm', toBase64(u8), 'base64');
    };
    hookMethod(Wasm, 'compile', (args) => onWasm(args[0], 'compile'));
    hookMethod(Wasm, 'instantiate', (args) => onWasm(args[0], 'instantiate'));
    hookConstructor(Wasm, 'Module', (args) => onWasm(args[0], 'Module'));
    const onStreaming = (args, how) => {
      Promise.resolve(args[0]).then((r) => r.clone().arrayBuffer()).then((b) => onWasm(b, how)).catch(() => {});
    };
    hookMethod(Wasm, 'compileStreaming', (args) => onStreaming(args, 'compileStreaming'));
    hookMethod(Wasm, 'instantiateStreaming', (args) => onStreaming(args, 'instantiateStreaming'));
  }

  // Worker lancé depuis du code généré (blob: ou data:) : son script est récupéré et capturé.
  hookConstructor(window, 'Worker', (args) => {
    const url = String(args[0]);
    if (!/^(blob|data):/.test(url)) return;
    const src = callerScript();
    report('blob-worker', inFrameOr('medium'), `Worker lancé depuis du code généré (${url.slice(0, 60)})`, src);
    fetch(url).then((r) => r.text()).then((code) => capture('worker', code, 'text', src)).catch(() => {});
  });

  // Mémoire partagée : nécessaire à certaines attaques de concurrence.
  hookConstructor(window, 'SharedArrayBuffer', () =>
    report('shared-memory', inFrameOr('low'), 'SharedArrayBuffer créé (mémoire partagée entre threads)'));

  // Pulvérisation de la mémoire (« heap spraying ») depuis un cadre : des centaines de grands
  // tampons alloués en rafale pour placer des données à une adresse prévisible.
  if (inFrame) {
    const WINDOW_MS = 2000, BIG = 64 * 1024, MAX_COUNT = 500, MAX_TOTAL = 256 * 1024 * 1024;
    let windowStart = 0, count = 0, total = 0, flagged = false;
    const track = (bytes) => {
      if (flagged || !(bytes >= BIG)) return;
      const now = Date.now();
      if (now - windowStart > WINDOW_MS) { windowStart = now; count = 0; total = 0; }
      count += 1;
      total += bytes;
      if (count >= MAX_COUNT || total >= MAX_TOTAL) {
        flagged = true;
        report('heap-spray', 'high',
          `Pulvérisation mémoire : ${count} tampons de 64 Ko ou plus (${Math.round(total / 1048576)} Mo) en moins de 2 s`);
      }
    };
    hookConstructor(window, 'ArrayBuffer', (args) => track(Number(args[0])));
    for (const name of ['Uint8Array', 'Uint16Array', 'Uint32Array', 'Float32Array', 'Float64Array', 'BigUint64Array']) {
      const bytesPer = window[name] && window[name].BYTES_PER_ELEMENT;
      hookConstructor(window, name, (args) => {
        if (typeof args[0] === 'number') track(args[0] * bytesPer);
      });
    }
  }

  // 6. Surveillance du comportement depuis un cadre (souris, clavier, défilement…)
  if (inFrame) {
    const BEHAVIOR = new Set(['mousemove', 'pointermove', 'keydown', 'keyup', 'scroll',
      'touchstart', 'touchmove', 'visibilitychange', 'submit']);
    const seen = new Set();
    hookMethod(EventTarget.prototype, 'addEventListener', (args) => {
      const type = args[0];
      if (!BEHAVIOR.has(type) || seen.has(type)) return;
      seen.add(type);
      if (seen.size === 3) {
        report('behavior-tracking', 'medium',
          `Un cadre écoute plusieurs interactions de l'utilisateur : ${[...seen].join(', ')}`);
      }
    });
  }
})();
