// Sondes exécutées dans le contexte de la page (world MAIN), dans chaque cadre.
// Elles enveloppent les API utilisées par le SDK Discover-Tech et signalent leur usage
// au script isolé (content.js) via un événement DOM.
(() => {
  'use strict';
  const FLAG = Symbol.for('adsentinel.installed');
  if (window[FLAG]) return;
  window[FLAG] = true;

  const inFrame = window !== window.top;
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
      return host !== '' && baseDomain(host) !== baseDomain(location.hostname);
    } catch {
      return false;
    }
  }

  function report(type, severity, detail, source = callerScript()) {
    counts[type] = (counts[type] || 0) + 1;
    if (counts[type] > MAX_PER_TYPE) return;
    const evt = {
      type,
      severity,
      detail: String(detail).slice(0, 300),
      source,
      frame: location.href.slice(0, 200),
      inFrame,
      ts: Date.now()
    };
    document.dispatchEvent(new CustomEvent('__adsentinel', { detail: JSON.stringify(evt) }));
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
    report('dynamic-code', inFrameOr(body.length > 500 ? 'medium' : 'low'),
      `new Function() — ${body.length} caractères : ${body.slice(0, 120)}`);
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

  // 2. Canaux persistants vers un C2 (WebSocket, WebRTC)
  hookConstructor(window, 'WebSocket', (args) =>
    report('websocket', inFrameOr('medium'), `WebSocket ouvert vers ${args[0]}`));
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
            report('cookie-read', inFrameOr('medium'),
              `Lecture de document.cookie (${value.split(';').length} cookies) par ${src}`, src);
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

  // 5. Surveillance du comportement depuis un cadre (souris, clavier, défilement…)
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
