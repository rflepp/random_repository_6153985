/* Public unlock screen. Knows nothing about the game: it fetches payload.enc, derives the key from the
 * passphrase, decrypts the app in memory and mounts it. Wrong passphrase -> nothing but an error message. */
(function () {
  'use strict';
  var STORE_KEY = 'p30.pw';
  var TT = {
    de: {
      title: 'Summit 30', welcome: 'Willkommen zum ultimativen Quiz mit fesselnden Missionen und Fragen auf Expertenniveau. Erklimme das Matterhorn, indem du Punkte sammelst.', luck: 'Viel Glück ;)',
      sub: 'Gib das Passwort ein, um den Aufstieg zu starten.', label: 'Passwort', go: 'Entsperren',
      bad: 'Falsches Passwort. Probier es nochmal.', https: 'Diese Seite braucht eine sichere Verbindung (https).', net: 'Keine Verbindung. Prüfe dein Netz und versuch es nochmal.', wait: 'Moment, ich klettere…'
    },
    en: {
      title: 'Summit 30', welcome: 'Welcome to the ultimate quiz with mesmerizing missions and expert‑level questions. Climb to the top of the Matterhorn by scoring points.', luck: 'Good luck ;)',
      sub: 'Enter the passphrase to start the climb.', label: 'Passphrase', go: 'Unlock',
      bad: 'Wrong passphrase. Try again.', https: 'This page needs a secure connection (https).', net: 'No connection. Check your network and try again.', wait: 'Climbing…'
    }
  };
  var LANG_KEY = 'p30.lang'; // the app reads the same key, so the choice made here carries over
  var T;
  function pickLang() {
    try { var v = JSON.parse(localStorage.getItem(LANG_KEY)); if (v === 'de' || v === 'en') return v; } catch (e) { /* ignore */ }
    return /^de/i.test(navigator.language || '') ? 'de' : 'en';
  }
  function applyLang(l, remember) {
    T = TT[l];
    document.documentElement.lang = l;
    document.querySelectorAll('[data-t]').forEach(function (el) { el.textContent = T[el.getAttribute('data-t')]; });
    document.querySelectorAll('.lang button').forEach(function (b) { var on = b.getAttribute('data-l') === l; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on ? 'true' : 'false'); });
    if (remember) { try { localStorage.setItem(LANG_KEY, JSON.stringify(l)); } catch (e) { /* ignore */ } }
  }
  applyLang(pickLang(), false);
  document.querySelectorAll('.lang button').forEach(function (b) {
    b.addEventListener('click', function () { applyLang(b.getAttribute('data-l'), true); document.getElementById('err').textContent = ''; });
  });

  var form = document.getElementById('unlock-form');
  if (!window.crypto || !crypto.subtle) { document.getElementById('err').textContent = T.https; document.getElementById('go').disabled = true; return; } // Web Crypto only exists on https and localhost
  var input = document.getElementById('pw');
  var err = document.getElementById('err');
  var btn = document.getElementById('go');
  var version = (document.querySelector('meta[name="p30-v"]') || {}).content || '';
  var payloadBytes = null;
  var failures = 0;

  function store(op, k, v) {
    try { return op === 'get' ? localStorage.getItem(k) : op === 'set' ? localStorage.setItem(k, v) : localStorage.removeItem(k); } catch (e) { return null; }
  }

  function loadPayload() {
    if (payloadBytes) return Promise.resolve(payloadBytes);
    return fetch('payload.enc?v=' + encodeURIComponent(version)).then(function (r) {
      if (!r.ok) throw new Error('http ' + r.status);
      return r.arrayBuffer();
    }).then(function (buf) { payloadBytes = new Uint8Array(buf); return payloadBytes; });
  }

  function setBusy(on) {
    form.classList.toggle('busy', on);
    btn.disabled = on;
    input.readOnly = on;
    btn.firstElementChild.textContent = on ? T.wait : T.go;
  }

  function fail(msg) {
    err.textContent = msg;
    form.classList.remove('shake');
    void form.offsetWidth; // restart animation
    form.classList.add('shake');
  }

  function mount(payload, key) {
    var mediaCache = {};
    window.__P30 = {
      version: version,
      config: payload.config || {},
      content: payload.content || {},
      i18n: payload.i18n || {},
      mediaUrl: function (path) {
        var file = (payload.media || {})[path];
        if (!file) return Promise.reject(new Error('unknown media ' + path));
        if (!mediaCache[path]) {
          mediaCache[path] = fetch(file + '?v=' + encodeURIComponent(version)).then(function (r) {
            if (!r.ok) throw new Error('http ' + r.status);
            return r.arrayBuffer();
          }).then(function (buf) {
            return P30Crypto.decryptRaw(key, new Uint8Array(buf));
          }).then(function (bytes) {
            return URL.createObjectURL(new Blob([bytes], { type: payload.mediaTypes[path] || 'application/octet-stream' }));
          });
          mediaCache[path].catch(function () { delete mediaCache[path]; });
        }
        return mediaCache[path];
      },
      forget: function () { store('del', STORE_KEY); location.replace(location.pathname + location.search); }
    };
    var shellCss = document.getElementById('shell-css');
    if (shellCss) shellCss.remove();
    document.title = payload.title || document.title;
    var style = document.createElement('style');
    style.textContent = payload.css;
    document.head.appendChild(style);
    document.body.innerHTML = payload.html;
    var script = document.createElement('script');
    script.src = URL.createObjectURL(new Blob([payload.js], { type: 'text/javascript' }));
    document.body.appendChild(script);
  }

  function attempt(pw, fromStore) {
    setBusy(true);
    err.textContent = '';
    return loadPayload().then(function (bytes) {
      return P30Crypto.open(bytes, pw);
    }).then(function (res) {
      var payload = JSON.parse(new TextDecoder().decode(res.data));
      store('set', STORE_KEY, pw);
      mount(payload, res.key);
    }).catch(function (e) {
      setBusy(false);
      if (fromStore) { store('del', STORE_KEY); return; } // stale remembered passphrase: just show the form
      if (e && e.name === 'BadPassword') {
        failures++;
        fail(T.bad);
        if (failures >= 5) { btn.disabled = true; setTimeout(function () { btn.disabled = false; }, 3000); } // cosmetic; real defence is the KDF cost
        input.select();
      } else {
        fail(T.net);
      }
    });
  }

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var pw = input.value.trim();
    if (pw) attempt(pw, false);
  });

  // 1) passphrase in the URL fragment (QR code on the invitation): #k=...
  var m = /(?:^#|&)k=([^&]*)/.exec(location.hash);
  if (m) {
    var fromHash = '';
    try { fromHash = decodeURIComponent(m[1]); } catch (e) { fromHash = m[1]; }
    history.replaceState(null, '', location.pathname + location.search); // remove it from the address bar and history
    if (fromHash) { attempt(fromHash, false); return; }
  }
  // 2) remembered on this device
  var saved = store('get', STORE_KEY);
  if (saved) { attempt(saved, true); return; }
  if (!(window.matchMedia && matchMedia('(pointer: coarse)').matches)) input.focus(); // on phones the keyboard would cover the welcome text
})();
