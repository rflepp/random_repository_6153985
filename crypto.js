/* Summit 30 crypto core. Runs unchanged in the browser (unlock screen) and in Node (build, tests).
 *
 * Container format of payload.enc:
 *   [1 byte version=1][4 bytes PBKDF2 iterations, big endian][16 bytes salt][12 bytes IV][ciphertext + GCM tag]
 * Media files (m/*.enc) reuse the same key:  [12 bytes IV][ciphertext + GCM tag]
 *
 * Key: PBKDF2-HMAC-SHA256(password, salt, iterations) -> AES-256-GCM. The AAD binds ciphertexts to this app.
 */
(function (root) {
  'use strict';
  var VERSION = 1;
  var ITERATIONS = 1000000;
  var SALT_LEN = 16;
  var IV_LEN = 12;
  var HEADER_LEN = 1 + 4 + SALT_LEN + IV_LEN;
  var AAD = new TextEncoder().encode('summit30:v1');
  var subtle = root.crypto.subtle;

  function BadPassword() {
    var e = new Error('bad password or corrupted data');
    e.name = 'BadPassword';
    return e;
  }

  function deriveKey(password, salt, iterations, usages) {
    var enc = new TextEncoder().encode(password.normalize('NFKC'));
    return subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
        base,
        { name: 'AES-GCM', length: 256 },
        false,
        usages
      );
    });
  }

  function concat(parts) {
    var n = 0;
    parts.forEach(function (p) { n += p.length; });
    var out = new Uint8Array(n);
    var o = 0;
    parts.forEach(function (p) { out.set(p, o); o += p.length; });
    return out;
  }

  function encryptRaw(key, bytes) {
    var iv = root.crypto.getRandomValues(new Uint8Array(IV_LEN));
    return subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: AAD }, key, bytes).then(function (ct) {
      return concat([iv, new Uint8Array(ct)]);
    });
  }

  function decryptRaw(key, bytes) {
    if (bytes.length < IV_LEN + 16) return Promise.reject(BadPassword());
    var iv = bytes.slice(0, IV_LEN);
    var ct = bytes.slice(IV_LEN);
    return subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: AAD }, key, ct).then(
      function (pt) { return new Uint8Array(pt); },
      function () { throw BadPassword(); }
    );
  }

  /* Build side: create a fresh salt + key and encrypt the payload. Returns {file, key}. */
  function seal(plainBytes, password, iterations) {
    iterations = iterations || ITERATIONS;
    var salt = root.crypto.getRandomValues(new Uint8Array(SALT_LEN));
    return deriveKey(password, salt, iterations, ['encrypt', 'decrypt']).then(function (key) {
      return encryptRaw(key, plainBytes).then(function (body) {
        var head = new Uint8Array(1 + 4 + SALT_LEN);
        head[0] = VERSION;
        new DataView(head.buffer).setUint32(1, iterations, false);
        head.set(salt, 5);
        return { file: concat([head, body]), key: key };
      });
    });
  }

  /* Browser side: derive the key from the password and decrypt the payload. Returns {data, key}. */
  function open(fileBytes, password) {
    if (fileBytes.length < HEADER_LEN + 16 || fileBytes[0] !== VERSION) return Promise.reject(BadPassword());
    var iterations = new DataView(fileBytes.buffer, fileBytes.byteOffset, fileBytes.byteLength).getUint32(1, false);
    // refuse absurd iteration counts coming from a tampered file (denial of service on the phone)
    if (iterations < 100000 || iterations > 5000000) return Promise.reject(BadPassword());
    var salt = fileBytes.slice(5, 5 + SALT_LEN);
    var body = fileBytes.slice(5 + SALT_LEN);
    return deriveKey(password, salt, iterations, ['decrypt']).then(function (key) {
      return decryptRaw(key, body).then(function (data) { return { data: data, key: key }; });
    });
  }

  root.P30Crypto = {
    ITERATIONS: ITERATIONS,
    seal: seal,
    open: open,
    encryptRaw: encryptRaw,
    decryptRaw: decryptRaw
  };
})(typeof self !== 'undefined' ? self : globalThis);
