(function (global) {
  'use strict';

  const DB_NAME = 'chatbot-enc-key';
  const DB_VERSION = 1;
  const STORE_NAME = 'keys';
  const WRAP_KEY_ID = 'device-wrap';
  // Per-account slots are keyed by sha256(username) so no account names are
  // stored in the browser. One record per account:
  //   { wrapped: {iv, wrapped}, mode, webauthnCredId, updatedAt }
  const SLOT_PREFIX = 'acct:';
  // Pre-multi-account entries; removed once a slotted login overwrites them.
  const LEGACY_WRAPPED_KEY_ID = 'wrapped-data-key';
  const LEGACY_MODE_KEY = 'storage-mode';
  const LEGACY_WEBAUTHN_CRED_ID = 'webauthn-cred';

  let cachedKey = null;

  function hasWebCrypto() {
    return !!(global.crypto && global.crypto.subtle);
  }

  function isSecureContext() {
    return global.isSecureContext === true;
  }

  function openDb() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function idbGet(key) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbSet(key, value) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function idbDelete(key) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function idbGetAllKeys() {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAllKeys();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbGetAllEntries() {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const keysReq = store.getAllKeys();
      const valuesReq = store.getAll();
      tx.oncomplete = () => {
        const keys = keysReq.result || [];
        const values = valuesReq.result || [];
        resolve(keys.map((key, index) => ({ key, value: values[index] })));
      };
      tx.onerror = () => reject(tx.error);
    });
  }

  async function generateWrapKey() {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function wrapKeyCanEncrypt(wrapKey) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, new Uint8Array([0]));
      return true;
    } catch (_) {
      return false;
    }
  }

  async function ensureWrapKey() {
    let existing = await idbGet(WRAP_KEY_ID);
    if (existing && (await wrapKeyCanEncrypt(existing))) {
      return existing;
    }
    if (existing) {
      await idbDelete(WRAP_KEY_ID);
      const keys = await idbGetAllKeys();
      for (const key of keys) {
        if (typeof key === 'string' && key.startsWith(SLOT_PREFIX)) {
          await idbDelete(key);
        }
      }
    }
    const wrapKey = await generateWrapKey();
    await idbSet(WRAP_KEY_ID, wrapKey);
    return wrapKey;
  }

  function encodeBase64(bytes) {
    let binary = '';
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  }

  function decodeBase64(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function wrapDataKey(rawKeyB64, aesKey) {
    const raw = decodeBase64(rawKeyB64);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, raw);
    return { iv: Array.from(iv), wrapped: Array.from(new Uint8Array(encrypted)) };
  }

  async function unwrapDataKey(record, aesKey) {
    const iv = new Uint8Array(record.iv);
    const ciphertext = new Uint8Array(record.wrapped);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
    return encodeBase64(new Uint8Array(plain));
  }

  async function deriveKeyFromPassword(password, saltB64) {
    const enc = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const saltStr = atob(saltB64);
    const salt = new Uint8Array(saltStr.length);
    for (let i = 0; i < saltStr.length; i += 1) {
      salt[i] = saltStr.charCodeAt(i);
    }
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      passwordKey,
      256
    );
    return encodeBase64(new Uint8Array(derivedBits));
  }

  // Minimal FIPS 180-4 SHA-256 over UTF-8 bytes. WebCrypto (crypto.subtle)
  // only exists in secure contexts, and the native Capacitor WebView loads
  // the app over plain HTTP — account-slot hashing must work there too, so
  // fall back to this when subtle is unavailable. Output is identical.
  const SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  function sha256PureJs(bytes) {
    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const blocks = ((bytes.length + 9 + 63) >> 6);
    const padded = new Uint8Array(blocks << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const bitLen = bytes.length * 8;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(padded.length - 4, bitLen >>> 0);

    const w = new Uint32Array(64);
    for (let i = 0; i < blocks; i += 1) {
      const off = i << 6;
      for (let t = 0; t < 16; t += 1) {
        w[t] = dv.getUint32(off + (t << 2));
      }
      for (let t = 16; t < 64; t += 1) {
        const x = w[t - 15];
        const y = w[t - 2];
        const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      let a = h[0];
      let b = h[1];
      let c = h[2];
      let d = h[3];
      let e = h[4];
      let f = h[5];
      let g = h[6];
      let hh = h[7];
      for (let t = 0; t < 64; t += 1) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const temp1 = (hh + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        hh = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0;
      h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0;
      h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0;
      h[5] = (h[5] + f) >>> 0;
      h[6] = (h[6] + g) >>> 0;
      h[7] = (h[7] + hh) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i += 1) {
      odv.setUint32(i << 2, h[i]);
    }
    return out;
  }

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(String(text));
    let digestBytes;
    if (hasWebCrypto()) {
      try {
        digestBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
      } catch (_) {
        digestBytes = sha256PureJs(bytes);
      }
    } else {
      digestBytes = sha256PureJs(bytes);
    }
    return Array.from(digestBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function accountHash(username) {
    return sha256Hex(String(username || '').trim());
  }

  function currentUsername() {
    if (global.APP_DATA && global.APP_DATA.username) {
      return String(global.APP_DATA.username);
    }
    return null;
  }

  async function slotKey(username) {
    const name = username || currentUsername();
    if (!name) {
      throw new Error('No account selected for key storage');
    }
    return SLOT_PREFIX + (await accountHash(name));
  }

  async function slotIdByHash(hash) {
    return SLOT_PREFIX + String(hash || '').toLowerCase();
  }

  async function removeLegacySlots() {
    await idbDelete(LEGACY_WRAPPED_KEY_ID);
    await idbDelete(LEGACY_MODE_KEY);
    await idbDelete(LEGACY_WEBAUTHN_CRED_ID);
  }

  async function storeWrappedKey(rawKeyB64, mode, username) {
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      await global.NativeBridge.callNativePlugin('NativeSecureKey', 'storeKey', { key: rawKeyB64 });
      cachedKey = rawKeyB64;
      if (username || currentUsername()) {
        await idbSet(await slotKey(username), { mode: 'native-keystore', updatedAt: Date.now() });
      }
      await removeLegacySlots();
      return;
    }
    if (!hasWebCrypto() || !isSecureContext()) {
      throw new Error('Encryption key storage requires a secure context (HTTPS) or the native app.');
    }
    const name = username || currentUsername();
    if (!name) {
      // Legacy single-slot storage: the calling page predates per-account
      // slots (stale cached login.js). Keep the old behaviour so login still
      // works; the next per-account login migrates the entry.
      const wrapKey = await ensureWrapKey();
      const wrapped = await wrapDataKey(rawKeyB64, wrapKey);
      await idbSet(LEGACY_WRAPPED_KEY_ID, wrapped);
      await idbSet(LEGACY_MODE_KEY, mode || 'indexeddb');
      cachedKey = rawKeyB64;
      return;
    }
    const wrapKey = await ensureWrapKey();
    const wrapped = await wrapDataKey(rawKeyB64, wrapKey);
    await idbSet(await slotKey(name), {
      wrapped,
      mode: mode || 'indexeddb',
      updatedAt: Date.now(),
    });
    cachedKey = rawKeyB64;
    await removeLegacySlots();
  }

  function isNativeSecureStorage() {
    return !!(global.NativeBridge && global.NativeBridge.isNativePlatform());
  }

  async function verifyStoredKey(expectedB64, username) {
    if (isNativeSecureStorage()) {
      return cachedKey === expectedB64;
    }
    cachedKey = null;
    const loaded = await loadWrappedKey(username);
    return loaded === expectedB64;
  }

  async function loadWrappedKey(username) {
    if (cachedKey) {
      return cachedKey;
    }
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        const result = await global.NativeBridge.callNativePlugin('NativeSecureKey', 'getKey', {});
        cachedKey = result && result.key ? result.key : null;
      } catch (err) {
        console.error('native secure key read failed', err);
        cachedKey = null;
      }
      return cachedKey;
    }
    if (!hasWebCrypto() || !isSecureContext()) {
      return null;
    }
    const name = username || currentUsername();
    if (!name) {
      return loadLegacyWrappedKey();
    }
    const key = await slotKey(name);
    const record = await idbGet(key);
    if (!record) {
      return loadLegacyWrappedKey();
    }
    if (record.mode === 'webauthn-prf') {
      return cachedKey;
    }
    const wrapKey = await idbGet(WRAP_KEY_ID);
    if (!wrapKey) {
      console.debug('enc-key: wrapping key missing from IndexedDB');
      return null;
    }
    try {
      cachedKey = await unwrapDataKey(record.wrapped, wrapKey);
      return cachedKey;
    } catch (err) {
      console.error('enc-key: failed to unwrap stored key', err);
      return null;
    }
  }

  // Pre-per-account storage format (single global slot, no username
  // attribution). Read only when no slot exists for the requested account.
  async function loadLegacyWrappedKey() {
    const mode = await idbGet(LEGACY_MODE_KEY);
    if (mode === 'session-fallback') {
      sessionStorage.removeItem('chatbot_enc_key');
      await removeLegacySlots();
      console.debug('enc-key: cleared legacy session-fallback storage');
      return null;
    }
    if (mode === 'webauthn-prf') {
      return cachedKey;
    }
    const record = await idbGet(LEGACY_WRAPPED_KEY_ID);
    if (!record) {
      console.debug('enc-key: no cached key slot for this account');
      return null;
    }
    const wrapKey = await idbGet(WRAP_KEY_ID);
    if (!wrapKey) {
      console.debug('enc-key: wrapping key missing from IndexedDB');
      return null;
    }
    try {
      cachedKey = await unwrapDataKey(record, wrapKey);
      return cachedKey;
    } catch (err) {
      console.error('enc-key: failed to unwrap stored key', err);
      return null;
    }
  }

  async function listCachedAccounts() {
    try {
      const entries = await idbGetAllEntries();
      return entries
        .filter((entry) => (
          typeof entry.key === 'string' &&
          entry.key.startsWith(SLOT_PREFIX) &&
          entry.value
        ))
        .map((entry) => ({
          hash: entry.key.slice(SLOT_PREFIX.length),
          updatedAt: entry.value.updatedAt || 0,
        }))
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .map((entry) => entry.hash);
    } catch (err) {
      console.debug('enc-key: unable to list cached accounts', err);
      return [];
    }
  }

  async function hasCachedAccount(username) {
    if (isNativeSecureStorage()) {
      try {
        const result = await global.NativeBridge.callNativePlugin('NativeSecureKey', 'getKey', {});
        return !!(result && result.key);
      } catch (_) {
        return false;
      }
    }
    try {
      const record = await idbGet(await slotKey(username));
      return !!record;
    } catch (_) {
      return false;
    }
  }

  async function clearStoredKey(username) {
    cachedKey = null;
    sessionStorage.removeItem('chatbot_enc_key');
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        await global.NativeBridge.callNativePlugin('NativeSecureKey', 'clearKey', {});
      } catch (err) {
        console.debug('native secure key clear failed', err);
      }
    }
    if (username) {
      await idbDelete(await slotKey(username));
      return;
    }
    const keys = await idbGetAllKeys();
    for (const key of keys) {
      if (typeof key === 'string' && key.startsWith(SLOT_PREFIX)) {
        await idbDelete(key);
      }
    }
    await removeLegacySlots();
  }

  async function unlockWithPassword(username, password) {
    const resp = await fetch(`/auth/salt/${encodeURIComponent(username)}`);
    if (!resp.ok) {
      throw new Error('Unable to fetch salt');
    }
    const data = await resp.json();
    const derived = await deriveKeyFromPassword(password, data.salt);
    await storeWrappedKey(derived, 'indexeddb', username);
    return derived;
  }

  async function supportsWebAuthnPrf() {
    if (!global.PublicKeyCredential) {
      return false;
    }
    if (typeof global.PublicKeyCredential.getClientCapabilities !== 'function') {
      return false;
    }
    try {
      const caps = await global.PublicKeyCredential.getClientCapabilities();
      return !!(caps && caps.prf === true);
    } catch (_) {
      return false;
    }
  }

  async function registerWebAuthnDeviceLock(displayName) {
    if (!(await supportsWebAuthnPrf())) {
      throw new Error('WebAuthn PRF is not supported in this browser');
    }
    const username = currentUsername();
    const rawKeyB64 = cachedKey || (username ? await loadWrappedKey(username) : null);
    if (!rawKeyB64) {
      throw new Error('Unlock your encryption key before enabling enhanced key cache security');
    }
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: 'Chatbot' },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: displayName || 'chatbot-user',
          displayName: displayName || 'Chatbot user',
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        extensions: { prf: {} },
      },
    });
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [
          {
            type: 'public-key',
            id: new Uint8Array(credential.rawId),
          },
        ],
        userVerification: 'required',
        extensions: {
          prf: {
            eval: {
              first: new TextEncoder().encode('chatbot-enc-key-wrap-v1'),
            },
          },
        },
      },
    });
    const extensions = assertion.getClientExtensionResults();
    const prfResults = extensions && extensions.prf && extensions.prf.results;
    if (!prfResults || !prfResults.first) {
      throw new Error('WebAuthn PRF extension unavailable during enrollment');
    }
    const prfKey = await crypto.subtle.importKey(
      'raw',
      prfResults.first,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    const wrapped = await wrapDataKey(rawKeyB64, prfKey);
    const key = await slotKey(username);
    await idbSet(key, {
      wrapped,
      mode: 'webauthn-prf',
      webauthnCredId: {
        id: credential.id,
        rawId: Array.from(new Uint8Array(credential.rawId)),
      },
      updatedAt: Date.now(),
    });
    // The device wrap key is only removable when no other account still relies
    // on IndexedDB wrapping for its key slot.
    const slots = await listCachedAccounts();
    if (slots.length <= 1) {
      await idbDelete(WRAP_KEY_ID);
    }
    await removeLegacySlots();
    cachedKey = rawKeyB64;
    return credential.id;
  }

  async function unlockWithWebAuthn(username) {
    const name = username || currentUsername();
    if (!name) {
      throw new Error('No account selected for WebAuthn unlock');
    }
    const key = await slotKey(name);
    const record = await idbGet(key);
    if (!record || !record.webauthnCredId) {
      throw new Error('No WebAuthn credential registered');
    }
    return unwrapSlotWithWebAuthn(record);
  }

  /// Slot-lookup variants keyed directly by the account hash (used by the
  /// login page, which never knows the username — the server maps hashes).
  async function getKeyForSlot(hash) {
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        const result = await global.NativeBridge.callNativePlugin('NativeSecureKey', 'getKey', {});
        if (result && result.key) {
          cachedKey = result.key;
          return cachedKey;
        }
      } catch (err) {
        console.error('native secure key read failed', err);
      }
      return null;
    }
    if (!hasWebCrypto() || !isSecureContext()) {
      return null;
    }
    const record = await idbGet(await slotIdByHash(hash));
    if (!record || record.mode === 'webauthn-prf' || !record.wrapped) {
      return null;
    }
    const wrapKey = await idbGet(WRAP_KEY_ID);
    if (!wrapKey) {
      return null;
    }
    try {
      cachedKey = await unwrapDataKey(record.wrapped, wrapKey);
      return cachedKey;
    } catch (err) {
      console.error('enc-key: failed to unwrap stored key', err);
      return null;
    }
  }

  async function unlockWithWebAuthnSlot(hash) {
    const record = await idbGet(await slotIdByHash(hash));
    if (!record || !record.webauthnCredId) {
      throw new Error('No WebAuthn credential registered');
    }
    return unwrapSlotWithWebAuthn(record);
  }

  async function unwrapSlotWithWebAuthn(record) {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [
          {
            type: 'public-key',
            id: new Uint8Array(record.webauthnCredId.rawId),
          },
        ],
        userVerification: 'required',
        extensions: {
          prf: {
            eval: {
              first: new TextEncoder().encode('chatbot-enc-key-wrap-v1'),
            },
          },
        },
      },
    });
    const extensions = assertion.getClientExtensionResults();
    const prfResults = extensions && extensions.prf && extensions.prf.results;
    if (!prfResults || !prfResults.first) {
      throw new Error('WebAuthn PRF extension unavailable');
    }
    const prfKey = await crypto.subtle.importKey(
      'raw',
      prfResults.first,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    if (!record.wrapped) {
      throw new Error('No wrapped encryption key stored');
    }
    cachedKey = await unwrapDataKey(record.wrapped, prfKey);
    return cachedKey;
  }

  /// Bump a slot's last-used timestamp so account lists stay recency-sorted.
  async function touchSlot(hash) {
    try {
      const key = await slotIdByHash(hash);
      const record = await idbGet(key);
      if (record) {
        record.updatedAt = Date.now();
        await idbSet(key, record);
      }
    } catch (_) {}
  }

  /// Remove one account's cached credentials from this browser: the key slot
  /// (and, on native, the single keystore key). The account can still be used
  /// afterwards, but only via its password.
  async function removeSlot(hash) {
    cachedKey = null;
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        await global.NativeBridge.callNativePlugin('NativeSecureKey', 'clearKey', {});
      } catch (err) {
        console.debug('native secure key clear failed', err);
      }
    }
    await idbDelete(await slotIdByHash(hash));
  }

  async function getKeyForRequest() {
    return loadWrappedKey();
  }

  function getKeyForRequestSync() {
    if (cachedKey) {
      return cachedKey;
    }
    return null;
  }

  function lock() {
    cachedKey = null;
  }

  const EncKey = {
    storeFromLogin: storeWrappedKey,
    verifyStoredKey,
    unlockWithPassword,
    unlockWithWebAuthn,
    registerWebAuthnDeviceLock,
    getKeyForRequest,
    getKeyForRequestSync,
    lock,
    clearStoredKey,
    listCachedAccounts,
    hasCachedAccount,
    accountHash,
    getKeyForSlot,
    unlockWithWebAuthnSlot,
    touchSlot,
    removeSlot,
    supportsWebAuthnPrf,
    isNativeSecureStorage,
    isSecureContext,
    hasWebCrypto,
  };

  global.EncKey = EncKey;
})(window);
