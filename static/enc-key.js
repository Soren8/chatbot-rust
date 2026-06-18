(function (global) {
  'use strict';

  const DB_NAME = 'chatbot-enc-key';
  const DB_VERSION = 1;
  const STORE_NAME = 'keys';
  const WRAP_KEY_ID = 'device-wrap';
  const WRAPPED_KEY_ID = 'wrapped-data-key';
  const MODE_KEY = 'storage-mode';
  const WEBAUTHN_CRED_ID = 'webauthn-cred';

  let cachedKey = null;

  function isSecureContext() {
    return global.isSecureContext === true;
  }

  function hasWebCrypto() {
    return !!(global.crypto && global.crypto.subtle);
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
      await idbDelete(WRAPPED_KEY_ID);
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

  async function storeWrappedKey(rawKeyB64, mode) {
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      await global.NativeBridge.callNativePlugin('NativeSecureKey', 'storeKey', { key: rawKeyB64 });
      cachedKey = rawKeyB64;
      await idbSet(MODE_KEY, 'native-keystore');
      return;
    }
    if (!hasWebCrypto() || !isSecureContext()) {
      throw new Error('Encryption key storage requires a secure context (HTTPS) or the native app.');
    }
    const wrapKey = await ensureWrapKey();
    const wrapped = await wrapDataKey(rawKeyB64, wrapKey);
    await idbSet(WRAPPED_KEY_ID, wrapped);
    await idbSet(MODE_KEY, mode || 'indexeddb');
    cachedKey = rawKeyB64;
  }

  function isNativeSecureStorage() {
    return !!(global.NativeBridge && global.NativeBridge.isNativePlatform());
  }

  async function verifyStoredKey(expectedB64) {
    if (isNativeSecureStorage()) {
      return cachedKey === expectedB64;
    }
    cachedKey = null;
    const loaded = await loadWrappedKey();
    return loaded === expectedB64;
  }

  async function loadWrappedKey() {
    if (cachedKey) {
      return cachedKey;
    }
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        const result = await global.NativeBridge.callNativePlugin('NativeSecureKey', 'getKey', {});
        if (result && result.key) {
          cachedKey = result.key;
          return cachedKey;
        }
        console.debug('enc-key: native keystore has no wrapped key yet');
      } catch (err) {
        console.error('enc-key: native secure key read failed', err);
        throw err;
      }
    }
    const mode = await idbGet(MODE_KEY);
    if (mode === 'session-fallback') {
      sessionStorage.removeItem('chatbot_enc_key');
      await idbDelete(MODE_KEY);
      console.debug('enc-key: cleared legacy session-fallback storage');
      return null;
    }
    if (mode === 'webauthn-prf') {
      return cachedKey;
    }
    const record = await idbGet(WRAPPED_KEY_ID);
    if (!record) {
      console.debug('enc-key: no wrapped key in IndexedDB');
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

  async function clearStoredKey() {
    cachedKey = null;
    sessionStorage.removeItem('chatbot_enc_key');
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        await global.NativeBridge.callNativePlugin('NativeSecureKey', 'clearKey', {});
      } catch (err) {
        console.debug('native secure key clear failed', err);
      }
    }
    await idbDelete(WRAPPED_KEY_ID);
    await idbDelete(MODE_KEY);
    await idbDelete(WEBAUTHN_CRED_ID);
  }

  async function unlockWithPassword(username, password) {
    const resp = await fetch(`/auth/salt/${encodeURIComponent(username)}`);
    if (!resp.ok) {
      throw new Error('Unable to fetch salt');
    }
    const data = await resp.json();
    const derived = await deriveKeyFromPassword(password, data.salt);
    await storeWrappedKey(derived, 'indexeddb');
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
    const rawKeyB64 = cachedKey || (await loadWrappedKey());
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
    await idbSet(WRAPPED_KEY_ID, wrapped);
    await idbDelete(WRAP_KEY_ID);
    await idbSet(WEBAUTHN_CRED_ID, {
      id: credential.id,
      rawId: Array.from(new Uint8Array(credential.rawId)),
    });
    await idbSet(MODE_KEY, 'webauthn-prf');
    cachedKey = rawKeyB64;
    return credential.id;
  }

  async function unlockWithWebAuthn() {
    const stored = await idbGet(WEBAUTHN_CRED_ID);
    if (!stored) {
      throw new Error('No WebAuthn credential registered');
    }
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [
          {
            type: 'public-key',
            id: new Uint8Array(stored.rawId),
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
    const record = await idbGet(WRAPPED_KEY_ID);
    if (!record) {
      throw new Error('No wrapped encryption key stored');
    }
    cachedKey = await unwrapDataKey(record, prfKey);
    return cachedKey;
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
    supportsWebAuthnPrf,
    isNativeSecureStorage,
    isSecureContext,
    hasWebCrypto,
  };

  global.EncKey = EncKey;
})(window);
