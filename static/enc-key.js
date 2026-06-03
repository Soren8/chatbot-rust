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

  async function ensureWrapKey() {
    const existing = await idbGet(WRAP_KEY_ID);
    if (existing) {
      return existing;
    }
    const wrapKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['wrapKey', 'unwrapKey']
    );
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

  async function importRawAesKey(rawKeyB64) {
    const raw = decodeBase64(rawKeyB64);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
      'wrapKey',
      'unwrapKey',
    ]);
  }

  async function wrapDataKey(rawKeyB64, wrapKey) {
    const dataKey = await importRawAesKey(rawKeyB64);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await crypto.subtle.wrapKey('raw', dataKey, wrapKey, { name: 'AES-GCM', iv });
    return { iv: Array.from(iv), wrapped: Array.from(new Uint8Array(wrapped)) };
  }

  async function unwrapDataKey(record, wrapKey) {
    const iv = new Uint8Array(record.iv);
    const wrapped = new Uint8Array(record.wrapped);
    const raw = await crypto.subtle.unwrapKey(
      'raw',
      wrapped,
      wrapKey,
      { name: 'AES-GCM', iv },
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const exported = await crypto.subtle.exportKey('raw', raw);
    return encodeBase64(new Uint8Array(exported));
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
    if (window.Capacitor && window.Capacitor.nativePromise) {
      await window.Capacitor.nativePromise('NativeSecureKey', 'storeKey', { key: rawKeyB64 });
      cachedKey = rawKeyB64;
      await idbSet(MODE_KEY, 'native-keystore');
      return;
    }
    if (!hasWebCrypto() || !isSecureContext()) {
      sessionStorage.setItem('chatbot_enc_key', rawKeyB64);
      await idbSet(MODE_KEY, 'session-fallback');
      cachedKey = rawKeyB64;
      return;
    }
    const wrapKey = await ensureWrapKey();
    const wrapped = await wrapDataKey(rawKeyB64, wrapKey);
    await idbSet(WRAPPED_KEY_ID, wrapped);
    await idbSet(MODE_KEY, mode || 'indexeddb');
    cachedKey = rawKeyB64;
  }

  async function loadWrappedKey() {
    if (cachedKey) {
      return cachedKey;
    }
    if (window.Capacitor && window.Capacitor.nativePromise) {
      try {
        const result = await window.Capacitor.nativePromise('NativeSecureKey', 'getKey', {});
        if (result && result.key) {
          cachedKey = result.key;
          return cachedKey;
        }
      } catch (err) {
        console.debug('native secure key read failed', err);
      }
    }
    const mode = await idbGet(MODE_KEY);
    if (mode === 'session-fallback') {
      const value = sessionStorage.getItem('chatbot_enc_key');
      cachedKey = value;
      return value;
    }
    if (mode === 'webauthn-prf') {
      return cachedKey;
    }
    const record = await idbGet(WRAPPED_KEY_ID);
    if (!record) {
      return null;
    }
    const wrapKey = await idbGet(WRAP_KEY_ID);
    if (!wrapKey) {
      return null;
    }
    cachedKey = await unwrapDataKey(record, wrapKey);
    return cachedKey;
  }

  async function clearStoredKey() {
    cachedKey = null;
    sessionStorage.removeItem('chatbot_enc_key');
    if (window.Capacitor && window.Capacitor.nativePromise) {
      try {
        await window.Capacitor.nativePromise('NativeSecureKey', 'clearKey', {});
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

  function supportsWebAuthnPrf() {
    return !!(global.PublicKeyCredential && global.PublicKeyCredential.prototype.getClientExtensionResults);
  }

  async function registerWebAuthnDeviceLock(displayName) {
    if (!supportsWebAuthnPrf()) {
      throw new Error('WebAuthn PRF is not supported in this browser');
    }
    const rawKeyB64 = cachedKey || (await loadWrappedKey());
    if (!rawKeyB64) {
      throw new Error('Unlock your encryption key before enabling device lock');
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
      ['wrapKey', 'unwrapKey']
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
      ['wrapKey', 'unwrapKey']
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
    if (sessionStorage.getItem('chatbot_enc_key')) {
      return sessionStorage.getItem('chatbot_enc_key');
    }
    return null;
  }

  function lock() {
    cachedKey = null;
  }

  async function promptUnlock(username) {
    const password = global.prompt('Enter your password to unlock encrypted chats:');
    if (!password) {
      return null;
    }
    return unlockWithPassword(username, password);
  }

  const EncKey = {
    storeFromLogin: storeWrappedKey,
    unlockWithPassword,
    unlockWithWebAuthn,
    registerWebAuthnDeviceLock,
    getKeyForRequest,
    getKeyForRequestSync,
    lock,
    clearStoredKey,
    promptUnlock,
    supportsWebAuthnPrf,
    isSecureContext,
    hasWebCrypto,
  };

  global.EncKey = EncKey;
})(window);
