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

  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest))
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

  async function removeLegacySlots() {
    await idbDelete(LEGACY_WRAPPED_KEY_ID);
    await idbDelete(LEGACY_MODE_KEY);
    await idbDelete(LEGACY_WEBAUTHN_CRED_ID);
  }

  async function storeWrappedKey(rawKeyB64, mode, username) {
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      await global.NativeBridge.callNativePlugin('NativeSecureKey', 'storeKey', { key: rawKeyB64 });
      cachedKey = rawKeyB64;
      const key = await slotKey(username);
      await idbSet(key, { mode: 'native-keystore', updatedAt: Date.now() });
      await removeLegacySlots();
      return;
    }
    if (!hasWebCrypto() || !isSecureContext()) {
      throw new Error('Encryption key storage requires a secure context (HTTPS) or the native app.');
    }
    const wrapKey = await ensureWrapKey();
    const wrapped = await wrapDataKey(rawKeyB64, wrapKey);
    const key = await slotKey(username);
    await idbSet(key, {
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
      console.debug('enc-key: no account in page context for key lookup');
      return null;
    }
    const key = await slotKey(name);
    const record = await idbGet(key);
    if (!record) {
      console.debug('enc-key: no cached key slot for this account');
      return null;
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

  async function listCachedAccounts() {
    try {
      const keys = await idbGetAllKeys();
      return keys
        .filter((key) => typeof key === 'string' && key.startsWith(SLOT_PREFIX))
        .map((key) => key.slice(SLOT_PREFIX.length));
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
    supportsWebAuthnPrf,
    isNativeSecureStorage,
    isSecureContext,
    hasWebCrypto,
  };

  global.EncKey = EncKey;
})(window);
