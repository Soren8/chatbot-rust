(function (global) {
  'use strict';

  const DB_NAME = 'chatbot-enc-key';
  const DB_VERSION = 1;
  const STORE_NAME = 'keys';
  const WRAP_KEY_ID = 'device-wrap';
  // Per-account slots are keyed by the username so the login page can list
  // cached accounts (and forget them) by name. Only accounts whose login had
  // "Remember this computer" checked get a slot. The Fernet key is not stored
  // here — it lives in HttpOnly cookies. Slot naming, visibility and
  // recency policy are owned by ChatCredentialMetadata; derivation, wrap
  // and PRF algorithms by ChatCredentialCrypto (wired before this script).
  // Pre-multi-account entries; removed once a slotted login overwrites them.
  const LEGACY_WRAPPED_KEY_ID = 'wrapped-data-key';
  const LEGACY_MODE_KEY = 'storage-mode';
  const LEGACY_WEBAUTHN_CRED_ID = 'webauthn-cred';

  // These units are required. Slot policy and crypto algorithms live
  // there; this script keeps store lifecycle plus the EncKey surface and
  // passes browser capabilities explicitly.
  function metadataOwner() {
    const owner = global.ChatCredentialMetadata;
    if (!owner) {
      throw new Error('ChatCredentialMetadata unit required before enc-key.js');
    }
    return owner;
  }

  function cryptoUnit() {
    const owner = global.ChatCredentialCrypto;
    if (!owner) {
      throw new Error('ChatCredentialCrypto unit required before enc-key.js');
    }
    return owner;
  }

  // Browser capabilities passed explicitly to the crypto owner per call.
  // Reads stay lazy (per operation, at call time) so an operation never
  // requires a capability it does not use, and capability access for the
  // encrypt probe happens inside the owner's try (false, not reject).
  function cryptoEnv() {
    return {
      get subtle() { return crypto.subtle; },
      get getRandomValues() { return crypto.getRandomValues.bind(crypto); },
      get TextEncoderImpl() { return TextEncoder; },
      get atobImpl() { return atob; },
      get btoaImpl() { return btoa; }
    };
  }

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

  async function ensureWrapKey() {
    let existing = await idbGet(WRAP_KEY_ID);
    if (existing && (await wrapKeyCanEncrypt(existing))) {
      return existing;
    }
    if (existing) {
      await idbDelete(WRAP_KEY_ID);
      const keys = await idbGetAllKeys();
      for (const key of keys) {
        if (metadataOwner().isAccountSlotKey(key)) {
          await idbDelete(key);
        }
      }
    }
    const wrapKey = await generateWrapKey();
    await idbSet(WRAP_KEY_ID, wrapKey);
    return wrapKey;
  }

  // Thin adapters over the crypto owner (algorithms live there).
  async function generateWrapKey() {
    return cryptoUnit().generateWrapKey({ subtle: crypto.subtle });
  }

  async function wrapKeyCanEncrypt(wrapKey) {
    return cryptoUnit().wrapKeyCanEncrypt(wrapKey, cryptoEnv());
  }

  async function wrapDataKey(rawKeyB64, aesKey) {
    return cryptoUnit().wrapDataKey(rawKeyB64, aesKey, cryptoEnv());
  }

  async function unwrapDataKey(record, aesKey) {
    return cryptoUnit().unwrapDataKey(record, aesKey, cryptoEnv());
  }

  async function deriveKeyFromPassword(password, saltB64) {
    return cryptoUnit().deriveKeyFromPassword(password, saltB64, cryptoEnv());
  }

  function currentUsername() {
    if (global.APP_DATA && global.APP_DATA.username) {
      return String(global.APP_DATA.username);
    }
    return null;
  }

  function slotKey(username) {
    return metadataOwner().slotKeyFor(username, currentUsername());
  }

  async function slotIdByHash(hash) {
    return metadataOwner().SLOT_PREFIX + String(hash || '').toLowerCase();
  }

  async function removeLegacySlots() {
    await idbDelete(LEGACY_WRAPPED_KEY_ID);
    await idbDelete(LEGACY_MODE_KEY);
    await idbDelete(LEGACY_WEBAUTHN_CRED_ID);
  }

  // `remembered` gates password-free re-entry (dropdown + remember cookie).
  // The Fernet key is not written to IndexedDB or the native plugin.
  async function storeWrappedKey(_rawKeyB64, _mode, username, remembered) {
    cachedKey = null;
    const name = username || currentUsername();
    if (!name) {
      return;
    }
    await idbSet(slotKey(name), {
      mode: 'cookie',
      remembered: !!remembered,
      updatedAt: Date.now(),
    });
    await scrubWrappedKeys();
    await removeLegacySlots();
  }

  async function scrubWrappedKeys() {
    try {
      await idbDelete(WRAP_KEY_ID);
      await idbDelete(LEGACY_WRAPPED_KEY_ID);
      const entries = await idbGetAllEntries();
      for (const entry of entries) {
        if (!entry.value || typeof entry.value !== 'object' || !entry.value.wrapped) {
          continue;
        }
        if (entry.value.mode === 'webauthn-prf') {
          continue;
        }
        const next = {
          mode: 'cookie',
          remembered: entry.value.remembered !== false,
          updatedAt: entry.value.updatedAt || Date.now(),
        };
        await idbSet(entry.key, next);
      }
    } catch (_) {}
  }

  function isNativeSecureStorage() {
    return !!(global.NativeBridge && global.NativeBridge.isNativePlatform());
  }

  async function verifyStoredKey(_expectedB64, username) {
    try {
      const record = await idbGet(slotKey(username));
      return !!(record && record.updatedAt);
    } catch (_) {
      return false;
    }
  }

  async function loadWrappedKey(_username) {
    return null;
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
      return metadataOwner().filterCachedAccounts(entries, Date.now());
    } catch (err) {
      console.debug('enc-key: unable to list cached accounts', err);
      return [];
    }
  }

  async function clearStoredKey(username) {
    cachedKey = null;
    sessionStorage.removeItem('chatbot_enc_key');
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        await global.NativeBridge.callNativePlugin('NativeSecureKey', 'clearKey', {
          account: username,
        });
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
      if (metadataOwner().isAccountSlotKey(key)) {
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
    return cryptoUnit().supportsWebAuthnPrf({ credentialCtor: global.PublicKeyCredential });
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
              first: cryptoUnit().prfEvalBytes({ TextEncoderImpl: TextEncoder }),
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
    const prfKey = await cryptoUnit().importPrfKey(prfResults.first, { subtle: crypto.subtle });
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

  // Slot-lookup by username (no session yet). The data key is not available
  // to page JS; HttpOnly cookies carry it.
  async function getKeyForUsername(username) {
    return null;
  }

  async function unlockWithWebAuthnForUser(username) {
    const record = await idbGet(slotKey(username));
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
              first: cryptoUnit().prfEvalBytes({ TextEncoderImpl: TextEncoder }),
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
    const prfKey = await cryptoUnit().importPrfKey(prfResults.first, { subtle: crypto.subtle });
    if (!record.wrapped) {
      throw new Error('No wrapped encryption key stored');
    }
    cachedKey = await unwrapDataKey(record.wrapped, prfKey);
    return cachedKey;
  }

  // Bump a slot's last-used timestamp so account lists stay recency-sorted.
  async function touchSlot(username) {
    try {
      const key = slotKey(username);
      const record = await idbGet(key);
      if (record) {
        await idbSet(key, metadataOwner().touchSlotRecord(record, Date.now()));
      }
    } catch (_) {}
  }

  // Remove one account's cached credentials from this browser: the key slot
  // and, on native, that account's keystore entry. The account can still be
  // used afterwards, but only via its password.
  async function removeSlot(username) {
    cachedKey = null;
    if (global.NativeBridge && global.NativeBridge.isNativePlatform()) {
      try {
        await global.NativeBridge.callNativePlugin('NativeSecureKey', 'clearKey', {
          account: username,
        });
      } catch (err) {
        console.debug('native secure key clear failed', err);
      }
    }
    await idbDelete(slotKey(username));
  }

  async function purgeNonRememberedSlots() {
    try {
      const entries = await idbGetAllEntries();
      const usernames = metadataOwner().purgeableSlotUsernames(entries);
      for (const username of usernames) {
        await removeSlot(username);
      }
    } catch (err) {
      console.debug('enc-key: unable to purge non-remembered slots', err);
    }
  }

  async function getKeyForRequest() {
    return null;
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

  scrubWrappedKeys();

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
    getKeyForUsername,
    unlockWithWebAuthnForUser,
    touchSlot,
    removeSlot,
    purgeNonRememberedSlots,
    supportsWebAuthnPrf,
    isNativeSecureStorage,
    isSecureContext,
    hasWebCrypto,
  };

  global.EncKey = EncKey;
})(window);
