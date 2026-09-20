(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatCredentialCrypto = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Credential derivation/wrap/PRF algorithms shared by enc-key.js.
  // PBKDF2 derivation (100000 x SHA-256 -> 256 bits), AES-GCM wrap-key
  // generation/probe, data-key wrap/unwrap, authenticator PRF import/eval
  // bytes plus base64 transforms. Every browser capability arrives via
  // explicit env params (no ambient store, DOM, or key-flow reach);
  // enc-key.js passes browser globals at the call site and keeps store
  // lifecycle plus the EncKey surface.

  var PBKDF2_ITERATIONS = 100000;
  var PBKDF2_HASH = 'SHA-256';
  var PBKDF2_KEY_BITS = 256;
  var PRF_WRAP_LABEL = 'chatbot-enc-key-wrap-v1';

  function requireFn(env, name) {
    if (!env || typeof env[name] !== 'function') {
      throw new Error('ChatCredentialCrypto requires ' + name);
    }
    return env[name];
  }

  function requireSubtle(env) {
    if (!env || !env.subtle) {
      throw new Error('ChatCredentialCrypto requires subtle');
    }
    return env.subtle;
  }

  function requireTextEncoder(env) {
    if (!env || typeof env.TextEncoderImpl !== 'function') {
      throw new Error('ChatCredentialCrypto requires TextEncoderImpl');
    }
    return env.TextEncoderImpl;
  }

  // Base64 encode for raw key bytes (byte-wise String.fromCharCode shape).
  function encodeBase64(bytes, btoaImpl) {
    if (typeof btoaImpl !== 'function') {
      throw new Error('ChatCredentialCrypto requires btoaImpl');
    }
    var binary = '';
    bytes.forEach(function (b) {
      binary += String.fromCharCode(b);
    });
    return btoaImpl(binary);
  }

  // Base64 decode to bytes.
  function decodeBase64(value, atobImpl) {
    if (typeof atobImpl !== 'function') {
      throw new Error('ChatCredentialCrypto requires atobImpl');
    }
    var binary = atobImpl(value);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Salt bytes for PBKDF2 from the server-provided base64 salt.
  function decodeSaltB64(saltB64, atobImpl) {
    if (typeof atobImpl !== 'function') {
      throw new Error('ChatCredentialCrypto requires atobImpl');
    }
    var saltStr = atobImpl(saltB64);
    var salt = new Uint8Array(saltStr.length);
    for (var i = 0; i < saltStr.length; i += 1) {
      salt[i] = saltStr.charCodeAt(i);
    }
    return salt;
  }

  // PBKDF2 derivation parameters (deriveBits shape, minus salt bytes).
  function pbkdf2Params() {
    return {
      name: 'PBKDF2',
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
      bits: PBKDF2_KEY_BITS
    };
  }

  // Authenticator PRF eval input label for the device-wrap key.
  function prfWrapLabel() {
    return PRF_WRAP_LABEL;
  }

  // Authenticator PRF eval input bytes for the device-wrap key.
  function prfEvalBytes(env) {
    var TextEncoderImpl = requireTextEncoder(env);
    return new TextEncoderImpl().encode(PRF_WRAP_LABEL);
  }

  // Derive the Fernet data key from password + server salt.
  async function deriveKeyFromPassword(password, saltB64, env) {
    var subtle = requireSubtle(env);
    var TextEncoderImpl = requireTextEncoder(env);
    var atobImpl = requireFn(env, 'atobImpl');
    var btoaImpl = requireFn(env, 'btoaImpl');
    var enc = new TextEncoderImpl();
    var passwordKey = await subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    var salt = decodeSaltB64(saltB64, atobImpl);
    var params = pbkdf2Params();
    var derivedBits = await subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: params.iterations,
        hash: params.hash
      },
      passwordKey,
      params.bits
    );
    return encodeBase64(new Uint8Array(derivedBits), btoaImpl);
  }

  // Generate a device wrap key (AES-GCM 256, non-extractable).
  async function generateWrapKey(env) {
    var subtle = requireSubtle(env);
    return subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Probe whether a stored wrap key can still encrypt. False on any
  // failure, including missing capabilities: subtle and randomness resolve
  // inside the probe so a missing provider reports false instead of
  // rejecting.
  async function wrapKeyCanEncrypt(wrapKey, env) {
    try {
      var subtle = requireSubtle(env);
      var getRandomValues = requireFn(env, 'getRandomValues');
      var iv = getRandomValues(new Uint8Array(12));
      await subtle.encrypt({ name: 'AES-GCM', iv: iv }, wrapKey, new Uint8Array([0]));
      return true;
    } catch (_) {
      return false;
    }
  }

  // Wrap a base64 data key under an AES-GCM key.
  async function wrapDataKey(rawKeyB64, aesKey, env) {
    var subtle = requireSubtle(env);
    var getRandomValues = requireFn(env, 'getRandomValues');
    var atobImpl = requireFn(env, 'atobImpl');
    var raw = decodeBase64(rawKeyB64, atobImpl);
    var iv = getRandomValues(new Uint8Array(12));
    var encrypted = await subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, raw);
    return { iv: Array.from(iv), wrapped: Array.from(new Uint8Array(encrypted)) };
  }

  // Unwrap a wrapped record under an AES-GCM key to base64.
  async function unwrapDataKey(record, aesKey, env) {
    var subtle = requireSubtle(env);
    var btoaImpl = requireFn(env, 'btoaImpl');
    var iv = new Uint8Array(record.iv);
    var ciphertext = new Uint8Array(record.wrapped);
    var plain = await subtle.decrypt({ name: 'AES-GCM', iv: iv }, aesKey, ciphertext);
    return encodeBase64(new Uint8Array(plain), btoaImpl);
  }

  // Import authenticator PRF output as an AES-GCM wrap key.
  async function importPrfKey(prfBytes, env) {
    var subtle = requireSubtle(env);
    return subtle.importKey(
      'raw',
      prfBytes,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Whether the given credential constructor supports the PRF extension.
  async function supportsWebAuthnPrf(env) {
    var ctor = env ? env.credentialCtor : undefined;
    if (!ctor) {
      return false;
    }
    if (typeof ctor.getClientCapabilities !== 'function') {
      return false;
    }
    try {
      var caps = await ctor.getClientCapabilities();
      return !!(caps && caps.prf === true);
    } catch (_) {
      return false;
    }
  }

  return {
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    PBKDF2_HASH: PBKDF2_HASH,
    PBKDF2_KEY_BITS: PBKDF2_KEY_BITS,
    PRF_WRAP_LABEL: PRF_WRAP_LABEL,
    encodeBase64: encodeBase64,
    decodeBase64: decodeBase64,
    decodeSaltB64: decodeSaltB64,
    pbkdf2Params: pbkdf2Params,
    prfWrapLabel: prfWrapLabel,
    prfEvalBytes: prfEvalBytes,
    deriveKeyFromPassword: deriveKeyFromPassword,
    generateWrapKey: generateWrapKey,
    wrapKeyCanEncrypt: wrapKeyCanEncrypt,
    wrapDataKey: wrapDataKey,
    unwrapDataKey: unwrapDataKey,
    importPrfKey: importPrfKey,
    supportsWebAuthnPrf: supportsWebAuthnPrf
  };
}));
