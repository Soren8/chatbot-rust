'use strict';
// Behavior contract for static/credential-crypto.js: derivation/wrap/PRF
// algorithms with explicit env dependencies. Exercised through the stable
// UMD import against deterministic Node WebCrypto with explicit literal
// expectations; the independent Node pbkdf2Sync oracle cross-checks
// derivation without copying the unit's calculation.
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { TextEncoder: Text } = require('node:util');

const modPath = process.argv[2];
assert(modPath, 'usage: node credential_crypto_test.js <static/credential-crypto.js>');
const C = require(modPath);

function btoaImpl(bin) {
  return Buffer.from(bin, 'binary').toString('base64');
}

function atobImpl(b64) {
  return Buffer.from(b64, 'base64').toString('binary');
}

function webEnv() {
  const web = nodeCrypto.webcrypto;
  return {
    subtle: web.subtle,
    getRandomValues: (arr) => web.getRandomValues(arr),
    TextEncoderImpl: Text,
    atobImpl,
    btoaImpl,
  };
}

function testPbkdf2ConstantsUnchanged() {
  // Given the shared crypto unit, when reading parameters, then the legacy
  // 100000 x SHA-256 -> 256-bit contract is preserved.
  assert.equal(C.PBKDF2_ITERATIONS, 100000);
  assert.equal(C.PBKDF2_HASH, 'SHA-256');
  assert.equal(C.PBKDF2_KEY_BITS, 256);
  assert.deepEqual(C.pbkdf2Params(), {
    name: 'PBKDF2',
    iterations: 100000,
    hash: 'SHA-256',
    bits: 256,
  });
}

function testPrfWrapLabel() {
  // Given the shared crypto unit, when reading the PRF label, then the
  // legacy authenticator eval input is preserved exactly.
  assert.equal(C.PRF_WRAP_LABEL, 'chatbot-enc-key-wrap-v1');
  assert.equal(C.prfWrapLabel(), 'chatbot-enc-key-wrap-v1');
  const bytes = C.prfEvalBytes({ TextEncoderImpl: Text });
  assert.deepEqual(Array.from(bytes), Array.from(new Text().encode('chatbot-enc-key-wrap-v1')));
}

function testBase64RoundTripWithExplicitVectors() {
  // Given raw key bytes, when encoded, then the base64 vector matches the
  // legacy loop; decoding inverts it.
  assert.equal(C.encodeBase64(new Uint8Array([72, 105]), btoaImpl), 'SGk=');
  assert.equal(C.encodeBase64(new Uint8Array([0]), btoaImpl), 'AA==');
  assert.deepEqual(Array.from(C.decodeBase64('SGk=', atobImpl)), [72, 105]);
  const bytes = new Uint8Array([1, 2, 250, 255]);
  const encoded = C.encodeBase64(bytes, btoaImpl);
  assert.deepEqual(Array.from(C.decodeBase64(encoded, atobImpl)), [1, 2, 250, 255]);
}

function testBase64RequiresExplicitImpls() {
  // Given no media impl, when encoding/decoding, then the unit throws
  // instead of reaching for ambient globals.
  assert.throws(() => C.encodeBase64(new Uint8Array([1]), null), /requires btoaImpl/);
  assert.throws(() => C.decodeBase64('AA==', undefined), /requires atobImpl/);
  assert.throws(() => C.decodeSaltB64('YWJj', null), /requires atobImpl/);
}

function testSaltDecodesFromServerBase64() {
  // Given the server base64 salt 'YWJj' ("abc"), when decoded, then the
  // PBKDF2 salt bytes are [97, 98, 99].
  assert.deepEqual(Array.from(C.decodeSaltB64('YWJj', atobImpl)), [97, 98, 99]);
}

async function testDeriveMatchesIndependentOracle() {
  // Given a password and salt, when derived through the real unit, then the
  // output matches the independent Node pbkdf2Sync oracle exactly.
  const password = 'correct horse';
  const saltB64 = Buffer.from('salt123', 'utf8').toString('base64');
  const expected = nodeCrypto.pbkdf2Sync(password, Buffer.from('salt123', 'utf8'), 100000, 32, 'sha256').toString('base64');
  const actual = await C.deriveKeyFromPassword(password, saltB64, webEnv());
  assert.equal(actual, expected);
}

async function testDeriveIsDeterministic() {
  // Given the same inputs twice, when derived, then both outputs match.
  const env = webEnv();
  const saltB64 = Buffer.from('pepper', 'utf8').toString('base64');
  const first = await C.deriveKeyFromPassword('pw', saltB64, env);
  const second = await C.deriveKeyFromPassword('pw', saltB64, env);
  assert.equal(first, second);
}

async function testWrapUnwrapRoundTrip() {
  // Given a wrap key and base64 data key, when wrapped then unwrapped
  // through the real unit, then the data key round-trips intact.
  const env = webEnv();
  const wrapKey = await C.generateWrapKey({ subtle: env.subtle });
  assert.equal(await C.wrapKeyCanEncrypt(wrapKey, env), true);
  const rawB64 = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8').toString('base64');
  const record = await C.wrapDataKey(rawB64, wrapKey, env);
  assert.ok(Array.isArray(record.iv) && record.iv.length === 12);
  assert.ok(Array.isArray(record.wrapped) && record.wrapped.length > 0);
  assert.equal(await C.unwrapDataKey(record, wrapKey, env), rawB64);
}

async function testWrapProbeRejectsNonKey() {
  // Given a non-key handle, when probed, then it reports false instead of
  // throwing.
  const env = webEnv();
  assert.equal(await C.wrapKeyCanEncrypt({}, env), false);
}

async function testWrapProbeFalseWithoutCrypto() {
  // Given no env at all, when probed, then it reports false instead of
  // rejecting (capability access lives inside the probe).
  const wrapKey = await C.generateWrapKey({ subtle: webEnv().subtle });
  assert.equal(await C.wrapKeyCanEncrypt(wrapKey, null), false);
  assert.equal(await C.wrapKeyCanEncrypt(wrapKey, undefined), false);
  assert.equal(await C.wrapKeyCanEncrypt(wrapKey, {}), false);
}

async function testWrapProbeFalseWithoutRandom() {
  // Given subtle but no randomness, when probed, then it reports false
  // instead of rejecting.
  const env = webEnv();
  const wrapKey = await C.generateWrapKey({ subtle: env.subtle });
  assert.equal(await C.wrapKeyCanEncrypt(wrapKey, { subtle: env.subtle }), false);
  assert.equal(
    await C.wrapKeyCanEncrypt(wrapKey, { subtle: env.subtle, getRandomValues: null }),
    false
  );
}

async function testWrapProbeFalseWithoutSubtle() {
  // Given randomness but no subtle provider, when probed, then it reports
  // false instead of rejecting.
  const env = webEnv();
  const wrapKey = await C.generateWrapKey({ subtle: env.subtle });
  assert.equal(
    await C.wrapKeyCanEncrypt(wrapKey, { getRandomValues: env.getRandomValues }),
    false
  );
  assert.equal(await C.wrapKeyCanEncrypt(wrapKey, { subtle: null, getRandomValues: env.getRandomValues }), false);
}

async function testUnwrapNeedsNoRandomCapability() {
  // Given an env without randomness, when unwrapping, then it still
  // succeeds (unwrap never uses randomness).
  const env = webEnv();
  const wrapKey = await C.generateWrapKey({ subtle: env.subtle });
  const rawB64 = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8').toString('base64');
  const record = await C.wrapDataKey(rawB64, wrapKey, env);
  assert.equal(
    await C.unwrapDataKey(record, wrapKey, { subtle: env.subtle, btoaImpl }),
    rawB64
  );
}

async function testPrfImportWrapsAndUnwraps() {
  // Given fixed PRF bytes, when imported, then the resulting key wraps and
  // unwraps through the real unit.
  const env = webEnv();
  const prfBytes = new Uint8Array(32).fill(7);
  const prfKey = await C.importPrfKey(prfBytes, { subtle: env.subtle });
  const rawB64 = Buffer.from('prf-round-trip-key-material-012345', 'utf8').toString('base64');
  const record = await C.wrapDataKey(rawB64, prfKey, env);
  assert.equal(await C.unwrapDataKey(record, prfKey, env), rawB64);
}

async function testSupportsPrfWithExplicitCtor() {
  // Given explicit credential constructors, when checked, then PRF support
  // follows the capability without ambient reach.
  assert.equal(await C.supportsWebAuthnPrf({}), false);
  assert.equal(await C.supportsWebAuthnPrf({ credentialCtor: null }), false);
  assert.equal(await C.supportsWebAuthnPrf({ credentialCtor: {} }), false);
  assert.equal(
    await C.supportsWebAuthnPrf({ credentialCtor: { getClientCapabilities: async () => ({ prf: true }) } }),
    true
  );
  assert.equal(
    await C.supportsWebAuthnPrf({ credentialCtor: { getClientCapabilities: async () => ({ prf: false }) } }),
    false
  );
  assert.equal(
    await C.supportsWebAuthnPrf({ credentialCtor: { getClientCapabilities: async () => { throw new Error('no'); } } }),
    false
  );
}

const cases = [
  ['pbkdf2 constants unchanged', testPbkdf2ConstantsUnchanged],
  ['prf wrap label', testPrfWrapLabel],
  ['base64 round trip with explicit vectors', testBase64RoundTripWithExplicitVectors],
  ['base64 requires explicit impls', testBase64RequiresExplicitImpls],
  ['salt decodes from server base64', testSaltDecodesFromServerBase64],
  ['derive matches independent oracle', testDeriveMatchesIndependentOracle],
  ['derive is deterministic', testDeriveIsDeterministic],
  ['wrap unwrap round trip', testWrapUnwrapRoundTrip],
  ['wrap probe rejects non-key', testWrapProbeRejectsNonKey],
  ['wrap probe false without crypto', testWrapProbeFalseWithoutCrypto],
  ['wrap probe false without random', testWrapProbeFalseWithoutRandom],
  ['wrap probe false without subtle', testWrapProbeFalseWithoutSubtle],
  ['unwrap needs no random capability', testUnwrapNeedsNoRandomCapability],
  ['prf import wraps and unwraps', testPrfImportWrapsAndUnwraps],
  ['supports prf with explicit ctor', testSupportsPrfWithExplicitCtor],
];

(async () => {
  const failures = [];
  for (const [name, fn] of cases) {
    try {
      await fn();
    } catch (error) {
      failures.push(name + ': ' + (error && error.stack ? error.stack : String(error)));
    }
  }
  if (failures.length) {
    console.error('credential crypto FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
  } else {
    console.error('credential crypto: derive/wrap/prf contract holds');
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
