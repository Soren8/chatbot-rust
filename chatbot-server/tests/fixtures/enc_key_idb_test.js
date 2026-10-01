'use strict';
// IndexedDB lifecycle for static/enc-key.js against a counting fake
// indexedDB in a VM context. A clean page load must open one connection
// and run no readwrite transaction; later operations reuse the connection;
// a versionchange closes it and the next operation reopens; the load-time
// scrub still removes/rewrites exactly the records it always did.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const [encKeyPath, metadataPath] = process.argv.slice(2);
assert(encKeyPath && metadataPath, 'usage: node enc_key_idb_test.js <enc-key.js> <credential-metadata.js>');
const encKeySrc = fs.readFileSync(encKeyPath, 'utf8');
const metadataSrc = fs.readFileSync(metadataPath, 'utf8');

// Records written inside the VM come from another realm; compare as JSON.
function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function later(fn) {
  setImmediate(fn);
}

function createFakeIndexedDb(initial) {
  const data = new Map(initial || []);
  const stats = { opens: 0, readwrite: 0, readonly: 0, closes: 0, connections: [] };
  let created = initial !== undefined;

  function makeDb() {
    const db = {
      closed: false,
      onversionchange: null,
      onclose: null,
      objectStoreNames: { contains: (name) => created && name === 'keys' },
      createObjectStore(name) {
        assert.equal(name, 'keys');
        created = true;
      },
      close() {
        db.closed = true;
        stats.closes += 1;
      },
      transaction(name, mode) {
        assert.equal(name, 'keys');
        assert(!db.closed, 'transaction on a closed connection');
        if (mode === 'readwrite') {
          stats.readwrite += 1;
        } else {
          assert.equal(mode, 'readonly');
          stats.readonly += 1;
        }
        let pending = 0;
        let done = false;
        const tx = { oncomplete: null, onerror: null, error: null };
        function settle() {
          later(() => {
            if (!done && pending === 0) {
              done = true;
              if (tx.oncomplete) tx.oncomplete();
            }
          });
        }
        function request(run) {
          assert(!done, 'request after transaction completed');
          pending += 1;
          const req = { result: undefined, error: null, onsuccess: null, onerror: null };
          later(() => {
            req.result = run();
            pending -= 1;
            if (req.onsuccess) req.onsuccess();
            settle();
          });
          return req;
        }
        function write(run) {
          assert.equal(mode, 'readwrite', 'write in a readonly transaction');
          return request(run);
        }
        tx.objectStore = () => ({
          get: (key) => request(() => data.get(key)),
          getAll: () => request(() => Array.from(data.values())),
          getAllKeys: () => request(() => Array.from(data.keys())),
          put: (value, key) => write(() => { data.set(key, value); return key; }),
          delete: (key) => write(() => { data.delete(key); }),
        });
        settle();
        return tx;
      },
    };
    stats.connections.push(db);
    return db;
  }

  const indexedDB = {
    open(name, version) {
      assert.equal(name, 'chatbot-enc-key');
      assert.equal(version, 1);
      stats.opens += 1;
      const req = { result: null, error: null, onsuccess: null, onerror: null, onupgradeneeded: null };
      later(() => {
        req.result = makeDb();
        if (!created && req.onupgradeneeded) req.onupgradeneeded();
        if (req.onsuccess) req.onsuccess();
      });
      return req;
    },
  };
  return { indexedDB, data, stats };
}

function load(fake) {
  const ctx = {
    indexedDB: fake.indexedDB,
    console: { debug() {}, error() {} },
    sessionStorage: { removeItem() {} },
    setImmediate,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(metadataSrc, ctx, { filename: 'credential-metadata.js' });
  vm.runInContext(encKeySrc, ctx, { filename: 'enc-key.js' });
  return ctx;
}

async function flush() {
  for (let i = 0; i < 50; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function testCleanPageLoadOpensOnceWithoutWrites() {
  // Given an empty store, when enc-key.js loads, then the scrub opens one
  // connection and runs no readwrite transaction.
  const fake = createFakeIndexedDb();
  load(fake);
  await flush();
  assert.equal(fake.stats.opens, 1, 'clean load must open exactly one connection');
  assert.equal(fake.stats.readwrite, 0, 'clean load must not open a readwrite transaction');
}

async function testCleanSlotsLoadOpensOnceWithoutWrites() {
  // Given only cookie-mode and PRF slots, when enc-key.js loads, then there
  // is nothing to scrub: one connection, no readwrite, records untouched.
  const prf = { wrapped: { iv: 'i', ct: 'c' }, mode: 'webauthn-prf', updatedAt: 5 };
  const cookie = { mode: 'cookie', remembered: true, updatedAt: 7 };
  const fake = createFakeIndexedDb([['acct:alice', cookie], ['acct:bob', prf]]);
  load(fake);
  await flush();
  assert.equal(fake.stats.opens, 1);
  assert.equal(fake.stats.readwrite, 0);
  assert.deepEqual(plain(fake.data.get('acct:alice')), cookie);
  assert.deepEqual(plain(fake.data.get('acct:bob')), prf);
}

async function testDirtyLoadScrubsSameRecords() {
  // Given a device wrap key, a legacy wrapped slot, wrapped non-PRF slots
  // and a PRF slot, when enc-key.js loads, then the wrap key and legacy
  // slot are deleted, wrapped non-PRF slots become cookie records, and the
  // PRF slot plus unrelated records are untouched.
  const prf = { wrapped: { iv: 'i', ct: 'c' }, mode: 'webauthn-prf', updatedAt: 5 };
  const fake = createFakeIndexedDb([
    ['device-wrap', { kind: 'aes' }],
    ['wrapped-data-key', { wrapped: 'legacy', iv: 'x' }],
    ['storage-mode', 'indexeddb'],
    ['acct:carol', { wrapped: { iv: 'a' }, mode: 'indexeddb', updatedAt: 11 }],
    ['acct:dave', { wrapped: { iv: 'b' }, mode: 'indexeddb', remembered: false, updatedAt: 12 }],
    ['acct:erin', prf],
    ['acct:frank', { mode: 'cookie', remembered: false, updatedAt: 13 }],
  ]);
  load(fake);
  await flush();
  assert.equal(fake.data.has('device-wrap'), false, 'device wrap key must be scrubbed');
  assert.equal(fake.data.has('wrapped-data-key'), false, 'legacy wrapped slot must be scrubbed');
  assert.equal(fake.data.get('storage-mode'), 'indexeddb', 'legacy mode marker is not scrubbed at load');
  assert.deepEqual(plain(fake.data.get('acct:carol')), { mode: 'cookie', remembered: true, updatedAt: 11 });
  assert.deepEqual(plain(fake.data.get('acct:dave')), { mode: 'cookie', remembered: false, updatedAt: 12 });
  assert.deepEqual(plain(fake.data.get('acct:erin')), prf);
  assert.deepEqual(plain(fake.data.get('acct:frank')), { mode: 'cookie', remembered: false, updatedAt: 13 });
  assert.equal(fake.stats.opens, 1, 'dirty load still uses one connection');
  assert(fake.stats.readwrite >= 1, 'dirty load must write');
}

async function testWrapKeyOnlyIsDeleted() {
  // Given only a stale device wrap key, when enc-key.js loads, then it is
  // deleted (the scrub writes only because something must go).
  const fake = createFakeIndexedDb([['device-wrap', { kind: 'aes' }]]);
  load(fake);
  await flush();
  assert.equal(fake.data.has('device-wrap'), false);
  assert.equal(fake.stats.readwrite, 1);
}

async function testOperationsReuseConnection() {
  // Given a loaded page, when several EncKey operations run, then they all
  // reuse the single cached connection.
  const fake = createFakeIndexedDb([['acct:alice', { mode: 'cookie', remembered: true, updatedAt: Date.now() }]]);
  const ctx = load(fake);
  await flush();
  await ctx.EncKey.listCachedAccounts();
  await ctx.EncKey.touchSlot('alice');
  assert.equal(await ctx.EncKey.verifyStoredKey(null, 'alice'), true);
  await ctx.EncKey.removeSlot('alice');
  assert.equal(fake.data.has('acct:alice'), false);
  assert.equal(fake.stats.opens, 1, 'operations must reuse one connection');
}

async function testUnexpectedCloseReopens() {
  // Given an unexpectedly closed connection, the cached promise is cleared
  // and the next operation opens a replacement connection.
  const fake = createFakeIndexedDb([['acct:alice', { mode: 'cookie', remembered: true, updatedAt: Date.now() }]]);
  const ctx = load(fake);
  await flush();
  const first = fake.stats.connections[0];
  assert.equal(typeof first.onclose, 'function', 'connection must handle close');
  first.onclose();
  assert.equal(await ctx.EncKey.verifyStoredKey(null, 'alice'), true);
  assert.equal(fake.stats.opens, 2, 'next operation must reopen after close');
  await ctx.EncKey.verifyStoredKey(null, 'alice');
  assert.equal(fake.stats.opens, 2, 'replacement connection is cached');
}

async function testVersionChangeClosesAndReopens() {
  // Given an open cached connection, when another context bumps the schema
  // (versionchange), then the connection is closed and the next operation
  // opens a fresh one.
  const fake = createFakeIndexedDb([['acct:alice', { mode: 'cookie', remembered: true, updatedAt: Date.now() }]]);
  const ctx = load(fake);
  await flush();
  const first = fake.stats.connections[0];
  assert.equal(typeof first.onversionchange, 'function', 'connection must handle versionchange');
  first.onversionchange();
  assert.equal(first.closed, true, 'versionchange must close the connection');
  assert.equal(await ctx.EncKey.verifyStoredKey(null, 'alice'), true);
  assert.equal(fake.stats.opens, 2, 'next operation must reopen after versionchange');
  await ctx.EncKey.verifyStoredKey(null, 'alice');
  assert.equal(fake.stats.opens, 2, 'reopened connection is cached again');
}

(async () => {
  await testCleanPageLoadOpensOnceWithoutWrites();
  await testCleanSlotsLoadOpensOnceWithoutWrites();
  await testDirtyLoadScrubsSameRecords();
  await testWrapKeyOnlyIsDeleted();
  await testOperationsReuseConnection();
  await testUnexpectedCloseReopens();
  await testVersionChangeClosesAndReopens();
  console.log('enc_key_idb_test: ok');
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
