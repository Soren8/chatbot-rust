'use strict';
// Behavior contract for static/credential-metadata.js: per-account cached
// login slot-metadata policy. Pure policy only — no IndexedDB, no window,
// no key material — exercised through the stable UMD import with explicit
// literal expectations.
const assert = require('node:assert/strict');

const modPath = process.argv[2];
assert(modPath, 'usage: node credential_metadata_test.js <static/credential-metadata.js>');
const M = require(modPath);

function testSlotKeyPrefixesTrimmedUsername() {
  // Given an explicit account, when building its slot key, then the legacy
  // 'acct:' prefix applies and surrounding whitespace is trimmed.
  assert.equal(M.slotKeyFor('alice', null), 'acct:alice');
  assert.equal(M.slotKeyFor('  bob  ', null), 'acct:bob');
  assert.equal(M.slotKeyFor(null, 'carol'), 'acct:carol');
  assert.equal(M.slotKeyFor(null, '  dave  '), 'acct:dave');
}

function testSlotKeyThrowsWithoutAccount() {
  // Given no account and no fallback, when building a slot key, then the
  // legacy contract error is thrown.
  assert.throws(() => M.slotKeyFor(null, null), /No account selected for key storage/);
  assert.throws(() => M.slotKeyFor('', ''), /No account selected for key storage/);
}

function testSlotKeyPredicates() {
  // Given slot and non-slot keys, when classified, then only 'acct:' keys
  // match and the username round-trips through the prefix.
  assert.equal(M.isAccountSlotKey('acct:alice'), true);
  assert.equal(M.isAccountSlotKey('wrapped-data-key'), false);
  assert.equal(M.isAccountSlotKey(null), false);
  assert.equal(M.accountNameFromSlotKey('acct:alice'), 'alice');
  assert.equal(M.SLOT_PREFIX, 'acct:');
}

function testHashedSlotsAreHidden() {
  // Given a legacy 64-hex slot username, when checked, then it is hashed
  // (the server no longer maps hashes, so it must never list).
  const hashed = 'a'.repeat(64);
  assert.equal(M.isHashedSlotUsername(hashed), true);
  assert.equal(M.isHashedSlotUsername('alice'), false);
  assert.equal(M.isHashedSlotUsername('ABC'), false);
}

function testFilterListsOnlyRememberedFreshSlotsNewestFirst() {
  // Given mixed slot entries, when filtering, then only remembered, fresh,
  // non-hashed slots list, newest first.
  const now = 1_700_000_000_000;
  const hashed = 'b'.repeat(64);
  const entries = [
    { key: 'acct:alice', value: { remembered: true, updatedAt: now - 1000 } },
    { key: 'acct:bob', value: { remembered: true, updatedAt: now - 100 } },
    { key: 'acct:plain', value: { remembered: false, updatedAt: now - 50 } },
    { key: 'acct:' + hashed, value: { remembered: true, updatedAt: now - 10 } },
    { key: 'acct:stale', value: { remembered: true, updatedAt: now - M.MAX_CACHED_ACCOUNT_AGE_MS - 1 } },
    { key: 'wrapped-data-key', value: { remembered: true, updatedAt: now } },
    { key: 'acct:novalue', value: null },
  ];
  assert.deepEqual(M.filterCachedAccounts(entries, now), ['bob', 'alice']);
}

function testFilterDefaultsRememberedAndHandlesEmpty() {
  // Given a slot without an explicit remembered flag, when filtering, then
  // it defaults to listed (legacy remembered !== false). Empty input lists
  // nothing.
  const now = 1_700_000_000_000;
  assert.deepEqual(
    M.filterCachedAccounts([{ key: 'acct:erin', value: { updatedAt: now } }], now),
    ['erin']
  );
  assert.deepEqual(M.filterCachedAccounts([], now), []);
  assert.deepEqual(M.filterCachedAccounts(null, now), []);
}

function testFilterHidesSlotsWithoutTimestamp() {
  // Given a remembered slot with no updatedAt, when filtering, then it is
  // hidden (legacy updatedAt gate).
  const now = 1_700_000_000_000;
  assert.deepEqual(
    M.filterCachedAccounts([{ key: 'acct:frank', value: { remembered: true } }], now),
    []
  );
}

function testTouchBumpsTimestampWithoutMutatingInput() {
  // Given a slot record, when touched, then a copy carries the new timestamp
  // and the input record is unchanged.
  const record = { mode: 'cookie', remembered: true, updatedAt: 100 };
  const next = M.touchSlotRecord(record, 200);
  assert.equal(next.updatedAt, 200);
  assert.equal(next.mode, 'cookie');
  assert.equal(record.updatedAt, 100);
}

function testSlotVisibilityPredicate() {
  // Given mapped slot rows, when checked, then remembered + fresh +
  // non-hashed rows are visible and every other shape is hidden.
  const now = 1_700_000_000_000;
  assert.equal(M.isSlotEntryVisible({ username: 'alice', remembered: true, updatedAt: now }, now), true);
  assert.equal(M.isSlotEntryVisible({ username: 'alice', remembered: false, updatedAt: now }, now), false);
  assert.equal(M.isSlotEntryVisible({ username: 'c'.repeat(64), remembered: true, updatedAt: now }, now), false);
  assert.equal(M.isSlotEntryVisible({ username: 'alice', remembered: true, updatedAt: 0 }, now), false);
  assert.equal(M.isSlotEntryVisible(null, now), false);
}

function testPurgeListsOnlyOptedOutSlots() {
  // Given mixed slot entries, when collecting purge candidates, then only
  // opted-out (remembered === false) account slots return as usernames.
  const entries = [
    { key: 'acct:alice', value: { remembered: false, updatedAt: 1 } },
    { key: 'acct:bob', value: { remembered: true, updatedAt: 2 } },
    { key: 'acct:carol', value: { updatedAt: 3 } },
    { key: 'wrapped-data-key', value: { remembered: false, updatedAt: 4 } },
    { key: 'acct:novalue', value: null },
  ];
  assert.deepEqual(M.purgeableSlotUsernames(entries), ['alice']);
  assert.deepEqual(M.purgeableSlotUsernames([]), []);
  assert.deepEqual(M.purgeableSlotUsernames(null), []);
}

const cases = [
  ['slot key prefixes trimmed username', testSlotKeyPrefixesTrimmedUsername],
  ['slot key throws without account', testSlotKeyThrowsWithoutAccount],
  ['slot key predicates', testSlotKeyPredicates],
  ['hashed slots are hidden', testHashedSlotsAreHidden],
  ['filter lists only remembered fresh slots newest first', testFilterListsOnlyRememberedFreshSlotsNewestFirst],
  ['filter defaults remembered and handles empty', testFilterDefaultsRememberedAndHandlesEmpty],
  ['filter hides slots without timestamp', testFilterHidesSlotsWithoutTimestamp],
  ['touch bumps timestamp without mutating input', testTouchBumpsTimestampWithoutMutatingInput],
  ['slot visibility predicate', testSlotVisibilityPredicate],
  ['purge lists only opted-out slots', testPurgeListsOnlyOptedOutSlots],
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
    console.error('credential metadata FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
  } else {
    console.error('credential metadata: slot naming/listing/touch contract holds');
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
