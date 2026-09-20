(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatCredentialMetadata = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Per-account cached-login slot-metadata policy. Pure helpers only —
  // no store access, no browser globals, no derivation, no key material.
  // enc-key.js keeps store access and the EncKey public surface and
  // delegates slot naming / listing / touch policy here.
  //
  // Slot record shape (owned by enc-key.js storage):
  //   key: 'acct:<username>' (SLOT_PREFIX + trimmed username)
  //   value: { mode, remembered, updatedAt }
  // Only slots with remembered !== false stay listed; legacy hashed-slot
  // entries and slots older than 30 days stay hidden.

  var SLOT_PREFIX = 'acct:';
  var MAX_CACHED_ACCOUNT_AGE_MS = 30 * 24 * 3600 * 1000;
  var HASHED_SLOT_RE = /^[0-9a-f]{64}$/;

  function normalizeUsername(name) {
    return String(name).trim();
  }

  // Slot key for an explicit account with an explicit fallback (the caller
  // resolves the page's account name). Throws when neither is present,
  // preserving the legacy 'No account selected for key storage' contract.
  function slotKeyFor(username, fallbackUsername) {
    var name = username || fallbackUsername;
    if (!name) {
      throw new Error('No account selected for key storage');
    }
    return SLOT_PREFIX + normalizeUsername(name);
  }

  function isAccountSlotKey(key) {
    return typeof key === 'string' && key.startsWith(SLOT_PREFIX);
  }

  function accountNameFromSlotKey(slotKey) {
    return String(slotKey).slice(SLOT_PREFIX.length);
  }

  function isHashedSlotUsername(username) {
    return HASHED_SLOT_RE.test(String(username));
  }

  // Single-entry visibility predicate used by the cached-account listing:
  // remembered slots only, no legacy hashed slots, no stale (>30d) slots.
  function isSlotEntryVisible(mapped, nowMs) {
    if (!mapped || !mapped.remembered) {
      return false;
    }
    if (isHashedSlotUsername(mapped.username)) {
      return false;
    }
    if (!mapped.updatedAt) {
      return false;
    }
    return (nowMs - mapped.updatedAt) <= MAX_CACHED_ACCOUNT_AGE_MS;
  }

  // Given raw IndexedDB entries [{key, value}], when listing cached accounts,
  // then return recency-sorted visible usernames (newest first). Entries with
  // missing values are ignored; mapping preserves the legacy remembered
  // default (remembered !== false) and updatedAt default (0).
  function filterCachedAccounts(entries, nowMs) {
    var now = Number(nowMs);
    if (!entries || !entries.length) {
      return [];
    }
    var mapped = [];
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      if (!entry || typeof entry.key !== 'string' || !entry.key.startsWith(SLOT_PREFIX) || !entry.value) {
        continue;
      }
      mapped.push({
        username: entry.key.slice(SLOT_PREFIX.length),
        remembered: entry.value.remembered !== false,
        updatedAt: entry.value.updatedAt || 0
      });
    }
    var visible = [];
    for (var j = 0; j < mapped.length; j++) {
      if (isSlotEntryVisible(mapped[j], now)) {
        visible.push(mapped[j]);
      }
    }
    visible.sort(function (a, b) { return b.updatedAt - a.updatedAt; });
    var out = [];
    for (var k = 0; k < visible.length; k++) {
      out.push(visible[k].username);
    }
    return out;
  }

  // Pure last-used bump: returns a copy with updatedAt set. The caller
  // persists it (idbSet). Returns the input unchanged when it is not a
  // record object.
  function touchSlotRecord(record, nowMs) {
    if (!record || typeof record !== 'object') {
      return record;
    }
    var next = {};
    for (var key in record) {
      if (Object.prototype.hasOwnProperty.call(record, key)) {
        next[key] = record[key];
      }
    }
    next.updatedAt = nowMs;
    return next;
  }

  // Usernames whose slots opted out of remember (remembered === false).
  // enc-key.js purges exactly these via removeSlot; no other policy here.
  function purgeableSlotUsernames(entries) {
    var out = [];
    if (!entries || !entries.length) {
      return out;
    }
    for (var i = 0; i < entries.length; i++) {
      var entry = entries[i];
      if (!entry || !isAccountSlotKey(entry.key) || !entry.value) {
        continue;
      }
      if (entry.value.remembered !== false) {
        continue;
      }
      out.push(accountNameFromSlotKey(entry.key));
    }
    return out;
  }

  return {
    SLOT_PREFIX: SLOT_PREFIX,
    MAX_CACHED_ACCOUNT_AGE_MS: MAX_CACHED_ACCOUNT_AGE_MS,
    slotKeyFor: slotKeyFor,
    isAccountSlotKey: isAccountSlotKey,
    accountNameFromSlotKey: accountNameFromSlotKey,
    isHashedSlotUsername: isHashedSlotUsername,
    isSlotEntryVisible: isSlotEntryVisible,
    filterCachedAccounts: filterCachedAccounts,
    touchSlotRecord: touchSlotRecord,
    purgeableSlotUsernames: purgeableSlotUsernames
  };
}));
