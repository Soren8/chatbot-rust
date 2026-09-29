'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const [caseName, loginPath, chatPath, templatePath] = process.argv.slice(2);
const loginSource = fs.readFileSync(loginPath, 'utf8');
const chatSource = fs.readFileSync(chatPath, 'utf8');
const template = fs.readFileSync(templatePath, 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

function loginHarness(fetchMock) {
  const handlers = {};
  const fields = { username: 'alice', password: 'password', 'saved-account-select': '__other__' };
  const notices = [];
  const removed = [];
  const form = {
    storageKey: null,
    querySelector(selector) {
      assert.equal(selector, 'input[name="storage_key"]');
      return this.storageKey && { remove: () => { this.storageKey = null; } };
    }
  };
  function $(selector, attrs) {
    if (typeof selector === 'function') { selector(); return; }
    if (selector === '<input>') return {
      attr(values) { form.storageKey = values.value; return this; }, appendTo() { return this; }
    };
    const key = selector === form ? 'form' : selector;
    const wrapper = {
      length: 1,
      on(event, fn) { handlers[`${key}:${event}`] = fn; return this; },
      val(value) {
        if (value !== undefined) { fields[key.replace(/^#/, '')] = value; return this; }
        return fields[key.replace(/^#/, '')] || '';
      },
      first() { return this; },
      find() { return this; },
      prop() { return this; }, trigger() { return this; }, toggleClass() { return this; },
      hasClass(name) { return key === '#saved-account-section' && name === 'd-none'; },
      removeClass() { return this; }, addClass() { return this; },
      text(value) { notices.push(value); return this; }
    };
    return wrapper;
  }
  const context = {
    $, window: { isSecureContext: true, crypto: { subtle: {
      importKey: async () => ({}), deriveBits: async () => new Uint8Array(32).buffer
    } }, location: { href: '/login' }, confirm: () => true,
      EncKey: { purgeNonRememberedSlots: () => Promise.resolve(),
        listCachedAccounts: () => Promise.resolve([]), removeSlot: async username => { removed.push(username); } } },
    console: { debug() {}, log() {}, warn() {}, error() {}, info() {} },
    fetch: fetchMock, FormData: class { constructor() { this.entries = [['username', fields.username], ['password', fields.password]]; if (form.storageKey) this.entries.push(['storage_key', form.storageKey]); } [Symbol.iterator]() { return this.entries[Symbol.iterator](); } },
    URL, URLSearchParams, TextEncoder, Uint8Array, btoa, atob, encodeURIComponent,
    document: {}, alert() {}
  };
  vm.runInNewContext(loginSource, context, { filename: loginPath });
  return { handlers, fields, form, notices, removed, context };
}

async function loginCase() {
  const bodies = [];
  let saltAttempts = 0;
  const h = loginHarness(async (url, init) => {
    if (url.startsWith('/auth/salt/')) return ++saltAttempts === 1
      ? { ok: true, json: async () => ({ salt: 'c2FsdA==' }) } : { ok: false };
    if (url === '/login') {
      bodies.push(init.body);
      return { ok: false, url: '/login', json: async () => ({ error: 'Invalid credentials' }) };
    }
    throw Error(`unexpected URL ${url}`);
  });
  await h.handlers['form:submit'].call(h.form, { preventDefault() {} });
  assert.match(bodies[0], /storage_key=/, 'first attempt must submit a derived key');
  await h.handlers['form:submit'].call(h.form, { preventDefault() {} });
  assert.equal(bodies.length, 2);
  assert.equal(new URLSearchParams(bodies[1]).has('storage_key'), false,
    'fallback POST after a derived attempt must omit the stale key');
}

async function forgetCase() {
  const h = loginHarness(async url => {
    assert.equal(url, '/login/forget');
    return { ok: false };
  });
  h.fields['saved-account-select'] = 'alice';
  await h.handlers['#forget-account:click'].call({}, {});
  assert.deepEqual(h.removed, [], 'a failed revoke must preserve the cached slot');
  assert.equal(h.notices.some(text => text.startsWith('Removed')), false);
  assert.equal(h.notices.at(-1), 'Could not forget this account. Please try again.');
  assert.equal(h.context.window.location.href, '/login');
}

async function logoutCase() {
  const start = chatSource.indexOf('function logoutThisComputer() {');
  const end = chatSource.indexOf('// Settings panel behavior', start);
  assert.ok(start >= 0 && end > start, 'logout action exists');
  let removed = false;
  const alerts = [];
  const window = { APP_DATA: { username: 'alice' }, CSRF_TOKEN: 'csrf',
    location: { href: '/chat' }, confirm: () => true,
    EncKey: { removeSlot: async () => { removed = true; } } };
  const context = { window, fetch: async () => ({ ok: false }), alert: text => alerts.push(text),
    console: { debug() {} }, encodeURIComponent };
  vm.runInNewContext(chatSource.slice(start, end), context);
  context.logoutThisComputer();
  await tick();
  assert.equal(removed, false, 'a failed revoke must preserve the cached slot');
  assert.equal(window.location.href, '/chat', 'a failed revoke must not navigate to logout');
  assert.deepEqual(alerts, ['Could not forget this account. Please try again.']);
}

async function privacyCase() {
  const options = template.match(/<select id="privacy-select"[^>]*>([\s\S]*?)<\/select>/);
  assert.ok(options, 'saved-chat privacy selector exists');
  assert.deepEqual([...options[1].matchAll(/<option value="([^"]+)"/g)].map(m => m[1]),
    ['private', 'standard', 'non_private']);
  assert.match(template, /Standard:[^<]*limited[^<]*retention/i);
  assert.match(template, /history encrypted/i);

  const start = chatSource.indexOf("$('#privacy-select').on('change'");
  const end = chatSource.indexOf('function loadSets(', start);
  assert.ok(start >= 0 && end > start, 'privacy change action exists');
  const handlers = {};
  const prompts = [];
  const posts = [];
  const window = { APP_DATA: { loggedIn: true, setVersion: 1 } };
  const context = {
    window, confirm: message => { prompts.push(message); return false; },
    $: selector => ({ on: (event, fn) => { handlers[event] = fn; }, text() {} }),
    chatPolicyReady: () => true, captureVoiceBinding: () => ({ setId: 'set-1' }),
    PRIVACY_LEVELS: ['private', 'standard', 'non_private'],
    SELECTABLE_PRIVACY_LEVELS: vm.runInNewContext(
      chatSource.match(/^const SELECTABLE_PRIVACY_LEVELS = [^\n]+/m)[0] + '\nSELECTABLE_PRIVACY_LEVELS;'),
    loadedPrivacy: { setId: 'set-1', level: 'private' },
    fetch: async (...args) => { posts.push(args); throw Error('cancelled confirmation must not POST'); }
  };
  vm.runInNewContext(chatSource.slice(start, end), context);
  assert.equal(typeof handlers.change, 'function');
  await handlers.change.call({ value: 'standard' });
  assert.equal(posts.length, 0, 'declined Standard confirmation does not POST');
  assert.match(prompts[0], /Standard.*limited or anonymized retention/i);
  assert.match(prompts[0], /Earlier transmissions cannot be undone/i);
  await handlers.change.call({ value: 'non_private' });
  assert.equal(posts.length, 0, 'declined Non-private confirmation does not POST');
  assert.match(prompts[1], /Non-private.*retain data or train/i);

  context.confirm = () => true;
  context.fetch = async (url, options) => {
    posts.push({ url, payload: JSON.parse(options.body) });
    return { ok: false, json: async () => ({ error: 'privacy_busy' }) };
  };
  context.withCsrf = headers => headers;
  context.refreshPrivacyControls = () => {};
  context.isLiveMemoryBinding = () => true;
  await handlers.change.call({ value: 'standard' });
  assert.equal(posts.length, 1, 'accepted Standard transition submits a mode change');
  assert.equal(posts[0].url, '/set_privacy');
  assert.equal(posts[0].payload.privacy_level, 'standard');
}

({ login: loginCase, forget: forgetCase, logout: logoutCase, privacy: privacyCase })[caseName]()
  .catch(err => { console.error(err); process.exitCode = 1; });
