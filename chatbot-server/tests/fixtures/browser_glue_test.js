'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function load(path, globals) {
  const context = vm.createContext(globals);
  vm.runInContext(fs.readFileSync(path, 'utf8'), context, { filename: path });
  return context;
}

function testTrustedTypes(path) {
  const calls = [];
  const context = load(path, {
    window: {},
    trustedTypes: { createPolicy(name, rules) { calls.push(name); return rules; } }
  });
  assert.deepEqual(calls, ['default', 'chatbot']);
  assert.equal(context.window.__chatbotTt.createHTML('<b>input</b>'), '<b>input</b>');
  const withoutTrustedTypes = load(path, { window: {} });
  assert.equal(withoutTrustedTypes.window.__chatbotTt, undefined);
  console.log('PASS tt.js policy creation and absent Trusted Types');
}

async function testNativeBridge(path) {
  const context = load(path, { window: {} });
  const bridge = context.window.NativeBridge;
  assert.equal(bridge.isNativePlatform(), false);
  await assert.rejects(bridge.callNativePlugin('Example', 'run', {}), /Not a native platform/);
  context.window.Capacitor = { isNativePlatform: () => false };
  assert.equal(bridge.isNativePlatform(), false);
  await assert.rejects(bridge.callNativePlugin('Example', 'run', {}), /Not a native platform/);

  let lookups = 0;
  const calls = [];
  const plugin = { run: (...args) => { calls.push(args); return Promise.resolve('ok'); },
    fail: () => Promise.reject(new Error('plugin failed')) };
  context.window.Capacitor = { isNativePlatform: () => true, registerPlugin(name) { lookups++; assert.equal(name, 'Example'); return plugin; } };
  assert.equal(await bridge.callNativePlugin('Example', 'run', { value: 7 }), 'ok');
  assert.equal(await bridge.callNativePlugin('Example', 'run', { value: 8 }), 'ok');
  assert.equal(lookups, 1);
  assert.deepEqual(calls, [[{ value: 7 }], [{ value: 8 }]]);
  await assert.rejects(bridge.callNativePlugin('Example', 'fail', {}), /plugin failed/);
  let opened = 0;
  context.window.Capacitor.registerPlugin = name => {
    lookups++;
    assert.equal(name, 'ServerSettings');
    return { open: () => { opened++; return Promise.resolve('opened'); } };
  };
  assert.equal(await bridge.openServerSettings(), 'opened');
  assert.equal(opened, 1);
  console.log('PASS native-bridge.js detection, fallback, caching, forwarding and settings');
}

async function testAgentConnections(path) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) {
      const listeners = {};
      elements.set(id, {
        id, value: '', textContent: '', hidden: false, disabled: false, required: false,
        children: [], style: {}, listeners,
        addEventListener(type, callback) { listeners[type] = callback; },
        replaceChildren(...children) { this.children = children; this.textContent = ''; },
        appendChild(child) { this.children.push(child); },
        reset() { for (const field of ['connection-name', 'connection-url', 'connection-username', 'connection-password']) element(field).value = ''; },
        focus() {},
        setAttribute() {}
      });
    }
    return elements.get(id);
  }
  const ids = ['connections-settings', 'connections-list', 'connections-status', 'connection-form',
    'connection-name', 'connection-url', 'connection-username', 'connection-password', 'connection-save',
    'connections-refresh', 'connection-cancel', 'connection-form-title', 'connection-password-hint'];
  for (const id of ids) element(id);
  const requests = [];
  let createFails = false;
  const ctx = load(path, {
    window: { APP_DATA: { agentConnectionsEnabled: true }, CSRF_TOKEN: 'csrf',
      activitySync: { async request(url, options) {
        requests.push({ url, options });
        if (url === '/agent_connections' && options.method === 'GET') return { ok: true, status: 200, json: async () => [{ id: 'c1', name: 'Existing', base_url: 'https://agent.example', username: 'opencode', revision: 2 }] };
        if (url === '/agent_connections' && options.method === 'POST' && createFails) return { ok: false, status: 400, json: async () => ({ error: 'connection_limit_reached' }) };
        if (url === '/agent_connections' && options.method === 'POST') return { ok: true, status: 201, json: async () => ({}) };
        throw new Error('Unexpected request ' + options.method + ' ' + url);
      } } },
    document: { getElementById: element, createElement: tag => element('created-' + elements.size + '-' + tag) },
    confirm: () => true,
    Date
  });
  const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
  await flush();
  assert.match(element('connections-list').children[0].children[0].textContent, /Existing/);
  assert.equal(element('connections-status').textContent, '');

  element('connection-name').value = 'New connection';
  element('connection-url').value = 'https://new.example';
  element('connection-username').value = 'operator';
  element('connection-password').value = 'secret';
  element('connection-form').listeners.submit({ preventDefault() {} });
  await flush();
  const add = requests.find(request => request.options.method === 'POST');
  assert.equal(add.url, '/agent_connections');
  assert.deepEqual(JSON.parse(add.options.body), { name: 'New connection', base_url: 'https://new.example', username: 'operator', kind: 'opencode', password: 'secret' });
  assert.equal(add.options.headers['X-CSRF-Token'], 'csrf');
  assert.equal(element('connections-status').textContent, 'Connection saved.');

  createFails = true;
  element('connection-name').value = 'At limit';
  element('connection-url').value = 'https://new.example';
  element('connection-username').value = 'operator';
  element('connection-password').value = 'secret';
  element('connection-form').listeners.submit({ preventDefault() {} });
  await flush();
  assert.equal(element('connections-status').textContent, 'Connection limit reached.');
  console.log('PASS agent-connections.js load, add request and failed-request status');
}

(async () => {
  testTrustedTypes(process.argv[2]);
  await testNativeBridge(process.argv[3]);
  await testAgentConnections(process.argv[4]);
})().catch(error => { console.error(error); process.exitCode = 1; });
