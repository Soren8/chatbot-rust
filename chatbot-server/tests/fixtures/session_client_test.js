'use strict';
// Behavior contract for static/session-client.js: owned HTTP/session client.
// Covers headers/CSRF refresh, single bootstrap sharing/error recovery,
// retry eligibility/count/delay/body, AbortSignal, 401 classification and
// independent instances through the real client (stable import).
const assert = require('node:assert/strict');

const modPath = process.argv[2];
assert(modPath, 'usage: node session_client_test.js <static/session-client.js>');
const S = require(modPath);

function mockResponse(opts) {
  opts = opts || {};
  const status = opts.status != null ? opts.status : 200;
  const ok = opts.ok != null ? opts.ok : (status >= 200 && status < 300);
  const jsonBody = opts.jsonBody;
  const textBody = opts.textBody != null ? opts.textBody : '';
  return {
    ok,
    status,
    headers: opts.headers || { get() { return null; } },
    json() { return Promise.resolve(jsonBody); },
    text() { return Promise.resolve(textBody); },
    clone() {
      return {
        json() { return Promise.resolve(jsonBody); },
        text() { return Promise.resolve(textBody); },
      };
    },
  };
}

function clientWith(overrides) {
  overrides = overrides || {};
  const state = {
    loggedIn: overrides.loggedIn != null ? overrides.loggedIn : true,
    csrf: overrides.csrf !== undefined ? overrides.csrf : 'csrf-1',
    redirected: 0,
    setTokens: [],
    delays: [],
    calls: [],
    bootstrapCalls: [],
  };
  const fetchImpl = overrides.fetchImpl || (async () => mockResponse({ status: 200 }));
  const bootstrapFetch = overrides.bootstrapFetch || (async (url, init) => {
    state.bootstrapCalls.push({ url, init });
    return mockResponse({ status: 200 });
  });
  const client = S.createSessionClient({
    fetchImpl: (url, init) => {
      state.calls.push({ url, init });
      return fetchImpl(url, init, state);
    },
    bootstrapFetch: (url, init) => {
      state.bootstrapCalls.push({ url, init });
      return bootstrapFetch(url, init, state);
    },
    getLoggedIn: () => state.loggedIn,
    getCsrfToken: () => state.csrf,
    setCsrfToken: (t) => { state.csrf = t; state.setTokens.push(t); },
    redirectHome: () => { state.redirected++; },
    sleep: (ms) => { state.delays.push(ms); return Promise.resolve(); },
    xhrFactory: overrides.xhrFactory,
  });
  return { client, state };
}

function fakeXhrQueue(script, record) {
  // script: array of {status, responseText} or {error:'network'|'timeout'}.
  let i = 0;
  return () => {
    const step = script[Math.min(i++, script.length - 1)];
    const headers = {};
    const xhr = {
      headers,
      timeout: 0,
      upload: {},
      open() {},
      setRequestHeader(name, value) { headers[name] = value; },
      abort() {
        if (xhr.onabort) xhr.onabort();
      },
      send(body) {
        record.push({ body, headers: Object.assign({}, headers), step: i });
        setImmediate(() => {
          if (step && step.error === 'network') {
            if (xhr.onerror) xhr.onerror();
          } else if (step && step.error === 'timeout') {
            if (xhr.ontimeout) xhr.ontimeout();
          } else {
            xhr.status = step ? step.status : 200;
            xhr.responseText = step && step.responseText != null ? step.responseText : '{}';
            if (xhr.onload) xhr.onload();
          }
        });
      },
    };
    return xhr;
  };
}

async function testCsrfHeadersCarryToken() {
  // Given a stored CSRF token, when building headers, then the token rides along.
  const { client } = clientWith({ csrf: 'tok-abc' });
  assert.deepEqual(client.withCsrf({ 'Content-Type': 'application/json' }),
    { 'Content-Type': 'application/json', 'X-CSRF-Token': 'tok-abc' });
  const asyncHeaders = await client.withCsrfAsync({});
  assert.deepEqual(asyncHeaders, { 'X-CSRF-Token': 'tok-abc' });

  // Given no token, when building headers, then nothing is added.
  const { client: anon } = clientWith({ csrf: null });
  assert.deepEqual(anon.withCsrf({ a: 'b' }), { a: 'b' });
  assert.deepEqual(await anon.withCsrfAsync(undefined), {});
}

async function testRefreshCsrfInitRebuildsOnlyToken() {
  // Given headers snapshotted before a refresh, when rebuilding, then only the
  // token header is refreshed and other headers survive.
  const { client, state } = clientWith({ csrf: 'old' });
  const init = { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'old' }, body: '{}' };
  state.csrf = 'new';
  const fresh = client.refreshCsrfInit(init);
  assert.equal(fresh.headers['X-CSRF-Token'], 'new');
  assert.equal(fresh.headers['Content-Type'], 'application/json');
  assert.equal(init.headers['X-CSRF-Token'], 'old', 'cached init must not mutate');

  // Given a Headers instance, when rebuilding, then the token is still refreshed.
  const h = new Headers({ 'X-CSRF-Token': 'old', 'Content-Type': 'text/plain' });
  state.csrf = 'new2';
  const fresh2 = client.refreshCsrfInit({ method: 'POST', headers: h });
  assert.equal(fresh2.headers['x-csrf-token'] || fresh2.headers['X-CSRF-Token'], 'new2');
  assert.equal(fresh2.headers['content-type'] || fresh2.headers['Content-Type'], 'text/plain');

  // Given lowercase header name, when rebuilding, then it is still refreshed.
  state.csrf = 'new3';
  const fresh3 = client.refreshCsrfInit({ headers: { 'x-csrf-token': 'old' } });
  assert.equal(fresh3.headers['x-csrf-token'], 'new3');
}

async function testRetryableStatusMatchesContract() {
  // Given voice transport statuses, when classified through the real client,
  // then only transient failures retry (408/429/5xx), never 400/401/404.
  const { client } = clientWith({});
  assert.equal(client.isRetryableVoiceStatus(408), true);
  assert.equal(client.isRetryableVoiceStatus(429), true);
  assert.equal(client.isRetryableVoiceStatus(502), true);
  assert.equal(client.isRetryableVoiceStatus(503), true);
  assert.equal(client.isRetryableVoiceStatus(504), true);
  assert.equal(client.isRetryableVoiceStatus(500), true);
  assert.equal(client.isRetryableVoiceStatus(599), true);
  assert.equal(client.isRetryableVoiceStatus(400), false);
  assert.equal(client.isRetryableVoiceStatus(401), false);
  assert.equal(client.isRetryableVoiceStatus(404), false);
}

async function testAllowlistAndGuestRedirect() {
  // Given a logged-in user, when the auth gate runs, then no redirect happens.
  const { client: logged } = clientWith({ loggedIn: true });
  assert.equal(logged.redirectHomeOnAuthFailure(), false);
  // Given a guest, when the auth gate runs, then home is requested once.
  const { client: guest, state } = clientWith({ loggedIn: false });
  assert.equal(guest.redirectHomeOnAuthFailure(), true);
  assert.equal(state.redirected, 1);
}

async function testGuestRefreshNeverBootstraps() {
  // Given a guest, when refreshing, then no bootstrap fetch runs.
  let bootstraps = 0;
  const { client } = clientWith({
    loggedIn: false,
    bootstrapFetch: async () => { bootstraps++; return mockResponse({}); },
  });
  assert.equal(await client.refreshSession(), false);
  assert.equal(bootstraps, 0);
}

async function testRefreshAdoptsTokenAndSharesOneAttempt() {
  // Given two concurrent callers after a restart, when refreshing, then one
  // bootstrap attempt serves both and the new CSRF is adopted.
  let logins = 0;
  let remembers = 0;
  const { client, state } = clientWith({
    loggedIn: true,
    csrf: 'dead',
    bootstrapFetch: async (url) => {
      if (url === '/login') {
        logins++;
        return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="fresh-bootstrap">' });
      }
      remembers++;
      assert.equal(url, '/login/remember');
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'restored-1' } });
    },
  });
  const [a, b] = await Promise.all([client.refreshSession(), client.refreshSession()]);
  assert.equal(a, true);
  assert.equal(b, true);
  assert.equal(logins, 1, 'concurrent callers share one bootstrap');
  assert.equal(remembers, 1);
  assert.equal(state.csrf, 'restored-1');
  assert.deepEqual(state.setTokens, ['restored-1']);
  // Bootstrap uses form encoding, not JSON.
  const rememberInit = state.bootstrapCalls.find((c) => c.url === '/login/remember').init;
  assert.equal(rememberInit.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.ok(rememberInit.body.includes('csrf_token=fresh-bootstrap'));
}

async function testRefreshFailureRecovers() {
  // Given a failed bootstrap, when refreshing again, then the next attempt
  // runs (the shared promise cleared) instead of sticking failed.
  let n = 0;
  const { client } = clientWith({
    bootstrapFetch: async (url) => {
      if (url === '/login') {
        n++;
        if (n === 1) return mockResponse({ status: 500, textBody: 'down' });
        return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="k2">' });
      }
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'ok-2' } });
    },
  });
  assert.equal(await client.refreshSession(), false);
  assert.equal(await client.refreshSession(), true);
  assert.equal(n, 2, 'error recovery must clear the shared promise');
}

async function testInstancesAreIndependent() {
  // Given two clients, when both refresh, then each bootstraps on its own.
  let aBoot = 0;
  let bBoot = 0;
  const a = clientWith({
    bootstrapFetch: async (url) => {
      if (url === '/login') { aBoot++; return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="ka">' }); }
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'ta' } });
    },
  });
  const b = clientWith({
    bootstrapFetch: async (url) => {
      if (url === '/login') { bBoot++; return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="kb">' }); }
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'tb' } });
    },
  });
  assert.equal(await a.client.refreshSession(), true);
  assert.equal(await b.client.refreshSession(), true);
  assert.equal(aBoot, 1);
  assert.equal(bBoot, 1);
  assert.equal(a.state.csrf, 'ta');
  assert.equal(b.state.csrf, 'tb');
}

async function testFetchVoiceRetryRetriesTransientWithFreshBody() {
  // Given a 503 then success, when fetching voice, then the body factory runs
  // per attempt and the retry waits out the backoff.
  let builds = 0;
  const { client, state } = clientWith({
    fetchImpl: async (url, init) => {
      assert.equal(url, '/tts');
      assert.ok(init.signal, 'voice fetch carries an AbortSignal');
      if (state.calls.length === 1) return mockResponse({ status: 503 });
      return mockResponse({ status: 200 });
    },
  });
  const res = await client.fetchVoiceRetry('/tts', () => {
    builds++;
    return { method: 'POST', headers: { 'X-CSRF-Token': 't' }, body: 'body-' + builds };
  }, 3);
  assert.equal(res.status, 200);
  assert.equal(builds, 2, 'body must rebuild per attempt (consumed streams)');
  assert.deepEqual(state.delays, [400], 'first voice backoff is 400ms');
  assert.equal(state.calls[0].init.body, 'body-1');
  assert.equal(state.calls[1].init.body, 'body-2');
}

async function testFetchVoiceRetryPassesThroughAbortAnd401() {
  // Given a user abort, when fetching voice, then AbortError is not retried.
  const { client: abortClient, state: abortState } = clientWith({
    fetchImpl: async () => {
      const e = new Error('aborted');
      e.name = 'AbortError';
      throw e;
    },
  });
  const controller = new AbortController();
  controller.abort();
  // Pre-aborted signal rejects without touching the network.
  await assert.rejects(
    abortClient.fetchVoiceRetry('/tts', { method: 'GET', signal: controller.signal }, 3),
    (e) => e.name === 'AbortError'
  );
  assert.equal(abortState.calls.length, 0, 'pre-aborted must not fetch');
  assert.deepEqual(abortState.delays, []);

  // Given a 401, when fetching voice, then it never retries (guest redirects).
  const { client: authClient, state: authState } = clientWith({
    loggedIn: false,
    fetchImpl: async () => mockResponse({ status: 401 }),
  });
  await assert.rejects(authClient.fetchVoiceRetry('/tts', { method: 'GET' }, 3), /Session expired/);
  assert.equal(authState.calls.length, 1);
  assert.equal(authState.redirected, 1);
  assert.deepEqual(authState.delays, []);
}

async function testFetchWithGenerateRetryRefreshesOnce() {
  // Given a 401 then success, when fetching generate, then one refresh runs
  // and the retry carries the fresh CSRF header exactly once.
  let fetches = 0;
  const { client, state } = clientWith({
    csrf: 'stale',
    fetchImpl: async (url, init) => {
      fetches++;
      if (fetches === 1) return mockResponse({ status: 401 });
      assert.equal(init.headers['X-CSRF-Token'], 'fresh-1', 'retry must refresh the snapshotted header');
      return mockResponse({ status: 200 });
    },
    bootstrapFetch: async (url) => {
      if (url === '/login') return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="b">' });
      state.csrf = 'fresh-1';
      state.setTokens.push('fresh-1');
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'fresh-1' } });
    },
  });
  const res = await client.fetchWithGenerateRetry('/chat', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'stale' }, body: '{}',
  });
  assert.equal(res.status, 200);
  assert.equal(fetches, 2);

  // Given a 429, when fetching generate, then it backs off and preserves the body.
  let tries = 0;
  const { client: rate, state: rateState } = clientWith({
    fetchImpl: async (url, init) => {
      tries++;
      assert.equal(init.body, 'same-body');
      if (tries === 1) return mockResponse({ status: 429 });
      return mockResponse({ status: 200 });
    },
  });
  const ok = await rate.fetchWithGenerateRetry('/chat', { method: 'POST', body: 'same-body' });
  assert.equal(ok.status, 200);
  assert.deepEqual(rateState.delays, [200], 'generate backoff starts at 200ms');
}

async function testFetchWithGenerateRetryHonorsAbort() {
  // Given an aborted generate signal, when the 429 backoff elapses, then the
  // retry surfaces AbortError instead of reissuing the request.
  let fetches = 0;
  const { client } = clientWith({
    fetchImpl: async () => { fetches++; return mockResponse({ status: 429 }); },
  });
  const controller = new AbortController();
  const pending = client.fetchWithGenerateRetry('/chat', { method: 'POST', signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, (e) => e.name === 'AbortError');
  assert.equal(fetches, 1, 'aborted generate must not reissue');
}

async function testResponse401KindAndHandle() {
  // Given an unlock message, when classified, then it is an enc-key failure
  // that never triggers a session refresh.
  const { client } = clientWith({});
  assert.equal(await client.response401Kind(mockResponse({ status: 200 })), null);
  assert.equal(
    await client.response401Kind(mockResponse({ status: 401, jsonBody: { error: 'invalid encryption key' } })),
    'enc_key'
  );
  assert.equal(
    await client.response401Kind(mockResponse({ status: 401, jsonBody: { error: 'no session' } })),
    'session'
  );
  let retried = false;
  await assert.rejects(
    client.handle401OrRetry(mockResponse({ status: 401, jsonBody: { error: 'unlock needed' } }), async () => { retried = true; return 'retry'; }),
    /unlock needed/
  );
  assert.equal(retried, false, 'enc-key 401 must throw the server message without retrying');

  // Given a session 401 with a restorable session, when handled, then the
  // caller retry runs; without restore it throws to sign-in.
  const { client: restorable } = clientWith({
    bootstrapFetch: async (url) => {
      if (url === '/login') return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="b">' });
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'new' } });
    },
  });
  assert.equal(await restorable.handle401OrRetry(mockResponse({ status: 401, jsonBody: {} }), async () => 'retried'), 'retried');
  const { client: unrestorable } = clientWith({
    loggedIn: false,
    bootstrapFetch: async () => mockResponse({ status: 401 }),
  });
  await assert.rejects(
    unrestorable.handle401OrRetry(mockResponse({ status: 401, jsonBody: {} }), async () => 'retried'),
    /Session expired/
  );
}

async function testSttXhrRetriesTransientNot400() {
  // Given a 503 then success, when uploading STT, then the form rebuilds and
  // the retry waits out the backoff.
  const bodies = [];
  const factory = fakeXhrQueue([{ status: 503, responseText: 'busy' }, { status: 200, responseText: '{"text":"hi"}' }], bodies);
  const { client, state } = clientWith({ xhrFactory: factory });
  const out = await client.postVoiceSttXhr('/stt', () => ({
    method: 'POST', headers: { 'X-CSRF-Token': 't' }, body: 'form-' + (bodies.length + 1),
  }), 3);
  assert.equal(out.status, 200);
  assert.equal(out.responseText, '{"text":"hi"}');
  assert.equal(bodies.length, 2, 'STT body must rebuild per attempt');
  assert.deepEqual(state.delays, [400]);

  // Given a 400, when uploading STT, then it never retries.
  const badBodies = [];
  const badFactory = fakeXhrQueue([{ status: 400, responseText: 'bad' }], badBodies);
  const { client: bad } = clientWith({ xhrFactory: badFactory });
  await assert.rejects(bad.postVoiceSttXhr('/stt', { headers: {}, body: 'x' }, 3), /request failed \(400\)/);
  assert.equal(badBodies.length, 1);
}

async function testInterceptorPreservesSemantics() {
  // Given the installed wrapper, when 401s land, then every allowlisted chat
  // URL stays with the caller (preference saves never loop the enc-key gate)
  // while guest non-allowlisted callers redirect and throw.
  const allowlisted = [
    '/chat',
    '/regenerate',
    '/get_sets',
    '/load_set',
    '/create_set',
    '/fork_set',
    '/delete_set',
    '/rename_set',
    '/update_memory',
    '/update_system_prompt',
    '/update_preferences',
    '/delete_message',
    '/reset_chat',
    '/history_pair',
    '/history_image/abc/0/0/0',
  ];
  const globalObj = {
    redirected: 0,
    fetch: async (url) => {
      if (String(url).includes('/login')) return mockResponse({ status: 200 });
      return mockResponse({ status: 401, jsonBody: {} });
    },
  };
  const client = S.createSessionClient({
    getLoggedIn: () => false,
    getCsrfToken: () => 't',
    setCsrfToken: () => {},
    redirectHome: () => { globalObj.redirected++; },
    sleep: () => Promise.resolve(),
  });
  client.installFetchInterceptor(globalObj);
  for (const url of allowlisted) {
    const res = await globalObj.fetch(url, {});
    assert.equal(res.status, 401, url + ' allowlisted 401 stays with the caller');
  }
  assert.equal(globalObj.redirected, 0, 'allowlisted 401s never redirect guests');
  await assert.rejects(globalObj.fetch('/tts', {}), /Session expired/);
  await assert.rejects(globalObj.fetch('/stt', {}), /Session expired/);
  await assert.rejects(globalObj.fetch('/tts_stream/abc', {}), /Session expired/);
  assert.equal(globalObj.redirected, 3);

  // Given a Request object, when it 401s, then its URL still allowlists.
  const req = new Request('https://example.test/chat', { method: 'GET' });
  const viaRequest = await globalObj.fetch(req, {});
  assert.equal(viaRequest.status, 401, 'Request URL allowlists like a string URL');

  // Given a logged-in user, when a non-allowlisted 401 lands, then it also
  // stays with the caller for refresh handling.
  const loggedGlobal = { fetch: async () => mockResponse({ status: 401 }) };
  const logged = S.createSessionClient({
    getLoggedIn: () => true,
    getCsrfToken: () => null,
    setCsrfToken: () => {},
    redirectHome: () => { throw new Error('must not redirect when logged in'); },
    sleep: () => Promise.resolve(),
  });
  logged.installFetchInterceptor(loggedGlobal);
  const resp = await loggedGlobal.fetch('/tts', {});
  assert.equal(resp.status, 401);
}

async function testCallbackFailuresPropagatePrecisely() {
  // Given a throwing login callback, when gating or refreshing, then the
  // exception propagates (never swallowed to a guest default).
  const throwingLogin = S.createSessionClient({
    fetchImpl: async () => mockResponse({ status: 200 }),
    bootstrapFetch: async () => mockResponse({ status: 200 }),
    getLoggedIn: () => { throw new Error('login boom'); },
    getCsrfToken: () => 't',
    setCsrfToken: () => {},
    redirectHome: () => {},
    sleep: () => Promise.resolve(),
  });
  assert.throws(() => throwingLogin.redirectHomeOnAuthFailure(), /login boom/);
  assert.throws(() => throwingLogin.refreshSession(), /login boom/);

  // Given a throwing token getter, when building headers, then it propagates.
  const throwingToken = S.createSessionClient({
    fetchImpl: async () => mockResponse({ status: 200 }),
    bootstrapFetch: async () => mockResponse({ status: 200 }),
    getLoggedIn: () => true,
    getCsrfToken: () => { throw new Error('csrf boom'); },
    setCsrfToken: () => {},
    redirectHome: () => {},
    sleep: () => Promise.resolve(),
  });
  assert.throws(() => throwingToken.withCsrf({}), /csrf boom/);
  await assert.rejects(throwingToken.withCsrfAsync({}), /csrf boom/);
  assert.throws(() => throwingToken.refreshCsrfInit({ headers: { 'X-CSRF-Token': 'old' } }), /csrf boom/);

  // Given a throwing redirect, when gating a guest, then it propagates
  // (the original location assignment was uncaught).
  const throwingRedirect = S.createSessionClient({
    fetchImpl: async () => mockResponse({ status: 200 }),
    bootstrapFetch: async () => mockResponse({ status: 200 }),
    getLoggedIn: () => false,
    getCsrfToken: () => 't',
    setCsrfToken: () => {},
    redirectHome: () => { throw new Error('redirect boom'); },
    sleep: () => Promise.resolve(),
  });
  assert.throws(() => throwingRedirect.redirectHomeOnAuthFailure(), /redirect boom/);

  // Given a throwing CSRF setter, when the bootstrap succeeds, then the
  // refresh resolves false via the shared catch (never true).
  const throwingSetter = S.createSessionClient({
    fetchImpl: async () => mockResponse({ status: 200 }),
    bootstrapFetch: async (url) => {
      if (url === '/login') {
        return mockResponse({ status: 200, textBody: '<input name="csrf_token" value="k">' });
      }
      return mockResponse({ status: 200, jsonBody: { csrf_token: 'new' } });
    },
    getLoggedIn: () => true,
    getCsrfToken: () => 'old',
    setCsrfToken: () => { throw new Error('setter boom'); },
    redirectHome: () => {},
    sleep: () => Promise.resolve(),
  });
  assert.equal(await throwingSetter.refreshSession(), false);

  // Given a throwing signal listener, when uploading STT, then the throw
  // rejects into the retry loop (never swallowed).
  const throwingSignal = {
    aborted: false,
    addEventListener() { throw new Error('listener boom'); },
    removeEventListener() {},
  };
  const { client: xhrClient, state: xhrState } = clientWith({
    xhrFactory: fakeXhrQueue([{ status: 200, responseText: '{}' }], []),
  });
  await assert.rejects(
    xhrClient.postVoiceSttXhr('/stt', { headers: {}, body: 'x', signal: throwingSignal }, 2),
    /listener boom/
  );
  assert.deepEqual(xhrState.delays, [400], 'listener throw retries once before exhausting');
}

const cases = [
  ['csrf headers carry token', testCsrfHeadersCarryToken],
  ['csrf init rebuilds only token', testRefreshCsrfInitRebuildsOnlyToken],
  ['retryable status matches contract', testRetryableStatusMatchesContract],
  ['allowlist and guest redirect', testAllowlistAndGuestRedirect],
  ['guest refresh never bootstraps', testGuestRefreshNeverBootstraps],
  ['refresh adopts token and shares one attempt', testRefreshAdoptsTokenAndSharesOneAttempt],
  ['refresh failure recovers', testRefreshFailureRecovers],
  ['instances are independent', testInstancesAreIndependent],
  ['voice retry retries transient with fresh body', testFetchVoiceRetryRetriesTransientWithFreshBody],
  ['voice retry passes through abort and 401', testFetchVoiceRetryPassesThroughAbortAnd401],
  ['generate retry refreshes once', testFetchWithGenerateRetryRefreshesOnce],
  ['generate retry honors abort', testFetchWithGenerateRetryHonorsAbort],
  ['401 kind and handle', testResponse401KindAndHandle],
  ['stt xhr retries transient not 400', testSttXhrRetriesTransientNot400],
  ['interceptor preserves semantics', testInterceptorPreservesSemantics],
  ['callback failures propagate precisely', testCallbackFailuresPropagatePrecisely],
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
    console.error('session client FAILED:\n' + failures.join('\n'));
    process.exitCode = 1;
  } else {
    console.error('session client: retry/header/abort/sharing contract holds');
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
