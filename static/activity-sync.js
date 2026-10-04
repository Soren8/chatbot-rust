(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory();
  else root.ChatActivitySync = factory();
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function createActivitySync(deps) {
    deps = deps || {};
    var fetchImpl = deps.fetch;
    var rng = deps.rng || Math.random;
    var clock = deps.clock || Date.now;
    var schedule = deps.setTimeout || setTimeout;
    var unschedule = deps.clearTimeout || clearTimeout;
    var sleep = deps.sleep || function (ms) { return new Promise(function (resolve) { schedule(resolve, ms); }); };
    var outbox = new Map();
    var reads = new Set();
    var view = null;
    var setId = '';
    var queuedIntent = null;
    var wasInterrupted = false;
    var recovery = null;
    var serial = 0;
    var navigation = 0;
    var mutationTail = Promise.resolve();
    var retryWaiters = new Set();
    var pendingAdmissions = new Set();

    function waitRetry(ms, signal) {
      return new Promise(function (resolve) {
        function wake() {
          retryWaiters.delete(wake);
          if (signal) signal.removeEventListener('abort', wake);
          resolve();
        }
        retryWaiters.add(wake);
        if (signal) signal.addEventListener('abort', wake);
        sleep(ms).then(wake);
      });
    }

    function state(value) { if (deps.onState) deps.onState(value); }
    function operationId() {
      serial++;
      return 'op-' + clock().toString(36) + '-' + serial.toString(36) + '-' + Math.floor(rng() * 0x100000000).toString(36);
    }
    function aborted() { var e = new Error('View detached'); e.name = 'AbortError'; return e; }
    function backoff(attempt) { return rng() * Math.min(30000, 500 * Math.pow(2, Math.min(attempt, 16))); }
    function retryable(status) { return status === 408 || status >= 500; }
    function safeRead(url) {
      return /^\/(get_sets|load_set|history_pair|history_image(?:\/|$)|activity(?:\?|$))/.test(url) || (url === '/agent_connections');
    }
    async function send(url, init, signal) {
      var attempt = 0;
      var refreshed = false;
      while (true) {
        if (signal && signal.aborted) throw aborted();
        try {
          var response = await fetchImpl(url, Object.assign({}, init, { signal: signal }));
          if (response.status === 401 && !refreshed) {
            // An unlock failure is not a session-refresh failure.
            var kind = deps.response401Kind ? await deps.response401Kind(response) : 'session';
            if (kind === 'enc_key') { state('needs-action'); return response; }
            refreshed = true;
            if (await deps.refreshSession()) { init = deps.refreshCsrfInit(init); continue; }
            state('needs-action'); return response;
          }
          if (!retryable(response.status) && !(response.status === 429 && /^\/(tts(?:_stream\/|$)|stt$)/.test(url))) return response;
          if (response.body && response.body.cancel) await response.body.cancel();
        } catch (e) {
          if (signal && signal.aborted) throw aborted();
          if (e.name !== 'TypeError') throw e;
        }
        state('reconnecting');
        await waitRetry(backoff(attempt++), signal);
      }
    }
    function request(url, init) {
      init = Object.assign({}, init || {});
      var method = (init.method || 'GET').toUpperCase();
      var read = safeRead(url) && (method === 'GET' || (method === 'POST' && (url === '/load_set' || url === '/history_pair')));
      var mutation = !read && method !== 'GET' && method !== 'HEAD';
      var controller = new AbortController();
      var userSignal = init.signal;
      function cancel() { controller.abort(); }
      if (userSignal) {
        if (userSignal.aborted) cancel();
        else userSignal.addEventListener('abort', cancel);
      }
      if (read) reads.add(controller);
      if (mutation) {
        init.headers = Object.assign({ 'Idempotency-Key': operationId() }, init.headers || {});
        if (url === '/create_set') {
          var body = JSON.parse(init.body || '{}');
          if (!body.set_name) body.set_name = deps.createSetName ? deps.createSetName() : 'New Chat ' + clock().toString(36) + '-' + serial;
          init.body = JSON.stringify(body);
        }
      }
      var createName = url === '/create_set' ? JSON.parse(init.body || '{}').set_name : null;
      var key = mutation && init.headers['Idempotency-Key'];
      var pending = { url: url, init: init, promise: null };
      function run() {
        pending.promise = send(url, init, controller.signal).then(async function (response) {
          if (!createName) return response;
          var body;
          try { body = await (response.clone ? response.clone() : response).json(); } catch (e) { return response; }
          if (!body || body.status !== 'error' || !/Set already exists or invalid name/.test(body.error || '')) return response;
          // Create has no server receipt. A lost successful acknowledgement
          // replays the explicit name, which then collides; resolve that
          // collision to the already-created set rather than creating a
          // second auto-named set or surfacing a misleading failure.
          var listed = await send('/get_sets', { headers: deps.headers ? deps.headers() : {} }, controller.signal).catch(function () { return null; });
          if (!listed || !listed.ok) return response;
          var sets = await listed.json().catch(function () { return []; });
          var found = Array.isArray(sets) && sets.find(function (set) { return set && set.name === createName; });
          if (!found) return response;
          return { ok: true, status: 200, json: async function () {
            return { status: 'success', set_id: found.set_id, name: found.name, version: found.version,
              privacy_level: found.privacy_level, recovered: true };
          } };
        });
        return pending.promise;
      }
      if (mutation) outbox.set(key, pending);
      // Absolute-value writes must not overtake an unresolved earlier write.
      var ordered = mutation && !(/^\/(tts$|stt$|generations\/[^/]+\/stop$)/.test(url));
      var result = ordered ? mutationTail.then(run) : run();
      if (ordered) mutationTail = result.catch(function () {});
      return result.finally(function () {
        reads.delete(controller);
        if (key) outbox.delete(key);
        if (userSignal) userSignal.removeEventListener('abort', cancel);
      });
    }
    function detach() {
      if (view) { view.detached = true; if (view.controller) view.controller.abort(); }
      view = null;
    }
    function navigate(id) {
      navigation++;
      reads.forEach(function (controller) { controller.abort(); });
      reads.clear();
      detach();
      setId = id || '';
    }
    async function attach(descriptor, onEvent, initialResponse) {
      if (view && view.id === descriptor.generation_id && !view.detached) return view.promise;
      detach();
      var current = { id: descriptor.generation_id, seq: 0, detached: false, controller: null, saved: false, failed: false, ended: false };
      view = current;
      wasInterrupted = false;
      current.promise = (async function () {
        var attempt = 0;
        while (!current.detached && !current.saved) {
          var controller = new AbortController();
          current.controller = controller;
          var timer = null;
          var reader = null;
          var closed = false;
          function alive() {
            if (timer) unschedule(timer);
            timer = schedule(function () { controller.abort(); }, 20000);
          }
          try {
            alive();
            var res = initialResponse || await send('/generations/' + encodeURIComponent(current.id) + '/events?after=' + current.seq, { headers: deps.headers ? deps.headers() : {} }, controller.signal);
            initialResponse = null;
            if (res.status === 404) {
              wasInterrupted = true; state('needs-action');
              if (deps.onInterrupted) deps.onInterrupted(current.id);
              return;
            }
            if (!res.ok) { state('needs-action'); return; }
            state('streaming');
            reader = res.body.getReader();
            var decoder = new TextDecoder();
            var buffer = '';
            while (!current.detached && !current.saved) {
              var chunk = await new Promise(function (resolve, reject) {
                function lost() { reject(aborted()); }
                controller.signal.addEventListener('abort', lost, { once: true });
                reader.read().then(resolve, reject).finally(function () { controller.signal.removeEventListener('abort', lost); });
              });
              if (chunk.done) { closed = true; break; }
              buffer += decoder.decode(chunk.value, { stream: true });
              var newline, offset = 0, rearm = true;
              while ((newline = buffer.indexOf('\n', offset)) >= 0) {
                var line = buffer.slice(offset, newline); offset = newline + 1;
                // Lines between awaits arrive together; one re-arm per run is equivalent.
                if (rearm) { alive(); rearm = false; }
                if (!line.trim()) continue;
                var event = JSON.parse(line);
                if (event.type === 'heartbeat') continue;
                if (event.seq <= current.seq) continue;
                if (event.seq !== current.seq + 1) throw new TypeError('Replay gap');
                current.seq = event.seq;
                attempt = 0;
                if (onEvent) onEvent(event);
                else if (deps.onEvent) deps.onEvent(event);
                if (event.type === 'ended') { current.ended = true; state(current.failed ? 'needs-action' : 'saving'); }
                if (event.type === 'error') { current.failed = true; wasInterrupted = true; state('needs-action'); }
                if (event.type === 'saved') current.saved = true;
                if (event.type === 'ended' || event.type === 'saved') {
                  if (deps.reconcile) { await deps.reconcile(setId, event); rearm = true; }
                }
              }
              buffer = buffer.slice(offset);
            }
          } catch (e) {
            if (!current.detached && e.name !== 'TypeError' && e.name !== 'AbortError') { state('needs-action'); throw e; }
          } finally {
            if (timer) unschedule(timer);
            if (reader && reader.cancel) {
              // Cancellation is cleanup, not a prerequisite for replay. Some WebViews
              // leave its promise pending after the underlying connection is lost.
              try { Promise.resolve(reader.cancel()).catch(function () {}); } catch (e) {}
            }
            controller.abort();
          }
          if (!current.detached && !current.saved) {
            if (current.failed && current.ended) { state('needs-action'); return; }
            if (closed) {
              var status = await send('/generations/' + encodeURIComponent(current.id), { headers: deps.headers ? deps.headers() : {} });
              if (status.status === 404) {
                wasInterrupted = true; state('needs-action');
                if (deps.onInterrupted) deps.onInterrupted(current.id);
                return;
              }
              var descriptorStatus = status.ok && await status.json();
              if (descriptorStatus && descriptorStatus.state === 'failed') {
                current.failed = true; wasInterrupted = true;
                if (onEvent) onEvent({ type: 'error', text: 'Generation failed. Retry to send again.' });
                else if (deps.onEvent) deps.onEvent({ generation_id: current.id, type: 'error', text: 'Generation failed. Retry to send again.' });
                state('needs-action'); return;
              }
            }
            state('reconnecting'); await sleep(backoff(attempt++));
          }
        }
        if (current.saved && !current.detached) state('idle');
      }());
      return current.promise;
    }
    async function start(payload, onEvent) {
      var binding = navigation;
      var admission = { stopRequested: false, resolveStop: null };
      admission.stopPromise = new Promise(function (resolve) { admission.resolveStop = resolve; });
      pendingAdmissions.add(admission);
      state('sending');
      var route = payload.kind === 'regenerate' ? '/regenerate' : '/chat';
      try {
        var response = await request(route, { method: 'POST', headers: Object.assign({}, deps.headers ? deps.headers() : {}, { 'X-Generation-Mode': 'durable' }), body: JSON.stringify(payload) });
        var id = response.headers && response.headers.get('X-Generation-Id');
        var data = id ? { generation_id: id } : await response.json();
        if (response.status === 409 && data.error === 'generation_active') {
          if (admission.stopRequested) {
            var activeId = data.generation && data.generation.generation_id;
            if (activeId) await request('/generations/' + encodeURIComponent(activeId) + '/stop', {
              method: 'POST', headers: deps.headers ? deps.headers() : {}, body: '{}'
            });
            admission.resolveStop();
            return { queued: true, response: response, data: data };
          }
        }
        if (binding !== navigation) {
          if (admission.stopRequested && response.ok && data && data.generation_id) {
            await request('/generations/' + encodeURIComponent(data.generation_id) + '/stop', {
              method: 'POST', headers: deps.headers ? deps.headers() : {}, body: '{}'
            });
          }
          if (response.body && response.body.cancel) await response.body.cancel();
          admission.resolveStop();
          return { response: response, data: data, detached: true };
        }
        if (response.status === 409 && data.error === 'generation_active') {
          queuedIntent = payload;
          state('needs-action');
          attach(data.generation).catch(function () { state('needs-action'); });
          admission.resolveStop();
          return { queued: true, response: response, data: data };
        }
        if (!response.ok) {
          admission.resolveStop();
          return { response: response, data: data };
        }
        queuedIntent = null;
        if (admission.stopRequested && data && data.generation_id) {
          await request('/generations/' + encodeURIComponent(data.generation_id) + '/stop', {
            method: 'POST', headers: deps.headers ? deps.headers() : {}, body: '{}'
          });
          admission.resolveStop();
        } else {
          admission.resolveStop();
          attach(data, onEvent, id ? response : null).catch(function () { state('needs-action'); });
        }
        return { descriptor: data, response: response };
      } finally {
        pendingAdmissions.delete(admission);
        admission.resolveStop();
      }
    }
    function stop() {
      if (pendingAdmissions.size) {
        var pending = Array.from(pendingAdmissions);
        pending.forEach(function (admission) { admission.stopRequested = true; });
        return Promise.all(pending.map(function (admission) { return admission.stopPromise; }));
      }
      if (!view) return Promise.resolve();
      return request('/generations/' + encodeURIComponent(view.id) + '/stop', { method: 'POST', headers: deps.headers ? deps.headers() : {}, body: '{}' });
    }
    function recover() {
      if (recovery) return recovery;
      recovery = Promise.resolve().then(async function () {
        state('reconnecting');
        // An expired session surfaces as 401 and send() refreshes once; refreshing
        // here would rotate the remember token on every focus or resume.
        retryWaiters.forEach(function (wake) { wake(); });
        // Requests already retry with their original identity; join them before discovery.
        await mutationTail;
        var res = await request('/activity?set_id=' + encodeURIComponent(setId), { headers: deps.headers ? deps.headers() : {} });
        if (!res.ok) { state('needs-action'); return; }
        var data = await res.json();
        if (data.generations.length && (!view || view.detached)) attach(data.generations[0]).catch(function () { state('needs-action'); });
        // Always compare the durable set version: another device may have saved
        // while this page was asleep, even when no generation is still running.
        if (deps.reconcile) await deps.reconcile(setId);
        if (!view) state('idle');
      }).finally(function () { recovery = null; });
      return recovery;
    }
    // Compatibility adapter for the existing renderer, not the legacy HTTP protocol.
    // Its reader closes only on saved, never on transport EOF.
    async function generationResponse(kind, init) {
      var payload = JSON.parse(init.body);
      payload.kind = kind;
      if (!payload.set_id) payload.set_id = '';
      if (payload.expected_version == null) payload.expected_version = 0;
      var chunks = [], waiter = null, complete = false, failure = null;
      var encoder = new TextEncoder();
      function wake() { if (waiter) { var w = waiter; waiter = null; w(); } }
      var result = await start(payload, function (event) {
        if (event.type === 'delta' || event.type === 'thinking') chunks.push(encoder.encode(event.type === 'thinking' ? '<think>' + event.text + '</think>' : event.text));
        if (event.type === 'error') { failure = new Error(event.text); complete = true; }
        if (event.type === 'saved') complete = true;
        wake();
      });
      if (!result.descriptor) {
        return { status: result.response.status, ok: false, text: async function () { return JSON.stringify(result.data); }, json: async function () { return result.data; } };
      }
      var current = view;
      function cancel() { if (view === current) detach(); complete = true; wake(); }
      if (init.signal) {
        if (init.signal.aborted) cancel(); else init.signal.addEventListener('abort', cancel, { once: true });
      }
      if (current) current.promise.then(function () {
        if (wasInterrupted) failure = new Error('Generation interrupted after server restart. Retry to send again.');
        complete = true; wake();
      }).catch(function (e) { failure = e; complete = true; wake(); });
      return { status: 200, ok: true, body: { cancel: async function () { cancel(); }, getReader: function () { return {
        read: async function read() {
          if (chunks.length) return { done: false, value: chunks.shift() };
          if (failure) throw failure;
          if (complete) { if (init.signal) init.signal.removeEventListener('abort', cancel); return { done: true }; }
          await new Promise(function (resolve) { waiter = resolve; });
          return read();
        }, cancel: async function () { cancel(); }
      }; } } };
    }
    return { request: request, start: start, attach: attach, stop: stop, detach: detach, navigate: navigate, recover: recover,
      generationResponse: generationResponse, queued: function () { return queuedIntent; }, interrupted: function () { return wasInterrupted; } };
  }
  return { createActivitySync: createActivitySync };
}));
