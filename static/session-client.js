(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatSessionClient = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // HTTP/session client boundary: fetch bootstrap, CSRF refresh, 401 retry,
  // generate retry and voice HTTP helpers. One instance owns the single
  // bootstrap promise; chat.js keeps DOM callbacks (location, CSRF meta,
  // login state) and all rendering. No data-key handling here: browsers send
  // the HttpOnly cookie automatically, tests use the header path elsewhere.

  var SESSION_EXPIRED_SEND_MSG =
    'Session expired or unauthorized. Your message was not sent — it is still in the input box.';

  function isAuthAllowlistedUrl(url) {
    if (typeof url !== 'string') return false;
    return url.includes('/chat') ||
      url.includes('/regenerate') ||
      url.includes('/get_sets') ||
      url.includes('/load_set') ||
      url.includes('/create_set') ||
      url.includes('/fork_set') ||
      url.includes('/delete_set') ||
      url.includes('/rename_set') ||
      url.includes('/update_memory') ||
      url.includes('/update_system_prompt') ||
      url.includes('/update_preferences') ||
      url.includes('/delete_message') ||
      url.includes('/reset_chat') ||
      url.includes('/history_pair') ||
      url.includes('/history_image');
  }

  function isRetryableVoiceStatus(status) {
    return status === 408 || status === 429 || status === 502 || status === 503 || status === 504
      || status >= 500;
  }

  function defaultSleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function defaultXhrFactory() {
    return new XMLHttpRequest();
  }

  // Cohesive owned client. DOM callbacks are explicit and required (no
  // window/document access in this unit; chat.js owns location, CSRF meta,
  // and login state):
  // - fetchImpl: normal requests (defaults to current global fetch at call
  //   time, i.e. the intercepted fetch after installFetchInterceptor).
  // - bootstrapFetch: /login bootstrap (defaults to the captured original
  //   fetch after install, else the normal fetch).
  // - getLoggedIn/getCsrfToken/setCsrfToken/redirectHome: required chat
  //   callbacks; exceptions propagate exactly as the inline code threw.
  // - sleep: backoff waits (tests inject an immediate spy).
  // - xhrFactory: XHR constructor (tests inject a fake).
  // State: one shared bootstrap promise per instance (concurrent callers on
  // the same instance share one attempt; separate instances are independent).
  function createSessionClient(deps) {
    deps = deps || {};
    if (typeof deps.getLoggedIn !== 'function') {
      throw new Error('createSessionClient requires getLoggedIn');
    }
    if (typeof deps.getCsrfToken !== 'function') {
      throw new Error('createSessionClient requires getCsrfToken');
    }
    if (typeof deps.setCsrfToken !== 'function') {
      throw new Error('createSessionClient requires setCsrfToken');
    }
    if (typeof deps.redirectHome !== 'function') {
      throw new Error('createSessionClient requires redirectHome');
    }
    var getLoggedIn = deps.getLoggedIn;
    var getCsrfToken = deps.getCsrfToken;
    var setCsrfToken = deps.setCsrfToken;
    var redirectHome = deps.redirectHome;
    var fetchImpl = (typeof deps.fetchImpl === 'function') ? deps.fetchImpl : null;
    var bootstrapOverride = (typeof deps.bootstrapFetch === 'function') ? deps.bootstrapFetch : null;
    var sleepFn = (typeof deps.sleep === 'function') ? deps.sleep : defaultSleep;
    var xhrFactory = (typeof deps.xhrFactory === 'function') ? deps.xhrFactory : defaultXhrFactory;

    var sessionRefreshPromise = null;
    var installedOriginalFetch = null;

    function getFetch() {
      if (fetchImpl) return fetchImpl;
      return globalThis.fetch;
    }

    function getBootstrapFetch() {
      if (bootstrapOverride) return bootstrapOverride;
      if (installedOriginalFetch) return installedOriginalFetch;
      return getFetch();
    }

    function redirectHomeOnAuthFailure() {
      if (getLoggedIn()) {
        return false;
      }
      redirectHome();
      return true;
    }

    function installFetchInterceptor(target) {
      var globalObj = target || globalThis;
      var originalFetch = globalObj.fetch;
      installedOriginalFetch = originalFetch;
      globalObj.fetch = function (input, init) {
        return originalFetch.apply(this, arguments).then(function (response) {
          if (response.status === 401) {
            var url = input;
            if (typeof Request !== 'undefined' && input instanceof Request) {
              url = input.url;
            }
            if (isAuthAllowlistedUrl(url)) {
              return response;
            }
            if (!redirectHomeOnAuthFailure()) {
              return response;
            }
            throw new Error('Session expired');
          }
          return response;
        });
      };
    }

    // Silent session restore after a server restart: bootstrap a fresh guest
    // session (GET /login) for a CSRF token the dead page cannot produce,
    // exchange the HttpOnly remember cookie (POST /login/remember), then adopt
    // the restored session's CSRF token so same-page requests keep validating.
    // Concurrent callers share one attempt. Resolves to a boolean.
    function refreshSession() {
      if (!getLoggedIn()) {
        return Promise.resolve(false);
      }
      if (sessionRefreshPromise) {
        return sessionRefreshPromise;
      }
      var bootstrap = getBootstrapFetch();
      sessionRefreshPromise = bootstrap('/login')
        .then(function (resp) {
          if (!resp.ok) {
            throw new Error('session bootstrap failed');
          }
          return resp.text();
        })
        .then(function (html) {
          var match = html.match(/name="csrf_token" value="([^"]+)"/);
          if (!match) {
            throw new Error('csrf token not found');
          }
          return bootstrap('/login/remember', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'csrf_token=' + encodeURIComponent(match[1]),
          });
        })
        .then(function (resp) {
          if (!resp.ok) {
            return false;
          }
          return resp.json().then(function (data) {
            if (data && data.csrf_token) {
              setCsrfToken(data.csrf_token);
              return true;
            }
            return false;
          });
        })
        .catch(function () {
          return false;
        });
      sessionRefreshPromise.finally(function () { sessionRefreshPromise = null; });
      return sessionRefreshPromise;
    }

    // Rebuild a cached fetch init's X-CSRF-Token header after a session
    // refresh (headers were snapshotted by withCsrf at call time).
    function refreshCsrfInit(init) {
      var token = getCsrfToken();
      if (!init || !init.headers || !token) {
        return init;
      }
      var fresh = Object.assign({}, init);
      var copy;
      if (typeof Headers !== 'undefined' && init.headers instanceof Headers) {
        copy = {};
        init.headers.forEach(function (value, key) { copy[key] = value; });
      } else {
        copy = Object.assign({}, init.headers);
      }
      Object.keys(copy).forEach(function (key) {
        if (key.toLowerCase() === 'x-csrf-token') {
          copy[key] = token;
        }
      });
      fresh.headers = copy;
      return fresh;
    }

    function sleepMs(ms) {
      return sleepFn(ms);
    }

    function fetchVoiceRetry(url, buildOptions, attempts) {
      attempts = attempts || 3;
      function attempt(n) {
        var options = typeof buildOptions === 'function' ? buildOptions() : (buildOptions || {});
        var userSignal = options.signal;
        var controller = new AbortController();
        var timeoutId = setTimeout(function () { controller.abort(); }, 60000);
        var userAborted = false;
        var onUserAbort = function () {
          userAborted = true;
          controller.abort();
        };
        if (userSignal) {
          if (userSignal.aborted) {
            clearTimeout(timeoutId);
            var aborted = new Error('aborted');
            aborted.name = 'AbortError';
            return Promise.reject(aborted);
          }
          userSignal.addEventListener('abort', onUserAbort);
        }
        var opts = Object.assign({}, options, { signal: controller.signal });
        var fetchFn = getFetch();
        return fetchFn(url, opts).then(function (res) {
          if (res.ok) return res;
          if (res.status === 401) {
            redirectHomeOnAuthFailure();
            throw new Error('Session expired');
          }
          if (n > 1 && isRetryableVoiceStatus(res.status)) {
            return sleepMs(400 * Math.pow(2, attempts - n)).then(function () { return attempt(n - 1); });
          }
          throw new Error('request failed (' + res.status + ')');
        }).catch(function (err) {
          if (err && err.message === 'Session expired') throw err;
          if (err && err.name === 'AbortError' && userAborted) throw err;
          if (n <= 1) throw err;
          return sleepMs(400 * Math.pow(2, attempts - n)).then(function () { return attempt(n - 1); });
        }).finally(function () {
          clearTimeout(timeoutId);
          if (userSignal) userSignal.removeEventListener('abort', onUserAbort);
        });
      }
      return attempt(attempts);
    }

    function postVoiceSttXhr(url, buildOptions, attempts) {
      attempts = attempts || 3;
      function attempt(n) {
        var options = typeof buildOptions === 'function' ? buildOptions() : (buildOptions || {});
        var userSignal = options.signal;
        return new Promise(function (resolve, reject) {
          var settled = false;
          function finish(fn, arg) {
            if (!settled) {
              settled = true;
              fn(arg);
            }
          }
          var abortErr = function () {
            var err = new Error('aborted');
            err.name = 'AbortError';
            return err;
          };
          var xhr = xhrFactory();
          xhr.open('POST', url, true);
          var headers = options.headers || {};
          Object.keys(headers).forEach(function (name) {
            xhr.setRequestHeader(name, headers[name]);
          });
          xhr.timeout = 60000;
          var tSend = Date.now();
          var tLastProgress = 0;
          var lastLoaded = 0;
          xhr.upload.onprogress = function (ev) {
            if (!ev || !ev.lengthComputable) return;
            tLastProgress = Date.now();
            lastLoaded = ev.loaded;
          };
          xhr.onload = function () {
            var tDone = Date.now();
            var upMs = tLastProgress > tSend ? tLastProgress - tSend : tDone - tSend;
            var net = {
              bytes: lastLoaded || options.bodyBytes || 0,
              upMs: Math.max(1, Math.round(upMs))
            };
            if (xhr.status === 401) {
              redirectHomeOnAuthFailure();
              finish(reject, new Error('Session expired'));
              return;
            }
            if (xhr.status >= 200 && xhr.status < 300) {
              finish(resolve, { status: xhr.status, responseText: xhr.responseText, net: net });
              return;
            }
            var err = new Error('request failed (' + xhr.status + ')');
            err.retryableVoice = isRetryableVoiceStatus(xhr.status);
            err.net = net;
            finish(reject, err);
          };
          xhr.onerror = function () {
            var err = new Error('network error');
            err.retryableVoice = true;
            finish(reject, err);
          };
          xhr.ontimeout = function () {
            var err = new Error('timeout');
            err.name = 'TimeoutError';
            err.retryableVoice = true;
            finish(reject, err);
          };
          xhr.onabort = function () {
            finish(reject, abortErr());
          };
          var onUserAbort = function () {
            try {
              xhr.abort();
            } catch (_) {
              finish(reject, abortErr());
            }
          };
          if (userSignal) {
            if (userSignal.aborted) {
              finish(reject, abortErr());
              return;
            }
            userSignal.addEventListener('abort', onUserAbort);
          }
          try {
            xhr.send(options.body);
          } catch (sendErr) {
            var serr = new Error(sendErr && sendErr.message ? sendErr.message : 'send failed');
            serr.retryableVoice = true;
            finish(reject, serr);
          }
        }).catch(function (err) {
          if (err && (err.message === 'Session expired' || err.name === 'AbortError')) throw err;
          if (n <= 1 || (err && err.retryableVoice === false)) throw err;
          return sleepMs(400 * Math.pow(2, attempts - n)).then(function () {
            return attempt(n - 1);
          });
        });
      }
      return attempt(attempts);
    }

    function withCsrf(headers) {
      var result = headers ? Object.assign({}, headers) : {};
      var token = getCsrfToken();
      if (token) {
        result['X-CSRF-Token'] = token;
      }
      return result;
    }

    async function withCsrfAsync(headers) {
      var result = headers ? Object.assign({}, headers) : {};
      var token = getCsrfToken();
      if (token) {
        result['X-CSRF-Token'] = token;
      }
      return result;
    }

    async function response401Message(response) {
      try {
        var body = await response.clone().json();
        return (body.error || body.message || '').toString();
      } catch (_) {
        return '';
      }
    }

    async function response401Kind(response) {
      if (response.status !== 401) {
        return null;
      }
      var msg = await response401Message(response);
      if (/encryption key|unlock|invalid encryption key/i.test(msg)) {
        return 'enc_key';
      }
      return 'session';
    }

    async function handle401OrRetry(response, retryFn) {
      var kind = await response401Kind(response);
      if (kind === 'enc_key') {
        throw new Error(
          (await response401Message(response)) ||
            'Could not unlock chats. Sign out and log in with your password.'
        );
      }
      if (response.status === 401) {
        var restored = await refreshSession();
        if (restored && retryFn) {
          return retryFn();
        }
        throw new Error('Session expired. Sign out and log in again.');
      }
      return response;
    }

    function fetchWithGenerateRetry(url, init, attempt, afterRefresh) {
      attempt = attempt || 0;
      var fetchFn = getFetch();
      return fetchFn(url, init).then(function (res) {
        if (res.status === 401 && !afterRefresh) {
          return refreshSession().then(function (restored) {
            if (!restored) {
              redirectHomeOnAuthFailure();
              throw new Error('Session expired');
            }
            return fetchWithGenerateRetry(url, refreshCsrfInit(init), attempt, true);
          });
        }
        if ((res.status === 429 || (res.status === 400 && attempt < 8)) && attempt < 12) {
          return sleepMs(200 + attempt * 150).then(function () {
            if (init && init.signal && init.signal.aborted) {
              var err = new Error('Aborted');
              err.name = 'AbortError';
              throw err;
            }
            return fetchWithGenerateRetry(url, init, attempt + 1, afterRefresh);
          });
        }
        return res;
      });
    }

    return {
      redirectHomeOnAuthFailure: redirectHomeOnAuthFailure,
      installFetchInterceptor: installFetchInterceptor,
      refreshSession: refreshSession,
      refreshCsrfInit: refreshCsrfInit,
      sleepMs: sleepMs,
      isRetryableVoiceStatus: isRetryableVoiceStatus,
      fetchVoiceRetry: fetchVoiceRetry,
      postVoiceSttXhr: postVoiceSttXhr,
      withCsrf: withCsrf,
      withCsrfAsync: withCsrfAsync,
      response401Message: response401Message,
      response401Kind: response401Kind,
      handle401OrRetry: handle401OrRetry,
      fetchWithGenerateRetry: fetchWithGenerateRetry
    };
  }

  return {
    SESSION_EXPIRED_SEND_MSG: SESSION_EXPIRED_SEND_MSG,
    createSessionClient: createSessionClient
  };
}));
