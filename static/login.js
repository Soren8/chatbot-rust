const OTHER_ACCOUNT = '__other__';

async function deriveKeyWebCrypto(password, saltB64) {
  try {
    const enc = new TextEncoder();
    const passwordKey = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const saltStr = atob(saltB64);
    const salt = new Uint8Array(saltStr.length);
    for (let i = 0; i < saltStr.length; i += 1) {
      salt[i] = saltStr.charCodeAt(i);
    }

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      passwordKey,
      256
    );

    const derivedArray = new Uint8Array(derivedBits);
    let derivedStr = '';
    for (let i = 0; i < derivedArray.length; i += 1) {
      derivedStr += String.fromCharCode(derivedArray[i]);
    }
    return btoa(derivedStr);
  } catch (e) {
    console.error('WebCrypto derivation failed', e);
    return null;
  }
}

async function deriveKeyForLogin(password, saltB64) {
  if (window.NativeBridge && window.NativeBridge.isNativePlatform()) {
    const result = await window.NativeBridge.callNativePlugin('NativeSecureKey', 'deriveKeyFromPassword', {
      password: password,
      salt: saltB64,
    });
    return result && result.key ? result.key : null;
  }
  if (!window.crypto || !window.crypto.subtle || !window.isSecureContext) {
    return null;
  }
  return deriveKeyWebCrypto(password, saltB64);
}

function showLoginNotice(message) {
  const $notice = $('#login-notice');
  if ($notice.length) {
    $notice
      .text(message)
      .removeClass('d-none alert-danger')
      .addClass('alert-warning');
  } else {
    console.info(message);
  }
}

/// Show a login failure inline as a red alert. Failures must stay on the page
/// rather than navigating to a bare error page.
function showLoginError(message) {
  const $notice = $('#login-notice');
  if ($notice.length) {
    $notice
      .text(message)
      .removeClass('d-none alert-warning')
      .addClass('alert-danger');
  } else {
    console.info(message);
  }
}

/// Submit the login form via fetch so a failed attempt renders as an inline
/// notice on the login page. On success the server answers with a redirect
/// that sets the session cookie; we then run `onSuccess` (used to cache the
/// verified encryption key) and navigate. Failures never cache the key.
async function postLogin(form, onSuccess) {
  try {
    const body = new URLSearchParams(new FormData(form)).toString();
    const resp = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body,
    });
    if (resp.status >= 200 && resp.status < 400) {
      if (typeof onSuccess === 'function') {
        try {
          await onSuccess();
        } catch (e) {
          console.error('post-login key caching failed', e);
        }
      }
      window.location.href = '/';
      return;
    }
    let message = 'Invalid credentials';
    try {
      const data = await resp.json();
      if (data && data.error) {
        message = data.error;
      }
    } catch (e) {}
    showLoginError(message);
  } catch (err) {
    console.error('login submission failed', err);
    showLoginError('Could not reach the server. Please try again.');
  }
}

/// Password-free login for a cached account: prove knowledge of the cached
/// encryption key against the server's HMAC verifier. Falls back to the
/// sign-in form when the key cannot be presented (e.g. WebAuthn cancelled).
async function loginCachedAccount() {
  const username = $('#saved-account-select').val();
  const csrfInput = $('input[name="csrf_token"]').first();
  try {
    let key = await window.EncKey.getKeyForUsername(username);
    if (!key && window.EncKey.unlockWithWebAuthnForUser) {
      key = await window.EncKey.unlockWithWebAuthnForUser(username);
    }
    if (!key) {
      throw new Error('cached key unavailable');
    }
    const resp = await fetch('/login/keyauth', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Enc-Key': key,
      },
      body:
        'csrf_token=' + encodeURIComponent(csrfInput.val()) +
        '&username=' + encodeURIComponent(username),
    });
    if (!resp.ok) {
      throw new Error('cached key login rejected');
    }
    const data = await resp.json();
    if (!data || !data.username) {
      throw new Error('unexpected keyauth response');
    }
    window.EncKey.touchSlot(username);
    window.location.href = '/';
  } catch (err) {
    console.debug('cached key login failed', err);
    showLoginNotice('Could not sign in with the cached key for this account. Sign in below.');
    $('#saved-account-select').val(OTHER_ACCOUNT);
    applyAccountMode();
  }
}

function cachedModeActive() {
  return (
    savedAccountSectionVisible() &&
    $('#saved-account-select').val() !== OTHER_ACCOUNT
  );
}

function savedAccountSectionVisible() {
  return !$('#saved-account-section').hasClass('d-none');
}

/// Cached account selected: password/remember-me hidden (resume needs
/// neither), forget button shown. "Other account…": classic username +
/// password + remember form.
function applyAccountMode() {
  const cached = cachedModeActive();
  $('#username-section').toggleClass('d-none', cached);
  $('#username').prop('disabled', cached);
  $('#password-fields').toggleClass('d-none', cached);
  $('#password').prop('required', !cached);
  $('#forget-account').toggleClass('d-none', !cached);
}

async function refreshCsrfToken() {
  try {
    const resp = await fetch('/login');
    if (!resp.ok) {
      return;
    }
    const html = await resp.text();
    const match = html.match(/name="csrf_token" value="([^"]+)"/);
    if (match) {
      $('input[name="csrf_token"]').first().val(match[1]);
    }
  } catch (err) {
    console.debug('csrf token refresh failed', err);
  }
}

function renderSavedAccountSelect() {
  if (!window.EncKey || !window.EncKey.listCachedAccounts) {
    return Promise.resolve();
  }
  return window.EncKey.listCachedAccounts().then(function (usernames) {
    const $section = $('#saved-account-section');
    const $select = $('#saved-account-select');
    if (!usernames.length || !$section.length || !$select.length) {
      $section.addClass('d-none');
      $select.empty();
      applyAccountMode();
      return;
    }
    $select.empty();
    usernames.forEach(function (username) {
      $select.append($('<option>', { value: username }).text(username));
    });
    $select.append(
      $('<option>', { value: OTHER_ACCOUNT }).text('Other account…')
    );
    $section.removeClass('d-none');
    applyAccountMode();
  }).catch(function (err) {
    console.debug('saved account listing failed', err);
    applyAccountMode();
  });
}

$(function() {
  renderSavedAccountSelect();
  $('#saved-account-select').on('change', applyAccountMode);

  // Remove a cached account's key from this browser. The remember token (if
  // any) may belong to the forgotten account, so revoke it via /logout and
  // pick up a fresh session + CSRF token for any further keyauth attempt.
  $('#forget-account').on('click', async function() {
    const username = $('#saved-account-select').val();
    if (!username || username === OTHER_ACCOUNT || !window.EncKey || !window.EncKey.removeSlot) {
      return;
    }
    if (!window.confirm(
      'Remove the cached login for ' + username +
      ' from this browser? You will need the password to sign in to it again.'
    )) {
      return;
    }
    $(this).prop('disabled', true);
    try {
      await window.EncKey.removeSlot(username);
      try {
        await fetch('/logout', { method: 'GET' });
      } catch (err) {
        console.debug('logout during forget failed', err);
      }
      await refreshCsrfToken();
      await renderSavedAccountSelect();
      if (!savedAccountSectionVisible()) {
        showLoginNotice('Removed the cached login. Sign in with the username and password.');
      } else {
        showLoginNotice('Removed the cached login for ' + username + '.');
      }
    } finally {
      $(this).prop('disabled', false);
    }
  });

  $('form').on('submit', async function(e) {
    e.preventDefault();
    const form = this;

    if (cachedModeActive()) {
      await loginCachedAccount();
      return;
    }

    const username = $('#username').val().trim();
    const password = $('#password').val();
    let derivedKey = null;

    if (!username || !password) {
      await postLogin(form);
      return;
    }

    const isNative = window.NativeBridge && window.NativeBridge.isNativePlatform();

    try {
      const resp = await fetch(`/auth/salt/${encodeURIComponent(username)}`);
      if (!resp.ok) {
        if (isNative) {
          alert('Could not fetch encryption salt. Login cannot continue.');
          return;
        }
        console.warn('Could not fetch salt, falling back to server derivation');
        await postLogin(form);
        return;
      }

      const data = await resp.json();
      try {
        derivedKey = await deriveKeyForLogin(password, data.salt);
      } catch (deriveErr) {
        console.error('Native derivation failed', deriveErr);
        alert('Could not derive encryption key on this device. Login cannot continue.');
        return;
      }

      if (!derivedKey) {
        if (isNative) {
          alert('Could not derive encryption key on this device. Login cannot continue.');
          return;
        }
        console.log('Web Crypto unavailable. Using server-side derivation.');
        await postLogin(form);
        return;
      }

      form.querySelector('input[name="storage_key"]')?.remove();
      $('<input>').attr({
        type: 'hidden',
        name: 'storage_key',
        value: derivedKey,
      }).appendTo(form);
    } catch (err) {
      console.error('Client side derivation process failed', err);
      alert('Encryption setup failed. Login cannot continue.');
      return;
    }

    // Cache the key only after the server has verified it (a failed login must
    // not land in the saved-account dropdown). The slot backs the live session
    // (X-Enc-Key); `remember_me` only decides password-free re-entry later.
    await postLogin(form, async function () {
      if (!derivedKey || !window.EncKey || !window.EncKey.storeFromLogin) {
        return;
      }
      const rememberChecked = $('#remember_me').is(':checked');
      try {
        await window.EncKey.storeFromLogin(derivedKey, 'indexeddb', username, rememberChecked);
        const ok = await window.EncKey.verifyStoredKey(derivedKey, username);
        if (!ok) {
          throw new Error('Encryption key did not persist on this device');
        }
      } catch (storeErr) {
        console.error('Failed to store encryption key locally', storeErr);
        throw storeErr;
      }
    });
  });
});
