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
    $notice.text(message).removeClass('d-none');
  } else {
    console.info(message);
  }
}

function truncatedHash(hash) {
  return '···' + hash.slice(-4);
}

async function refreshCsrfToken(csrfInput) {
  try {
    const resp = await fetch('/login');
    if (!resp.ok) {
      return;
    }
    const html = await resp.text();
    const match = html.match(/name="csrf_token" value="([^"]+)"/);
    if (match) {
      csrfInput.val(match[1]);
    }
  } catch (err) {
    console.debug('csrf token refresh failed', err);
  }
}

/// Attempt the remember-token restore. Returns {username} on success, else
/// null. A successful restore rotates the session and token server-side, so
/// callers that stay on the page must refreshCsrfToken() afterwards.
async function attemptRememberLogin() {
  const csrfInput = $('input[name="csrf_token"]').first();
  if (!csrfInput.length) {
    return null;
  }
  try {
    const resp = await fetch('/login/remember', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'csrf_token=' + encodeURIComponent(csrfInput.val()),
    });
    if (!resp.ok) {
      return null;
    }
    const data = await resp.json();
    if (data && data.username) {
      return data;
    }
  } catch (err) {
    console.debug('remember login not available', err);
  }
  return null;
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
/// neither). "Other account…": classic username + password + remember form.
function applyAccountMode() {
  const cached = cachedModeActive();
  $('#username-section').toggleClass('d-none', cached);
  $('#username').prop('disabled', cached);
  $('#password-fields').toggleClass('d-none', cached);
  $('#password').prop('required', !cached);
}

async function loginCachedAccount() {
  const data = await attemptRememberLogin();
  const csrfInput = $('input[name="csrf_token"]').first();
  if (!data) {
    showLoginNotice('No saved session is available on this device. Sign in below.');
    $('#saved-account-select').val(OTHER_ACCOUNT);
    applyAccountMode();
    return;
  }
  const restoredHash = await window.EncKey.accountHash(data.username);
  const pickedHash = $('#saved-account-select').val();
  if (restoredHash === pickedHash) {
    if (await window.EncKey.hasCachedAccount(data.username)) {
      window.location.href = '/';
      return;
    }
    // Session restored but the key is not cached on this device: password once.
    showLoginNotice(
      'Enter the password once to unlock ' + data.username + ' on this device.'
    );
    $('#saved-account-select').val(OTHER_ACCOUNT);
    $('#username').val(data.username);
    applyAccountMode();
    await refreshCsrfToken(csrfInput);
    return;
  }
  if (await window.EncKey.hasCachedAccount(data.username)) {
    // Remembered session belongs to a different cached account; offer it.
    $('#saved-account-select').val(restoredHash);
    showLoginNotice(
      'The saved session is for ' + truncatedHash(restoredHash) +
      '. Click Login to continue with it, or pick another account.'
    );
  } else {
    showLoginNotice(
      'The saved session is for ' + data.username +
      ', but its key is not cached here. Sign in below.'
    );
    $('#saved-account-select').val(OTHER_ACCOUNT);
    $('#username').val(data.username);
    applyAccountMode();
  }
  await refreshCsrfToken(csrfInput);
}

function renderSavedAccountSelect() {
  if (!window.EncKey || !window.EncKey.listCachedAccounts) {
    return;
  }
  window.EncKey.listCachedAccounts().then(function (hashes) {
    if (!hashes.length) {
      applyAccountMode();
      return;
    }
    const $section = $('#saved-account-section');
    const $select = $('#saved-account-select');
    if (!$section.length || !$select.length) {
      return;
    }
    $select.empty();
    hashes.forEach(function (hash) {
      $select.append($('<option>', { value: hash }).text(truncatedHash(hash)));
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

  $('form').on('submit', async function(e) {
    e.preventDefault();
    const form = this;

    if (cachedModeActive()) {
      await loginCachedAccount();
      return;
    }

    const username = $('#username').val().trim();
    const password = $('#password').val();

    if (!username || !password) {
      form.submit();
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
        form.submit();
        return;
      }

      const data = await resp.json();
      let derivedKey;
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
        form.submit();
        return;
      }

      if (window.EncKey && window.EncKey.storeFromLogin) {
        try {
          await window.EncKey.storeFromLogin(derivedKey, 'indexeddb', username);
          const ok = await window.EncKey.verifyStoredKey(derivedKey, username);
          if (!ok) {
            throw new Error('Encryption key did not persist on this device');
          }
        } catch (storeErr) {
          console.error('Failed to store encryption key locally', storeErr);
          alert('Could not save encryption key on this device. Login cannot continue.');
          return;
        }
      }
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

    form.submit();
  });
});
