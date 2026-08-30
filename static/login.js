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

function renderSavedAccounts() {
  if (!window.EncKey || !window.EncKey.listCachedAccounts) {
    return;
  }
  window.EncKey.listCachedAccounts().then(function (hashes) {
    if (!hashes.length) {
      return;
    }
    const $container = $('#saved-accounts');
    const $list = $('#saved-account-list');
    if (!$container.length || !$list.length) {
      return;
    }
    showResumeButton(true);
    $list.empty();
    hashes.forEach(function (hash) {
      const chip = $('<button>', {
        type: 'button',
        class: 'btn btn-sm btn-outline-secondary saved-account-chip',
        'data-hash': hash,
        title: 'Cached key slot ' + hash,
      }).text(truncatedHash(hash));
      chip.on('click', function () {
        resumeFromChip(chip);
      });
      $list.append(chip);
    });
    $container.removeClass('d-none');
    highlightMatchingAccount();
  }).catch(function (err) {
    console.debug('saved account listing failed', err);
  });
}

function highlightMatchingAccount() {
  const username = $('#username').val();
  if (!username || !window.EncKey || !window.EncKey.accountHash) {
    $('.saved-account-chip').removeClass('border-success text-success');
    return;
  }
  window.EncKey.accountHash(username).then(function (hash) {
    $('.saved-account-chip').each(function () {
      const $chip = $(this);
      const matches = $chip.attr('data-hash') === hash;
      $chip.toggleClass('border-success text-success', matches);
    });
  }).catch(function () {});
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

function showResumeButton(show) {
  $('#resume-session-wrap').toggleClass('d-none', !show);
}

async function resumeFromChip(chip) {
  const data = await attemptRememberLogin();
  const csrfInput = $('input[name="csrf_token"]').first();
  if (!data) {
    showLoginNotice('No saved session available on this device. Sign in below.');
    showResumeButton(false);
    return;
  }
  const savedHash = await window.EncKey.accountHash(data.username);
  if (savedHash === chip.attr('data-hash')) {
    window.location.href = '/';
    return;
  }
  // The remembered session belongs to a different account than the chip the
  // user picked; the restore already rotated the session, so refresh CSRF.
  showLoginNotice(
    'The saved session is for account ' + truncatedHash(savedHash) +
    '. Sign in below to use the account you picked.'
  );
  await refreshCsrfToken(csrfInput);
}

$(function() {
  renderSavedAccounts();
  $('#username').on('input', highlightMatchingAccount);

  $('#resume-session').on('click', async function() {
    const data = await attemptRememberLogin();
    if (data && window.EncKey.hasCachedAccount(data.username)) {
      window.location.href = '/';
      return;
    }
    if (data) {
      // No cached key for the remembered account; ask for the password once.
      $('#username').val(data.username);
      showLoginNotice(
        'Signed in as ' + data.username + ', but the encryption key for this ' +
        'account is not cached on this device. Enter the password once to unlock.'
      );
      const csrfInput = $('input[name="csrf_token"]').first();
      await refreshCsrfToken(csrfInput);
      return;
    }
    showLoginNotice('No saved session available on this device. Sign in below.');
    showResumeButton(false);
  });

  $('form').on('submit', async function(e) {
    e.preventDefault();
    const form = this;
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
