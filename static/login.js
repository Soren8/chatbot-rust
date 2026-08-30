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
    $list.empty();
    hashes.forEach(function (hash) {
      const chip = $('<button>', {
        type: 'button',
        class: 'btn btn-sm btn-outline-secondary saved-account-chip',
        'data-hash': hash,
        title: 'Cached key slot ' + hash,
      }).text(truncatedHash(hash));
      chip.on('click', function () {
        $('#username').trigger('focus');
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

async function tryRememberLogin() {
  if (!window.EncKey || typeof window.EncKey.hasCachedAccount !== 'function') {
    return;
  }
  const csrfInput = $('input[name="csrf_token"]').first();
  if (!csrfInput.length) {
    return;
  }
  try {
    const resp = await fetch('/login/remember', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'csrf_token=' + encodeURIComponent(csrfInput.val()),
    });
    if (!resp.ok) {
      return;
    }
    const data = await resp.json();
    if (!data || !data.username) {
      return;
    }
    const hasSlot = await window.EncKey.hasCachedAccount(data.username);
    if (hasSlot) {
      window.location.href = '/';
      return;
    }
    // Session restored, but this device has no cached key for the account:
    // data endpoints would 401, so ask for the password once instead.
    $('#username').val(data.username);
    showLoginNotice(
      'Signed in as ' + data.username + ', but the encryption key for this ' +
      'account is not cached on this device. Enter the password once to unlock.'
    );
  } catch (err) {
    console.debug('remember login not available', err);
  }
}

$(function() {
  renderSavedAccounts();
  $('#username').on('input', highlightMatchingAccount);
  tryRememberLogin();

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
