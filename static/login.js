async function deriveKey(password, saltB64) {
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
    console.error('Derivation failed', e);
    return null;
  }
}

$(function() {
  $('form').on('submit', async function(e) {
    e.preventDefault();
    const form = this;
    const username = $('#username').val().trim();
    const password = $('#password').val();

    if (!username || !password) {
      form.submit();
      return;
    }

    if (!window.crypto || !window.crypto.subtle) {
      console.log('Web Crypto API not available. Using server-side derivation.');
      form.submit();
      return;
    }

    try {
      const resp = await fetch(`/auth/salt/${encodeURIComponent(username)}`);
      if (!resp.ok) {
        console.warn('Could not fetch salt, falling back to server derivation');
        form.submit();
        return;
      }

      const data = await resp.json();
      const derivedKey = await deriveKey(password, data.salt);

      if (derivedKey) {
        if (window.EncKey && window.EncKey.storeFromLogin) {
          try {
            await window.EncKey.storeFromLogin(derivedKey, 'indexeddb');
            const ok = await window.EncKey.verifyStoredKey(derivedKey);
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
      } else {
        alert('Could not derive encryption key. Login cannot continue.');
        return;
      }
    } catch (err) {
      console.error('Client side derivation process failed', err);
      alert('Encryption setup failed. Login cannot continue.');
      return;
    }

    form.submit();
  });
});
