(function () {
  'use strict';
  var root = document.getElementById('connections-settings');
  if (!root) return;

  var list = document.getElementById('connections-list');
  var status = document.getElementById('connections-status');
  var form = document.getElementById('connection-form');
  var name = document.getElementById('connection-name');
  var url = document.getElementById('connection-url');
  var username = document.getElementById('connection-username');
  var password = document.getElementById('connection-password');
  var save = document.getElementById('connection-save');
  var refresh = document.getElementById('connections-refresh');
  var cancel = document.getElementById('connection-cancel');
  var records = [];
  var editing = null;
  var busy = false;

  function message(text) { status.textContent = text; }
  function errorMessage(code) {
    var errors = {
      agent_connections_forbidden: 'Connections are not enabled for this account.',
      connection_target_forbidden: 'This server address is not allowed by deployment policy.',
      blocked_by_policy: 'Blocked by deployment policy.',
      invalid_base_url: 'Enter a valid server-reachable URL.',
      invalid_connection_input: 'Check the connection fields and try again.',
      connection_limit_reached: 'Connection limit reached.',
      connection_not_found: 'Connection not found. Refresh the list.',
      connection_version_conflict: 'Connection changed elsewhere. Refresh the list and retry.',
      agent_auth_failed: 'The remote service rejected the credentials.',
      agent_timeout: 'The remote service timed out.',
      agent_invalid_health: 'The remote service returned an invalid health result.',
      agent_unhealthy: 'The remote service is unhealthy.',
      agent_unavailable: 'The remote service is unavailable.',
      agent_check_busy: 'Too many checks are running. Try later.',
      agent_check_rate_limited: 'Check limit reached. Try later.'
    };
    return errors[code] || 'Connection request failed. Please try again.';
  }

  async function request(path, method, payload) {
    var options = { method: method, cache: 'no-store' };
    if (payload !== undefined) {
      options.headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': window.CSRF_TOKEN || '' };
      options.body = JSON.stringify(payload);
    }
    var response = await fetch(path, options);
    if (!response.ok) {
      var body = await response.json().catch(function () { return {}; });
      throw new Error(errorMessage(body && body.error));
    }
    return response.status === 204 ? null : response.json();
  }

  function resetForm() {
    editing = null;
    form.reset();
    password.value = '';
    password.required = true;
    username.value = 'opencode';
    document.getElementById('connection-form-title').textContent = 'Add connection';
    document.getElementById('connection-password-hint').textContent = 'Required when adding. Never shown again.';
    save.textContent = 'Add';
    cancel.hidden = true;
  }

  function startEdit(record) {
    editing = record.id;
    name.value = record.name;
    url.value = record.base_url;
    username.value = record.username;
    password.value = '';
    password.required = false;
    document.getElementById('connection-form-title').textContent = 'Edit connection';
    document.getElementById('connection-password-hint').textContent = 'Leave blank to keep the current password; enter a new one to rotate it.';
    save.textContent = 'Save changes';
    cancel.hidden = false;
    name.focus();
  }

  function button(label, action) {
    var element = document.createElement('button');
    element.type = 'button';
    element.className = 'btn btn-outline-secondary btn-sm';
    element.textContent = label;
    element.disabled = busy;
    element.addEventListener('click', action);
    return element;
  }

  function render() {
    list.replaceChildren();
    if (!records.length) { list.textContent = 'No connections saved.'; return; }
    records.forEach(function (record) {
      var card = document.createElement('div');
      card.className = 'border rounded p-2';
      var details = document.createElement('div');
      details.className = 'small text-break';
      details.textContent = record.name + ' · OpenCode · Non-private\n' + record.base_url + '\nBasic username: ' + record.username;
      details.style.whiteSpace = 'pre-line';
      card.appendChild(details);
      var health = document.createElement('div');
      health.className = 'small';
      var check = record.last_check;
      health.textContent = check && check.status === 'blocked_by_policy' ? 'Blocked by deployment policy.' :
        check && check.status === 'reachable' ? 'Reachable' + (check.version ? ' (version ' + check.version + ')' : '') +
          (check.checked_at ? ' · checked ' + new Date(check.checked_at * 1000).toLocaleString() : '') : 'Not checked';
      card.appendChild(health);
      var actions = document.createElement('div');
      actions.className = 'd-flex flex-wrap gap-2 mt-2';
      actions.appendChild(button('Edit / rotate', function () { startEdit(record); }));
      actions.appendChild(button('Test', function () {
        perform(async function () {
          var result = await request('/agent_connections/' + encodeURIComponent(record.id) + '/check', 'POST', { expected_revision: record.revision });
          message('Connection reachable' + (result.version ? ' (version ' + result.version + ')' : '') + '.');
          await load(false);
        });
      }));
      actions.appendChild(button('Remove', function () {
        if (!window.confirm('Remove this connection? Its remote password will not be revoked.')) return;
        perform(async function () {
          await request('/agent_connections/' + encodeURIComponent(record.id), 'DELETE', { expected_revision: record.revision });
          if (editing === record.id) resetForm();
          await load(false);
          message('Connection removed. Remote credentials were not revoked.');
        });
      }));
      card.appendChild(actions);
      list.appendChild(card);
    });
  }

  async function load(announce) {
    records = await request('/agent_connections', 'GET');
    render();
    if (announce) message('Connections loaded.');
  }

  async function perform(action) {
    if (busy) return;
    busy = true;
    save.disabled = true;
    refresh.disabled = true;
    render();
    message('Working…');
    try { await action(); }
    catch (error) { message(error.message || 'Connection request failed.'); }
    finally { busy = false; save.disabled = false; refresh.disabled = false; render(); }
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    if (busy) return;
    var selected = records.find(function (record) { return record.id === editing; });
    var secret = password.value;
    password.value = '';
    if (!selected && !secret) { message('Enter a password to add a connection.'); return; }
    var payload = { name: name.value, base_url: url.value, username: username.value };
    if (selected) payload.expected_revision = selected.revision;
    else payload.kind = 'opencode';
    if (secret) payload.password = secret;
    var path = selected ? '/agent_connections/' + encodeURIComponent(selected.id) : '/agent_connections';
    var method = selected ? 'PATCH' : 'POST';
    perform(async function () {
      try { await request(path, method, payload); }
      finally { delete payload.password; secret = null; }
      resetForm();
      await load(false);
      message('Connection saved.');
    });
  });
  cancel.addEventListener('click', resetForm);
  refresh.addEventListener('click', function () { perform(function () { return load(true); }); });
  perform(function () { return load(false).then(function () { message(''); }); });
})();
