'use strict';

// goproxy web UI. Every piece of data from the server goes into the page as
// text (textContent / DOM nodes), never as HTML.

const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

class HTTPError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = { method, headers: { 'X-Goproxy': '1' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* no body */ }
  if (!res.ok) {
    if (res.status === 401 && path !== 'api/login') showLogin();
    throw new HTTPError(res.status, data.error || res.statusText);
  }
  return data;
}

// --- formatting ---

function bytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

function ago(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

function clock(iso) {
  const d = new Date(iso);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const splitList = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    // No clipboard API outside HTTPS: fall back to a selected textarea.
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) { /* ignore */ }
    ta.remove();
    return ok;
  }
}

// flash shows text on a button (in its label span, if it has one) for a moment.
function flash(button, text) {
  const target = button.querySelector('.lbl') || button;
  const old = target.textContent;
  target.textContent = text;
  setTimeout(() => { target.textContent = old; }, 1200);
}

// copyIcon returns the two-squares "copy" icon.
function copyIcon() {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.4');
  for (const [x, y] of [[5, 5], [2, 2]]) {
    const r = document.createElementNS(ns, 'rect');
    r.setAttribute('x', x); r.setAttribute('y', y);
    r.setAttribute('width', 9); r.setAttribute('height', 9); r.setAttribute('rx', 1.5);
    svg.append(r);
  }
  return svg;
}

function copyButton(text) {
  return h('button', {
    class: 'copy small',
    onclick: async (e) => flash(e.currentTarget, (await copyText(text)) ? 'Copied' : 'Failed'),
  }, copyIcon(), h('span', { class: 'lbl' }, 'Copy'));
}

function banner(text) {
  $('#banner').textContent = text || '';
  $('#banner').hidden = !text;
}

// --- login and polling ---

let state = null; // {node, peers, file_peers}
let settings = null; // {settings: [{key, value, source}], editable}
let lastConnections = null;
let timer = null;

function showLogin() {
  document.title = 'Sign in';
  clearInterval(timer);
  timer = null;
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-password').focus();
}

async function showApp() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  await refresh();
  clearInterval(timer);
  timer = setInterval(refresh, 3000);
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  try {
    await api('POST', 'api/login', { password: $('#login-password').value });
    $('#login-password').value = '';
    showApp();
  } catch (err) {
    $('#login-error').textContent = err.status === 401 ? 'Wrong password' : err.message;
  }
});

$('#logout').addEventListener('click', async () => {
  try { await api('POST', 'api/logout'); } catch (_) { /* ignore */ }
  showLogin();
});

async function refresh() {
  try {
    state = await api('GET', 'api/state');
    renderNode();
    renderPeers();
    renderConnections(await api('GET', 'api/connections'));
  } catch (err) {
    if (err.status !== 401) console.error(err);
  }
}

// --- this node ---

const pushRoutesText = {
  false: 'off',
  true: 'host and forwarded traffic',
  clients: 'forwarded traffic only',
};

function renderNode() {
  const n = state.node;
  $('#node-name').textContent = n.name;
  document.title = `${n.name} · goproxy`;
  const row = (k, ...v) => h('div', { class: 'kv-row' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, ...v));
  $('#node-facts').replaceChildren(
    h('div', { class: 'label' }, 'Public key'),
    h('div', { class: 'value-box' },
      h('code', { class: 'big', text: n.public_key }),
      h('div', { class: 'box-actions' }, copyButton(n.public_key))),
    h('div', { class: 'kv' },
      row('TUN', h('span', { text: n.tun_address }), h('span', { class: 'muted' }, `MTU ${n.mtu}`)),
      row('Accepts peers', n.listen
        ? [h('span', { text: n.listen }), h('span', { class: 'muted' }, n.transport)]
        : h('span', { class: 'muted' }, 'no')),
      row('Host routes', pushRoutesText[n.push_routes] || n.push_routes),
      n.masquerade ? row('Masquerade', n.masquerade) : null,
      row('Peers', peerSummary())));
  $('#readonly-note').hidden = n.editable;
  $('#add-peer').hidden = !n.editable;
}

// --- node settings dialog: key and settings ---

function renderKey() {
  const n = state.node;
  $('#key-public').textContent = n.public_key;
  const fromFile = n.key_source === 'file';
  $('#key-actions').replaceChildren(
    copyButton(n.public_key),
    fromFile ? h('button', { class: 'small', onclick: regenerateKey }, 'Generate new') : null);
  $('#key-env').hidden = fromFile;
  $('#key-form').hidden = !fromFile;
}

async function openSettings() {
  $('#settings-error').textContent = '';
  $('#key-error').textContent = '';
  $('#key-form').reset();
  renderKey();
  await loadSettings();
  $('#settings-dialog').showModal();
}

$('#open-settings').addEventListener('click', openSettings);

// peerSummary shows how many enabled peers are connected: green when all
// are, yellow when some are not, red when none is (grey with no peers).
function peerSummary() {
  const enabled = state.peers.filter((p) => !p.disabled);
  const up = enabled.filter((p) => p.links.length).length;
  let cls = 'muted';
  if (enabled.length) cls = up === enabled.length ? 'status-on' : up === 0 ? 'status-err' : 'status-warn';
  return h('span', { class: cls }, `${up} connected of ${enabled.length}`);
}

async function regenerateKey() {
  const ok = await confirmBox('Generate a new node key? Peers reject the node until they are given the new '
    + 'public key; established sessions persist until they reconnect.');
  if (!ok) return;
  try {
    await api('POST', 'api/node/key');
    await refresh();
    renderKey();
  } catch (err) {
    $('#key-error').textContent = err.message;
  }
}

$('#key-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#key-error').textContent = '';
  try {
    await api('POST', 'api/node/key', { private_key: $('#key-private').value.trim() });
    $('#key-private').value = '';
    await refresh();
    renderKey();
    flash($('#key-form button[type=submit]'), 'Key set');
  } catch (err) {
    $('#key-error').textContent = err.message;
  }
});

// --- peers ---

function renderPeers() {
  const tbody = $('#peers tbody');
  tbody.replaceChildren();
  if (!state.peers.length) {
    tbody.append(h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'No peers yet.')));
    return;
  }
  for (const p of state.peers) {
    const up = p.links.length > 0;
    const rx = p.links.reduce((a, l) => a + l.rx_bytes, 0);
    const tx = p.links.reduce((a, l) => a + l.tx_bytes, 0);
    const editable = state.node.editable && p.source === 'file';

    const name = h('td', {},
      h('strong', { text: p.name }),
      p.source === 'env' ? h('span', { class: 'badge', title: 'defined in the environment; read-only' }, 'env') : null,
      p.nat ? h('span', { class: 'badge', title: 'source NAT' }, 'NAT') : null,
      p.disabled ? h('span', { class: 'badge' }, 'disabled') : null);

    let status;
    if (p.disabled) {
      status = h('td', {}, h('span', { class: 'dot' }), 'disabled');
    } else {
      status = h('td', {},
        h('div', { class: up ? 'status-on' : 'muted' }, h('span', { class: up ? 'dot on' : 'dot' }), up ? 'connected' : 'not connected'),
        p.links.map((l) => h('div', { class: 'sub' },
          `${l.direction === 'out' ? 'outbound' : 'inbound'}, ${ago(l.since)}`)));
    }

    const routes = h('td', {}, h('div', { class: 'routes' },
      p.ip ? h('code', { title: 'assigned tunnel IP' }, `${p.ip} (IP)`) : null,
      (p.routes || []).map((r) => h('code', { text: r }))));

    const conn = h('td', {},
      p.links.map((l) => [
        h('div', { class: 'mono' }, l.remote),
        l.tunnel_ip ? h('div', { class: 'sub' }, `local tunnel IP ${l.tunnel_ip}`) : null,
      ]),
      !up && p.endpoint ? h('div', { class: 'sub' }, p.disabled ? '' : 'connecting to ', h('code', { text: p.endpoint })) : null,
      !up && !p.endpoint && !p.disabled ? h('div', { class: 'sub' }, 'inbound only') : null);

    const traffic = h('td', { class: 'traffic' },
      up ? [h('div', { title: 'received' }, `↓ ${bytes(rx)}`), h('div', { title: 'sent' }, `↑ ${bytes(tx)}`)] : null);

    const actions = h('td', { class: 'actions-cell' },
      h('button', { class: 'small', onclick: () => openConfig(p) }, 'Config'),
      editable ? h('button', { class: 'small', onclick: () => openPeer(p.name) }, 'Edit') : null,
      editable ? h('button', { class: 'small', onclick: () => toggleDisabled(p.name) }, p.disabled ? 'Enable' : 'Disable') : null,
      editable ? h('button', { class: 'small', onclick: () => deletePeer(p.name) }, 'Delete') : null);

    tbody.append(h('tr', { class: p.disabled ? 'disabled' : null }, name, status, routes, conn, traffic, actions));
  }
}

async function toggleDisabled(name) {
  const raw = state.file_peers.find((p) => p.name === name);
  if (!raw) return;
  try {
    await api('PUT', `api/peers/${encodeURIComponent(name)}`, { ...raw, disabled: !raw.disabled });
    refresh();
  } catch (err) {
    banner(err.message);
  }
}

async function deletePeer(name) {
  if (!(await confirmBox(`Delete peer ${name}? Its sessions are closed.`))) return;
  try {
    await api('DELETE', `api/peers/${encodeURIComponent(name)}`);
    refresh();
  } catch (err) {
    banner(err.message);
  }
}

// --- network lists ---

const ipv4Net = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(3[0-2]|[12]?\d)$/;
const ipv4Addr = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

// netChips turns a text input holding a list of networks into chips. The
// input stays in the form (hidden) and holds the list space-separated, so it
// is read as before; it gets an 'input' event on every change.
function netChips(input) {
  let list = [];
  const entry = h('input', { class: 'chip-entry', autocomplete: 'off', spellcheck: 'false' });
  const box = h('div', { class: 'chips', onclick: (e) => { if (e.target === box) entry.focus(); } }, entry);
  input.before(box); // first in its label, so a click on the label focuses the entry
  input.hidden = true;

  const changed = () => {
    input.value = list.join(' ');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  };
  function render() {
    box.querySelectorAll('.chip').forEach((c) => c.remove());
    list.forEach((v, i) => {
      const ok = ipv4Net.test(v);
      entry.before(h('span', { class: ok ? 'chip' : 'chip bad', title: ok ? null : 'Not an IPv4 network' },
        h('span', { ondblclick: () => edit(i) }, v),
        // Not a <button>: inside a <label> a click on the label would press it.
        h('span', {
          class: 'chip-x', role: 'button', 'aria-label': `Remove ${v}`,
          onmousedown: (e) => e.preventDefault(), // keep the entry focused: its blur re-renders
          onclick: (e) => {
            e.preventDefault();
            if (entry.disabled) return;
            list.splice(i, 1); render(); changed(); entry.focus();
          },
        }, '×')));
    });
    entry.placeholder = list.length ? '' : input.placeholder;
  }
  function add(text) {
    let added = false;
    for (let v of text.split(/[\s,;]+/).filter(Boolean)) {
      if (ipv4Addr.test(v)) v += '/32';
      if (!list.includes(v)) { list.push(v); added = true; }
    }
    if (added) { render(); changed(); }
  }
  function commit() {
    const v = entry.value;
    entry.value = '';
    if (v.trim()) add(v);
  }
  function edit(i) {
    if (entry.disabled) return;
    commit();
    entry.value = list[i];
    list.splice(i, 1);
    render();
    changed();
    entry.focus();
  }

  entry.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === 'Tab') && entry.value.trim()) {
      if (e.key === 'Enter') e.preventDefault();
      commit();
    } else if (e.key === 'Backspace' && !entry.value && list.length) {
      e.preventDefault();
      edit(list.length - 1);
    }
  });
  // A separator ends a network: typed, pasted, or from a mobile keyboard.
  entry.addEventListener('input', () => {
    if (!/[\s,;]/.test(entry.value)) return;
    const parts = entry.value.split(/[\s,;]+/);
    const rest = /[\s,;]$/.test(entry.value) ? '' : parts.pop();
    add(parts.join(' '));
    entry.value = rest;
  });
  entry.addEventListener('paste', (e) => {
    const text = (e.clipboardData || window.clipboardData).getData('text');
    if (!text.trim()) return;
    e.preventDefault();
    add(entry.value + ' ' + text);
    entry.value = '';
  });
  entry.addEventListener('blur', commit);

  return {
    set(values) { list = [...values]; entry.value = ''; render(); input.value = list.join(' '); },
    commit,
    invalid: () => list.filter((v) => !ipv4Net.test(v)),
    set disabled(d) { entry.disabled = d; box.classList.toggle('disabled', d); },
  };
}

// --- peer form ---

const field = (name) => $('#peer-form').elements.namedItem(name);
const routeChips = netChips(field('routes'));
let editing = null;      // name of the peer being edited; null for a new one
let generatedKey = null; // key pair generated in the open form

function syncTLSFields() {
  const t = field('transport').value || state.node.transport;
  document.querySelectorAll('.tls-only').forEach((el) => { el.hidden = t !== 'tls'; });
}

function openPeer(name) {
  const raw = name ? state.file_peers.find((p) => p.name === name) : null;
  editing = raw ? raw.name : null;
  generatedKey = null;
  $('#peer-form').reset();
  field('keepalive_saved').value = ''; // reset() leaves hidden inputs alone
  $('#peer-title').textContent = raw ? `Peer ${raw.name}` : 'New peer';
  $('#keypair-note').hidden = true;
  $('#peer-error').textContent = '';
  routeChips.set(raw ? raw.routes || [] : []);
  if (raw) {
    field('name').value = raw.name;
    field('endpoint').value = raw.endpoint || '';
    field('transport').value = raw.transport || '';
    field('psk').value = raw.psk || '';
    field('sni').value = (raw.tls && raw.tls.sni) || '';
    field('insecure').checked = !!(raw.tls && raw.tls.insecure);
    field('public_key').value = raw.public_key || '';
    field('ip').value = raw.ip || '';
    field('nat').checked = !!raw.nat;
    field('enabled').checked = !raw.disabled;
    field('keepalive_saved').value = raw.keepalive || '';
  }
  syncTLSFields();
  $('#peer-dialog').showModal();
  field('name').focus();
}

$('#add-peer').addEventListener('click', () => openPeer(null));
field('transport').addEventListener('change', syncTLSFields);

$('#gen-keypair').addEventListener('click', async () => {
  try {
    generatedKey = await api('POST', 'api/keypair');
    field('public_key').value = generatedKey.public_key;
    $('#keypair-note').hidden = false;
  } catch (err) {
    $('#peer-error').textContent = err.message;
  }
});

$('#next-ip').addEventListener('click', async () => {
  try {
    field('ip').value = (await api('GET', 'api/next-ip')).ip;
  } catch (err) {
    $('#peer-error').textContent = err.message;
  }
});

$('#peer-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#peer-error').textContent = '';
  routeChips.commit();
  const bad = routeChips.invalid();
  if (bad.length) {
    $('#peer-error').textContent = `Not an IPv4 network: ${bad.join(', ')}`;
    return;
  }
  const peer = {
    name: field('name').value.trim(),
    public_key: field('public_key').value.trim(),
    routes: splitList(field('routes').value),
    ip: field('ip').value.trim(),
    endpoint: field('endpoint').value.trim(),
    nat: field('nat').checked,
    disabled: !field('enabled').checked,
    transport: field('transport').value,
    psk: field('psk').value,
    tls: { sni: field('sni').value.trim(), insecure: field('insecure').checked },
    keepalive: Number(field('keepalive_saved').value) || 0,
  };
  // A key typed over a generated one: the generated private key no longer applies.
  const privateKey = generatedKey && generatedKey.public_key === peer.public_key ? generatedKey.private_key : null;
  try {
    if (editing) await api('PUT', `api/peers/${encodeURIComponent(editing)}`, peer);
    else await api('POST', 'api/peers', peer);
    $('#peer-dialog').close();
    await refresh();
    const saved = state.peers.find((p) => p.name === peer.name);
    if (saved && privateKey) openConfig(saved, privateKey);
  } catch (err) {
    $('#peer-error').textContent = err.message;
  }
});

// --- config for the peer's side ---

let configFor = null; // {peer, privateKey}
const cfgChips = netChips($('#cfg-routes'));

function openConfig(peer, privateKey) {
  configFor = { peer, privateKey: privateKey || null };
  const n = state.node;
  $('#config-peer').textContent = peer.name;
  $('#cfg-endpoint').value = n.listen ? `${location.hostname}:${n.listen.split(':').pop()}` : '';
  $('#cfg-name').value = n.name;
  // By default: this node's TUN network and what its other peers route.
  const nets = new Set([n.tun_network]);
  for (const q of state.peers) {
    if (q.name === peer.name || q.disabled) continue;
    for (const r of q.routes || []) if (r !== '0.0.0.0/0') nets.add(r);
  }
  cfgChips.set([...nets]);
  $('#cfg-all').checked = false;
  $('#cfg-secret').hidden = !privateKey;
  renderConfig();
  $('#config-dialog').showModal();
}

function renderConfig() {
  if (!configFor) return;
  const { peer, privateKey } = configFor;
  const n = state.node;
  const us = ($('#cfg-name').value.trim() || n.name).toUpperCase().replace(/[^A-Z0-9_-]/g, '_');
  const all = $('#cfg-all').checked;
  cfgChips.disabled = all;
  const routes = all ? ['0.0.0.0/0'] : splitList($('#cfg-routes').value).filter((r) => ipv4Net.test(r));
  const endpoint = $('#cfg-endpoint').value.trim();
  const psk = peer.psk || n.psk;

  const comments = [];
  const vars = [['GOPROXY_PRIVATE_KEY', privateKey || "<the peer's private key>"]];
  if (psk) vars.push(['GOPROXY_PSK', psk]);
  vars.push(['GOPROXY_TRANSPORT', n.transport]);
  if (n.transport === 'tls' && n.self_signed_tls) vars.push(['GOPROXY_TLS_INSECURE', 'true']);
  vars.push(['GOPROXY_PUSH_ROUTES', 'true']);
  if (!peer.ip) comments.push('No assigned tunnel IP: set GOPROXY_TUN_ADDRESS from the peer network.');
  const base = `GOPROXY_PEER_${us}`;
  vars.push([`${base}_PUBLIC_KEY`, n.public_key]);
  if (endpoint) vars.push([`${base}_ENDPOINT`, endpoint]);
  else comments.push('This node does not listen: set GOPROXY_LISTEN on the peer and its endpoint on this node.');
  if (routes.length) vars.push([`${base}_ROUTES`, routes.join(' ')]);

  let text;
  if (document.querySelector('input[name=cfg-format]:checked').value === 'env') {
    text = [...comments.map((c) => `# ${c}`), ...vars.map(([k, v]) => `${k}=${v}`)].join('\n');
  } else {
    text = [
      'services:',
      '  goproxy:',
      '    image: crashntech/go-proxy:latest',
      '    container_name: goproxy',
      '    restart: unless-stopped',
      '    command: ["node"]',
      '    network_mode: host',
      '    cap_add: [NET_ADMIN]',
      '    devices: ["/dev/net/tun:/dev/net/tun"]',
      '    environment:',
      ...comments.map((c) => `      # ${c}`),
      ...vars.map(([k, v]) => `      ${k}: ${JSON.stringify(v)}`),
    ].join('\n');
  }
  $('#cfg-output').value = text;
}

['#cfg-endpoint', '#cfg-name', '#cfg-routes'].forEach((s) => $(s).addEventListener('input', renderConfig));
$('#cfg-all').addEventListener('change', renderConfig);
document.querySelectorAll('input[name=cfg-format]').forEach((r) => r.addEventListener('change', renderConfig));
$('#cfg-copy').append(copyIcon(), h('span', { class: 'lbl' }, 'Copy'));
$('#cfg-copy').addEventListener('click', async (e) => {
  flash(e.currentTarget, (await copyText($('#cfg-output').value)) ? 'Copied' : 'Failed');
});
$('#config-dialog').addEventListener('close', () => {
  configFor = null; // forget a generated private key
  $('#cfg-output').value = '';
});

// --- settings ---

// How each setting is edited. Order is the order on the page.
const settingFields = {
  GOPROXY_NAME: { label: 'Node name', help: 'Peer name in generated configurations.' },
  GOPROXY_LISTEN: { label: 'Listen address', placeholder: '0.0.0.0:443', help: 'Empty: inbound connections disabled.' },
  GOPROXY_TRANSPORT: { label: 'Transport', options: ['aead', 'tls', 'udp'], help: 'Listener transport; default for outbound peers.' },
  GOPROXY_PSK: { label: 'PSK', help: 'Default pre-shared key.' },
  GOPROXY_TLS_HOST: { label: 'TLS host', placeholder: 'www.microsoft.com', help: 'CN/SAN of the self-signed certificate.' },
  GOPROXY_TUN_ADDRESS: { label: 'TUN address', placeholder: '10.8.0.1/24', help: 'Assigned tunnel IPs are allocated from this network.' },
  GOPROXY_PUSH_ROUTES: {
    label: 'Host routes',
    options: [['false', 'off'], ['true', 'host and forwarded traffic'], ['clients', 'forwarded traffic only']],
    help: 'Install peer routes into the TUN.',
  },
  GOPROXY_MASQUERADE: { label: 'SNAT interface', placeholder: 'eth0' },
  GOPROXY_MASQUERADE_IPS: { label: 'SNAT source networks', placeholder: 'TUN network', networks: true },
  GOPROXY_LOG_CONNECTIONS: { label: 'Log connections', options: [['false', 'off'], ['true', 'on']] },
};

async function loadSettings() {
  try {
    settings = await api('GET', 'api/settings');
  } catch (err) {
    return;
  }
  const form = $('#settings-form');
  form.replaceChildren();
  $('#settings-readonly').hidden = settings.editable;
  $('#settings-save').hidden = !settings.editable;
  for (const s of settings.settings) {
    const f = settingFields[s.key] || { label: s.key };
    const locked = s.source === 'env' || !settings.editable;
    let input;
    if (f.options) {
      input = h('select', { name: s.key, disabled: locked },
        f.options.map((o) => (Array.isArray(o) ? h('option', { value: o[0] }, o[1]) : h('option', { value: o }, o))));
      input.value = s.value;
    } else {
      input = h('input', { name: s.key, disabled: locked, placeholder: f.placeholder || '', autocomplete: 'off' });
      input.value = s.value;
    }
    form.append(h('label', {},
      h('span', {}, f.label, s.source === 'env' ? h('span', { class: 'src env' }, 'set by environment') : null),
      input,
      f.help ? h('small', {}, f.help) : null));
    if (f.networks) {
      const chips = netChips(input);
      chips.set(splitList(s.value));
      input.value = s.value; // unchanged until edited
      chips.disabled = locked;
    }
  }
}

$('#settings-save').addEventListener('click', async () => {
  $('#settings-error').textContent = '';
  const body = {};
  for (const s of settings.settings) {
    if (s.source === 'env') continue;
    const el = $('#settings-form').elements.namedItem(s.key);
    if (el.value !== s.value) body[s.key] = el.value;
  }
  if (!Object.keys(body).length) {
    $('#settings-error').textContent = 'No changes.';
    return;
  }
  if (!(await confirmBox('Save settings and restart the node? Tunnel traffic is interrupted; '
    + 'UDP peers may take up to 90 s to reconnect.'))) return;
  try {
    await api('PUT', 'api/settings', body);
  } catch (err) {
    $('#settings-error').textContent = err.message;
    return;
  }
  $('#settings-dialog').close();
  await waitForRestart(body);
});

// waitForRestart shows the overlay until the node answers again, then tells
// whether the new settings took effect or were rolled back.
async function waitForRestart(wanted) {
  clearInterval(timer);
  $('#restarting').hidden = false;
  await sleep(2000);
  let back = false;
  for (let i = 0; i < 60 && !back; i++) {
    try {
      await api('GET', 'api/settings');
      back = true;
    } catch (err) {
      if (err.status === 401) { $('#restarting').hidden = true; return; }
      await sleep(1000);
    }
  }
  $('#restarting').hidden = true;
  if (!back) {
    banner('The node did not come back within 60 s. Check its log.');
    return;
  }
  await showApp();
  await loadSettings();
  const norm = (v) => splitList(v || '').join(' ');
  const now = Object.fromEntries(settings.settings.map((s) => [s.key, norm(s.value)]));
  const rolledBack = Object.entries(wanted).some(([k, v]) => norm(v) !== '' && now[k] !== norm(v));
  banner(rolledBack
    ? 'Startup with the new settings failed; the previous settings were restored. See the node log.'
    : '');
}

// --- connection log ---

function renderConnections(c) {
  lastConnections = c;
  $('#conn-disabled').hidden = c.enabled;
  $('#connections').hidden = !c.enabled;
  if (!c.enabled) return;
  const filter = $('#conn-filter').value.trim().toLowerCase();
  const lines = (c.entries || []).slice().reverse()
    .filter((e) => !filter || e.text.toLowerCase().includes(filter))
    .slice(0, 500)
    .map((e) => `${clock(e.time)}  ${e.text.replace(/^conn /, '')}`);
  $('#connections').textContent = lines.length ? lines.join('\n') : 'Nothing yet.';
}

$('#conn-filter').addEventListener('input', () => { if (lastConnections) renderConnections(lastConnections); });

// --- dialogs ---

document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-close]');
  if (b) b.closest('dialog').close();
});

function confirmBox(text) {
  return new Promise((resolve) => {
    const d = $('#confirm-dialog');
    $('#confirm-text').textContent = text;
    const ok = () => { resolve(true); d.close(); };
    $('#confirm-ok').addEventListener('click', ok, { once: true });
    d.addEventListener('close', () => {
      $('#confirm-ok').removeEventListener('click', ok);
      resolve(false);
    }, { once: true });
    d.showModal();
  });
}

// --- start ---

(async () => {
  try {
    await api('GET', 'api/state');
    showApp();
  } catch (err) {
    showLogin();
    if (err.status !== 401) $('#login-error').textContent = err.message;
  }
})();
