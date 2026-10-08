/* Netwatch dashboard logic.
 *
 * No framework and no build step: this file is served straight from the binary.
 * Everything rendered from an API payload goes through esc() — the payload
 * contains names the operator typed, and a device that announces itself as
 * "<script>" is exactly the kind of thing that turns up on a home network.
 */
'use strict';

/* ────────────────────────────── helpers ────────────────────────────── */

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function hb(n) {
  n = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n = n / 1024; i += 1; }
  return (i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
}

function ago(ts) {
  if (!ts) return 'unknown';
  const s = Math.max(0, Math.floor(Date.now() / 1000) - Number(ts));
  if (s < 45) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function when(ts) {
  if (!ts) return 'unknown';
  return new Date(Number(ts) * 1000).toLocaleString();
}

function dur(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
  return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h';
}

/** An inline link that opens a glossary entry, so every term explains itself. */
function t(term, label) {
  return '<button class="term" data-term="' + esc(term) + '">' + esc(label || term) + '</button>';
}

function bars(values, titleFn) {
  const list = (values && values.length) ? values : [0];
  const max = Math.max(1, ...list.map((v) => Number(v) || 0));
  const body = list.map((v) => {
    const value = Number(v) || 0;
    const pct = value === 0 ? 2 : Math.max(3, Math.round((value / max) * 100));
    const title = titleFn ? titleFn(value) : String(value);
    return '<i class="' + (value ? '' : 'zero') + '" style="height:' + pct + '%" title="' + esc(title) + '"></i>';
  }).join('');
  return '<div class="chart">' + body + '</div>';
}

function spark(values) {
  const list = (values && values.length) ? values : [];
  const max = Math.max(1, ...list.map((v) => Number(v) || 0));
  return '<span class="spark">' + list.map((v) => {
    const value = Number(v) || 0;
    const pct = value === 0 ? 6 : Math.max(10, Math.round((value / max) * 100));
    return '<i class="' + (value >= max * 0.6 ? 'hot' : '') + '" style="height:' + pct + '%"></i>';
  }).join('') + '</span>';
}

function barrow(name, value, total, extra) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return '<div class="barrow">' +
    '<span class="name" title="' + esc(name) + '">' + esc(name) + '</span>' +
    '<span class="bar"><i style="width:' + pct + '%"></i></span>' +
    '<span class="val">' + esc(extra || hb(value)) + '</span></div>';
}

function toast(message, bad) {
  const el = $('#toast');
  el.textContent = message;
  el.className = 'toast' + (bad ? ' bad' : '');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.className = 'toast hidden'; }, 2600);
}

/* ────────────────────────────── state ────────────────────────────── */

const S = {
  tab: 'overview',
  summary: null,
  devices: null,
  detail: null,
  flows: null,
  alerts: null,
  glossary: null,
  filters: { devices: 'all', devq: '', alertSev: 'all', alertKind: '', flowProto: '', flowRemote: false, flowQ: '', glossq: '' },
  openMac: null,
  drawerDirty: false,
  failures: 0,
};

async function api(path, options) {
  const response = await fetch(path, Object.assign({ cache: 'no-store' }, options || {}));
  const text = await response.text();
  if (!response.ok) throw new Error(text.slice(0, 200) || ('HTTP ' + response.status));
  return JSON.parse(text);
}

/* ────────────────────────────── header ────────────────────────────── */

function chip(label, value, dotClass) {
  return '<span class="chip">' + (dotClass ? '<span class="dot ' + dotClass + '"></span>' : '') +
    esc(label) + (value !== undefined ? ' <b>' + esc(value) + '</b>' : '') + '</span>';
}

function renderHeader() {
  const s = S.summary;
  if (!s) return;
  const health = s.health || {};
  const dot = health.state === 'ok' ? 'ok' : (health.state === 'warn' ? 'warn' : (health.state === 'demo' ? 'demo' : 'bad'));
  $('#chips').innerHTML = [
    chip(health.headline || 'unknown', undefined, dot),
    chip('devices', (s.devices.online || 0) + ' of ' + (s.devices.total || 0)),
    chip('interface', s.iface),
    chip('mode', s.mode),
    chip('up', s.uptime_human),
  ].join('');

  const unreviewed = s.devices.review || 0;
  const parts = [];
  parts.push('<b>' + (s.devices.total || 0) + '</b> ' + (s.devices.total === 1 ? 'device' : 'devices') +
    ' — <b>' + (s.devices.online || 0) + '</b> online');
  if (unreviewed) parts.push('<b>' + unreviewed + '</b> never identified');
  parts.push('<b>' + (s.flows || 0) + '</b> ' + t('Flow', 'conversations').replace('class="term"', 'class="term"'));
  if (s.devices.randomized) parts.push('<b>' + s.devices.randomized + '</b> with ' + t('Randomised address', 'randomised addresses'));
  const sentence = parts.join(' · ') + '. ' + (health.detail || '');
  $('#subtitle').innerHTML = sentence;

  const banners = [];
  if (health.state && health.state !== 'ok') {
    const cls = health.state === 'bad' ? 'bad' : (health.state === 'demo' ? 'demo' : 'warn');
    banners.push('<div class="banner ' + cls + '"><h3>' + esc(health.headline) + '</h3>' +
      '<div class="detail">' + esc(health.detail) + '</div>' +
      (health.action ? '<div class="detail">' + esc(health.action) + '</div>' : '') + '</div>');
  }
  if (s.note) banners.push('<div class="banner"><h3>Note</h3><div class="detail">' + esc(s.note) + '</div></div>');
  if (S.failures >= 3) {
    banners.push('<div class="banner bad"><h3>The dashboard cannot reach netwatchd</h3>' +
      '<div class="detail">The last ' + S.failures + ' requests failed. The daemon may have stopped, or this page may be open without a network path to it.</div></div>');
  }
  $('#banner').innerHTML = banners.join('');
}

/* ────────────────────────────── overview ────────────────────────────── */

const OVERVIEW_SHELL = [
  '<div class="cards" id="ov-cards"></div>',
  '<h2>Traffic, last few minutes</h2>',
  '<div id="ov-chart"></div>',
  '<h2>Where it is going</h2><div id="ov-peers"></div>',
  '<h2>Busiest devices</h2><div id="ov-devices" class="rows"></div>',
  '<h2>Last two weeks</h2><div id="ov-history"></div>',
  '<h2>How this is working</h2><div id="ov-help" class="helpbox"></div>',
].join('');

function mountOverview() {
  $('#panel-overview').innerHTML = OVERVIEW_SHELL;
}

function updateOverview() {
  const s = S.summary;
  if (!s) return;
  const health = s.health || {};
  $('#ov-cards').innerHTML = [
    card('Devices online', (s.devices.online || 0) + ' / ' + (s.devices.total || 0), (s.devices.review || 0) + ' never identified'),
    card('Packets', (s.packets || 0).toLocaleString(), (s.packets_per_s || 0) + ' per second now'),
    card('Volume', s.bytes_human || hb(s.bytes), (s.bytes_per_s || 0) + ' bytes per second now'),
    card('Conversations', (s.flows || 0).toLocaleString(), 'between two addresses'),
    card('Dropped by kernel', (s.kernel_dropped || 0).toLocaleString(), (s.kernel_dropped ? 'the picture has holes' : 'nothing lost')),
    card('Alerts kept', (s.alerts.total || 0) + '', (s.alerts.alert || 0) + ' need a look'),
  ].join('');

  const series = s.series || {};
  const bytes = series.bytes || [];
  const step = series.step_s || 5;
  $('#ov-chart').innerHTML = bars(bytes, (v) => hb(v) + ' in ' + step + 's') +
    '<div class="chart-axis"><span>' + dur(bytes.length * step) + ' ago</span><span>now</span></div>' +
    '<div class="legend"><span><i class="swatch" style="background:var(--acc)"></i>bytes per sample (' + step + 's)</span>' +
    '<span>peak ' + esc(hb(Math.max.apply(null, bytes.concat([0])))) + '</span></div>';

  const ports = s.top_ports || [];
  const totalFlows = ports.reduce((sum, p) => sum + (p.flows || 0), 0) || 1;
  $('#ov-peers').innerHTML = ports.length
    ? ports.map((p) => barrow(p.label ? p.label + ' (' + p.port + ')' : 'port ' + p.port, p.flows, totalFlows, p.flows + (p.flows === 1 ? ' conversation' : ' conversations'))).join('')
    : '<div class="empty">Nothing yet. Ports appear as soon as devices start talking.</div>';

  const devices = (s.top_devices || []).filter((d) => d.bytes > 0);
  $('#ov-devices').innerHTML = devices.length
    ? devices.map((d) => '<div class="row" data-mac="' + esc(d.mac) + '" style="cursor:pointer">' +
        '<span class="left">' + spark(d.spark) + ' ' + esc(d.name || 'unnamed device') +
        (d.online ? '' : ' <span class="dim">(offline)</span>') + '</span>' +
        '<span class="right">' + esc(d.bytes_human) + '</span></div>').join('')
    : '<div class="empty">No device has carried traffic yet.</div>';

  $('#ov-help').innerHTML =
    '<b>' + esc(health.headline || '') + '</b>' +
    '<ul>' +
    '<li>Netwatch reads frames that were already passing through this machine. It never sends anything and never ' + t('Scan noise', 'scans your network') + ', so no device is disturbed and nothing is probed.</li>' +
    '<li>Devices are identified by their ' + t('MAC address', 'hardware address') + '. ' + t('Randomised address', 'Phones rotate theirs') + ', so the same phone can appear as a new device each day.</li>' +
    '<li>What it cannot see: ' + t('HTTPS', 'anything inside encrypted traffic') + ', and any name lookup done through ' + t('Encrypted DNS') + '. Most traffic on a modern network is one of those two.</li>' +
    '<li>Every alert is a fact from the wire, never a conclusion. "' + esc('A new address was seen') + '" is a fact; "someone broke in" is not something Netwatch will say.</li>' +
    '</ul>';

  loadHistory();

  $$('#panel-overview .row[data-mac]').forEach((row) => {
    row.addEventListener('click', () => openDevice(row.getAttribute('data-mac')));
  });
}

/** The kept days are read once a minute, not on every refresh. */
async function loadHistory() {
  const host = $('#ov-history');
  if (!host) return;
  if (!S.history || Date.now() - (S.historyAt || 0) > 60000) {
    try {
      S.history = await api('/api/history?days=30');
      S.historyAt = Date.now();
    } catch (error) {
      host.innerHTML = '<div class="empty">The kept history could not be read.</div>';
      return;
    }
  }
  paintHistory();
}

function paintHistory() {
  const host = $('#ov-history');
  const h = S.history;
  if (!host || !h) return;
  const days = h.network || [];
  if (h.off || !days.length) {
    host.innerHTML = '<div class="empty">Nothing kept yet. A day appears here once Netwatch has watched one.</div>';
    return;
  }
  const shown = days.slice(-30);
  const total = shown.reduce((sum, d) => sum + (d.total || 0), 0);
  const top = (h.uptime || [])[0];
  host.innerHTML =
    bars(shown.map((d) => d.total || 0), (v) => hb(v)) +
    '<div class="chart-axis"><span>' + esc(shown[0].date) + '</span><span>' + esc(shown[shown.length - 1].date) + '</span></div>' +
    '<div class="legend"><span>' + esc(hb(total)) + ' over ' + shown.length + ' kept day' + (shown.length === 1 ? '' : 's') + '</span>' +
    '<span>' + esc(h.file_human) + ' on disk · keeping ' + esc(String(h.keep_days)) + ' days</span></div>' +
    (top
      ? '<p style="font-size:13px;margin-top:10px">Steadiest device: <b>' + esc(top.name || top.mac) + '</b> — online ' +
        esc(top.online_human) + ' across the ' + esc(String(top.days_seen)) + ' day' + (top.days_seen === 1 ? '' : 's') + ' it was seen (' +
        esc(String(top.uptime_pct)) + '%).</p>'
      : '');
}

function card(key, value, sub) {
  return '<div class="card"><div class="k">' + esc(key) + '</div>' +
    '<div class="v">' + esc(value) + '</div>' + (sub ? '<div class="s">' + esc(sub) + '</div>' : '') + '</div>';
}

/* ────────────────────────────── devices ────────────────────────────── */

const DEVICE_FILTERS = [
  ['all', 'All'], ['online', 'Online'], ['offline', 'Offline'],
  ['review', 'Never identified'], ['rand', 'Randomised'], ['named', 'Named'], ['ignored', 'Muted'],
];

const DEVICES_SHELL =
  '<div class="toolbar">' +
    '<input type="search" id="dev-search" placeholder="Search name, address, maker, port…" autocomplete="off">' +
    '<div class="filters" id="dev-filters">' +
      DEVICE_FILTERS.map((f) => '<button class="fchip" data-devf="' + f[0] + '">' + f[1] + '</button>').join('') +
    '</div>' +
  '</div>' +
  '<div id="dev-review"></div>' +
  '<div id="dev-list"></div>';

function mountDevices() {
  $('#panel-devices').innerHTML = DEVICES_SHELL;
  $$('#dev-filters .fchip').forEach((btn) => {
    btn.addEventListener('click', () => {
      S.filters.devices = btn.getAttribute('data-devf');
      updateDevices();
    });
  });
  $('#dev-search').addEventListener('input', (event) => {
    S.filters.devq = event.target.value.trim().toLowerCase();
    updateDevices();
  });
}

function filterDevices(list) {
  const f = S.filters.devices;
  const q = S.filters.devq;
  const now = Date.now() / 1000;
  return list.filter((d) => {
    if (f === 'online' && !d.online) return false;
    if (f === 'offline' && d.online) return false;
    if (f === 'review' && d.trust !== 'unknown') return false;
    if (f === 'rand' && !d.randomized) return false;
    if (f === 'named' && !d.name) return false;
    if (f === 'ignored' && d.trust !== 'ignored') return false;
    if (q) {
      const hay = [d.display_name, d.name, d.auto_name, d.vendor, d.ip, d.mac, d.kind, (d.ports || []).join(' '), (d.domains || []).join(' ')]
        .filter(Boolean).join(' ').toLowerCase();
      if (hay.indexOf(q) === -1) return false;
    }
    if (now < 0) return true;
    return true;
  });
}

function deviceBadges(d) {
  const out = [];
  if (!d.name && !d.auto_name && !d.vendor) out.push('<span class="badge new">unnamed</span>');
  if (d.trust === 'unknown') out.push('<span class="badge new">never identified</span>');
  if (d.trust === 'trusted') out.push('<span class="badge trusted">trusted</span>');
  if (d.trust === 'ignored') out.push('<span class="badge ignored">muted</span>');
  if (d.randomized) out.push('<span class="badge rand">' + t('Randomised address', 'randomised address') + '</span>');
  if (d.kind_source === 'guess') out.push('<span class="badge guess">' + esc(d.kind_guess_label || d.kind_guess) + ' (guess)</span>');
  else if (d.kind) out.push('<span class="badge">' + esc(d.kind) + '</span>');
  if ((d.ips || []).length > 1) out.push('<span class="badge">' + d.ips.length + ' addresses</span>');
  return '<div class="badges">' + out.join('') + '</div>';
}

function updateDevices() {
  const data = S.devices;
  if (!data) return;
  $$('#dev-filters .fchip').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-devf') === S.filters.devices);
  });

  const counts = data.counts || {};
  const review = data.devices.filter((d) => d.trust === 'unknown');
  $('#dev-review').innerHTML = (review.length && S.filters.devices !== 'review')
    ? '<div class="callout"><b>' + review.length + ' device' + (review.length === 1 ? '' : 's') +
      ' nobody has identified yet.</b> Look at each one and say whether you recognise it — ' +
      '"I do not know that one" is the most useful answer this page can give you.' +
      '<div><button data-devf="review">Show the unreviewed devices</button></div></div>'
    : '';

  const visible = filterDevices(data.devices);
  $('#dev-list').innerHTML = visible.length
    ? visible.map((d) => {
        const last = d.online ? 'online now' : 'last seen ' + ago(d.last_seen);
        const meta = [d.vendor || (d.randomized ? 'no maker (randomised)' : 'maker unknown'),
          d.ip || 'no address', d.kind_source === 'you' ? d.kind : (d.kind_guess_label || 'unidentified'), last].join(' · ');
        return '<button class="devrow" data-mac="' + esc(d.mac) + '">' +
          '<span class="dot ' + (d.online ? 'ok' : '') + '"></span>' +
          '<span class="dev-main"><span class="devname">' + esc(d.display_name || 'unnamed device') + '</span>' +
          '<span class="devmeta">' + esc(meta) + '</span>' + deviceBadges(d) + '</span>' +
          '<span class="dev-tail">' + spark(d.spark) +
          '<span class="dev-traffic">' + esc(d.bytes_human) + '</span>' +
          '<span class="devmeta">' + (d.remote_peers || 0) + ' remote, ' + (d.ports || []).length + ' ports</span>' +
          '</span></button>';
      }).join('')
    : '<div class="empty">Nothing matches. ' + (data.devices.length ? 'Clear the search or pick another filter.' : 'No devices have been learned yet — this fills within seconds on a busy network.') + '</div>';

  $$('#dev-list .devrow').forEach((row) => {
    row.addEventListener('click', () => openDevice(row.getAttribute('data-mac')));
  });
  $$('#dev-review [data-devf]').forEach((btn) => {
    btn.addEventListener('click', () => { S.filters.devices = 'review'; updateDevices(); });
  });
}

/* ────────────────────────────── device detail ────────────────────────────── */

async function openDevice(mac) {
  S.openMac = mac;
  S.drawerDirty = false;
  try {
    S.detail = await api('/api/devices/' + encodeURIComponent(mac));
  } catch (error) {
    toast('Could not load that device', true);
    return;
  }
  renderDrawerDevice();
}

function renderDrawerDevice() {
  const d = S.detail;
  if (!d) return;
  const drawer = $('#drawer');
  drawer.classList.remove('hidden');
  drawer.setAttribute('aria-hidden', 'false');

  const identity =
    '<div class="section"><h3>Your decision about this device</h3>' +
    '<div class="field"><label for="ed-name">Name — what you call it</label>' +
    '<input type="text" id="ed-name" maxlength="48" value="' + esc(d.name || '') + '" placeholder="' + esc(d.auto_name || 'e.g. Living room TV') + '"></div>' +
    '<div class="field"><label for="ed-kind">What it is</label><select id="ed-kind">' +
      '<option value="">not decided</option>' +
      (S.devices ? S.devices.kinds : []).map((k) =>
        '<option value="' + esc(k.value) + '"' + (d.kind === k.value ? ' selected' : '') + '>' + esc(k.label) + '</option>').join('') +
    '</select></div>' +
    '<div class="field"><label for="ed-trust">How you think of it</label><select id="ed-trust">' +
      ['unknown', 'known', 'trusted', 'ignored'].map((v) =>
        '<option value="' + v + '"' + (d.trust === v ? ' selected' : '') + '>' + v + ' — ' + esc(trustNote(v)) + '</option>').join('') +
    '</select></div>' +
    '<div class="field"><label for="ed-notify">When Netwatch should interrupt you about it</label><select id="ed-notify">' +
      NOTIFY.map((o) =>
        '<option value="' + o[0] + '"' + ((d.notify || 'default') === o[0] ? ' selected' : '') + '>' + o[0] + ' — ' + esc(o[1]) + '</option>').join('') +
    '</select></div>' +
    '<div class="field"><label for="ed-quota">Daily traffic budget, in gigabytes</label>' +
    '<input type="text" inputmode="decimal" id="ed-quota" maxlength="8" value="' + esc(d.quota_text || '') + '" placeholder="blank for none, e.g. 5 or 2.5"></div>' +
    '<div class="field"><label for="ed-notes">Notes</label>' +
    '<textarea id="ed-notes" maxlength="280" placeholder="Anything you want to remember about it">' + esc(d.notes || '') + '</textarea></div>' +
    '<div class="actions"><button class="btn primary" id="ed-save">Save</button>' +
    '<button class="btn" data-quick="trusted">Mark trusted</button>' +
    '<button class="btn" data-quick="ignored">Mute it</button></div></div>';

  const facts =
    '<div class="section"><h3>What is known</h3><dl class="kv">' +
    kv('Hardware address', '<span class="mono">' + esc(d.mac) + '</span>') +
    kv('Maker', d.vendor ? esc(d.vendor) : (d.randomized ? 'none — this is a ' + t('Randomised address', 'randomised address') : 'not in the registry')) +
    kv('Addresses', esc((d.ips || []).join(', ')) || 'none') +
    kv('First seen', esc(when(d.first_seen)) + ' <span class="dim">(' + esc(ago(d.first_seen)) + ')</span>') +
    kv('Last seen', esc(when(d.last_seen)) + ' <span class="dim">(' + esc(ago(d.last_seen)) + ')</span>') +
    kv('Status', d.online ? 'online now' : ('offline' + (d.offline_for_s ? ' for ' + esc(dur(d.offline_for_s)) : ''))) +
    kv('Sessions', String(d.sessions || 0)) +
    kv('Traffic', esc(hb(d.bytes)) + ' in ' + (d.packets || 0).toLocaleString() + ' packets') +
    kv('Direction', 'sent ' + esc(hb(d.up_bytes)) + ' · received ' + esc(hb(d.down_bytes))) +
    '</dl>' +
    '<h3 style="margin-top:14px">Last hour</h3>' + bars(d.spark, (v) => hb(v) + ' in that minute') +
    '</div>';

  const hints = (d.hints && d.hints.length)
    ? '<div class="section"><h3>What this means</h3><ul class="hintlist">' +
      d.hints.map((h) => '<li>' + esc(h) + '</li>').join('') + '</ul></div>'
    : '';

  const peers = (d.peer_list && d.peer_list.length)
    ? '<div class="section"><h3>Who it talks to</h3><table class="plain"><tr><th>Remote end</th><th>Name</th><th class="n">Traffic</th></tr>' +
      d.peer_list.map((p) => '<tr><td class="mono">' + esc(p.ip) + '</td><td>' + esc(p.local ? 'on this network' : p.name) +
        '</td><td class="n">' + esc(p.bytes_human) + '</td></tr>').join('') + '</table></div>'
    : '';

  const ports = (d.port_list && d.port_list.length)
    ? '<div class="section"><h3>Ports it used</h3><table class="plain"><tr><th>Port</th><th>Service</th><th class="n">Traffic</th></tr>' +
      d.port_list.map((p) => '<tr><td class="mono">' + esc(p.port) + '</td><td>' + (p.label ? esc(p.label) : '<span class="dim">well-known: none</span>') +
        '</td><td class="n">' + esc(p.bytes_human) + '</td></tr>').join('') + '</table></div>'
    : '';

  const domains = (d.domain_list && d.domain_list.length)
    ? '<div class="section"><h3>Names it asked for</h3><p class="dim" style="font-size:12.5px">Read from plain text name lookups only. A device using ' + t('Encrypted DNS') + ' shows nothing here.</p>' +
      '<table class="plain">' + d.domain_list.map((x) => '<tr><td>' + esc(x.name) + '</td><td class="n">' + x.count + '×</td></tr>').join('') + '</table></div>'
    : '';

  const timeline = (d.timeline && d.timeline.length)
    ? '<div class="section"><h3>When it is on</h3><div class="timeline">' +
      d.timeline.slice(0, 24).reverse().map((x) =>
        '<span class="sp' + (x.ongoing ? ' now' : '') + '" title="' + esc(when(x.start) + ' → ' + (x.ongoing ? 'now' : when(x.end))) + '"></span>').join('') +
      '</div><div class="legend"><span>older → newer, each bar is one ' + t('Session', 'session') + '</span></div></div>'
    : '';

  const alerts = (d.alert_history && d.alert_history.length)
    ? '<div class="section"><h3>What was reported about it</h3>' +
      d.alert_history.map((a) => '<div class="alert ' + esc(a.severity) + '-sev" style="border-left-color:var(--line-2)">' +
        '<div class="head"><span class="who">' + esc(a.kind) + (a.muted ? ' <span class="tag quiet">kept quiet</span>' : '') + '</span><span class="when">' + esc(when(a.ts)) + '</span></div>' +
        '<div class="detail">' + esc(a.detail) + '</div></div>').join('') + '</div>'
    : '';

  const budget = d.quota_bytes
    ? '<div class="section"><h3>Today against your budget</h3>' +
      '<div class="meter ' + esc(d.quota_state) + '"><span style="width:' + Math.min(100, d.quota_pct || 0) + '%"></span></div>' +
      '<p style="font-size:13px">' + esc(d.today_human) + ' of ' + esc(d.quota_text) + ' GB used — ' +
      (d.quota_state === 'over' ? 'over budget' : (d.quota_pct || 0) + '% of it') +
      '. Counted from midnight UTC, and it resets there.</p></div>'
    : '';

  const history = (d.history && d.history.days && d.history.days.length)
    ? '<div class="section"><h3>Kept history</h3>' +
      '<p class="dim" style="font-size:12.5px">' + d.history.seen_days + ' day' + (d.history.seen_days === 1 ? '' : 's') + ' recorded, online for ' +
      esc(d.history.online_human) + ' of it (' + d.history.uptime_pct + '% of the days it was seen). ' +
      (d.history.sessions_recorded ? esc(String(d.history.sessions_recorded)) + ' sessions recorded.' : '') + '</p>' +
      '<table class="plain"><tr><th>Day</th><th class="n">Received</th><th class="n">Sent</th><th class="n">Online</th><th class="n">Sessions</th></tr>' +
      d.history.days.slice(-14).reverse().map((x) =>
        '<tr><td class="mono">' + esc(x.date) + '</td><td class="n">' + esc(hb(x.down)) + '</td><td class="n">' + esc(hb(x.up)) +
        '</td><td class="n">' + esc(dur(x.online_secs)) + '</td><td class="n">' + x.sessions + '</td></tr>').join('') +
      '</table></div>'
    : '';

  const duplicate = d.duplicate_of
    ? '<div class="section"><h3>Possibly the same device</h3><p style="font-size:13px">' +
      esc(d.duplicate_of.name || d.duplicate_of.mac) + ' — ' + esc(d.duplicate_of.reason) + '</p></div>'
    : '';

  drawer.innerHTML =
    '<div class="drawer-head"><h2>' + esc(d.display_name || 'unnamed device') + '</h2>' +
    '<button class="ghost" id="drawer-close" title="Close">✕</button></div>' +
    '<div class="badges">' + (deviceBadges(d).replace(/^<div class="badges">|<\/div>$/g, '')) + '</div>' +
    duplicate + budget + identity + hints + history + peers + ports + domains + timeline + alerts;

  $('#drawer-close').addEventListener('click', closeDrawer);
  ['#ed-name', '#ed-kind', '#ed-trust', '#ed-notes', '#ed-notify', '#ed-quota'].forEach((sel) => {
    $(sel).addEventListener('input', () => { S.drawerDirty = true; });
    $(sel).addEventListener('change', () => { S.drawerDirty = true; });
  });
  $('#ed-save').addEventListener('click', () => saveDevice());
  $$('#drawer [data-quick]').forEach((btn) => btn.addEventListener('click', () => {
    const mac = S.openMac;
    const trust = btn.getAttribute('data-quick');
    if (!mac) return;
    api('/api/devices/' + encodeURIComponent(mac), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ trust: trust }),
    }).then((updated) => {
      S.detail = updated;
      S.drawerDirty = false;
      renderDrawerDevice();
      toast(trust === 'ignored' ? 'Muted — Netwatch will say nothing about it' : 'Marked trusted');
      reloadCurrentTab();
    }).catch(() => toast('Could not save that change', true));
  }));
}

/* The per-device notification rules, in the operator's own words. */
const NOTIFY = [
  ['default', 'tell me about everything here'],
  ['quiet', 'only things that need action'],
  ['never', 'nothing — keep it in the dashboard only'],
];

function trustNote(value) {
  const notes = {
    unknown: 'nobody has looked at it yet',
    known: 'I recognise this device',
    trusted: 'expected here, alerts are informational',
    ignored: 'muted, no alerts at all',
  };
  return notes[value] || '';
}

function kv(key, value) {
  return '<dt>' + esc(key) + '</dt><dd>' + value + '</dd>';
}

function saveDevice() {
  const mac = S.openMac;
  if (!mac) return;
  const body = {
    name: $('#ed-name').value.trim(),
    kind: $('#ed-kind').value,
    trust: $('#ed-trust').value,
    notes: $('#ed-notes').value,
    notify: $('#ed-notify').value,
    quota_gb: $('#ed-quota').value.trim(),
  };
  api('/api/devices/' + encodeURIComponent(mac), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then((updated) => {
    S.detail = updated;
    S.drawerDirty = false;
    renderDrawerDevice();
    toast('Saved');
    reloadCurrentTab();
  }).catch((error) => toast('Could not save: ' + error.message, true));
}

function closeDrawer() {
  S.openMac = null;
  S.detail = null;
  S.drawerDirty = false;
  $('#drawer').classList.add('hidden');
  $('#drawer').setAttribute('aria-hidden', 'true');
  $('#drawer').innerHTML = '';
}

/* ────────────────────────────── traffic ────────────────────────────── */

const TRAFFIC_SHELL =
  '<div class="toolbar">' +
    '<input type="search" id="flow-search" placeholder="Search address, name, service, device…" autocomplete="off">' +
    '<div class="filters" id="flow-filters">' +
      ['all', 'TCP', 'UDP', 'other'].map((p) => '<button class="fchip" data-proto="' + p + '">' + (p === 'all' ? 'All' : p) + '</button>').join('') +
      '<button class="fchip" data-remote="1">Remote only</button>' +
    '</div>' +
  '</div>' +
  '<div class="legend"><span>up is what left the device, down is what arrived ' + t('Flow', 'what is a conversation?') + '</span></div>' +
  '<div id="flow-list" style="margin-top:10px"></div>';

function mountTraffic() {
  $('#panel-traffic').innerHTML = TRAFFIC_SHELL;
  $$('#flow-filters .fchip').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (btn.hasAttribute('data-remote')) S.filters.flowRemote = !S.filters.flowRemote;
      else S.filters.flowProto = btn.getAttribute('data-proto') === 'all' ? '' : btn.getAttribute('data-proto');
      updateTraffic();
    });
  });
  let timer = null;
  $('#flow-search').addEventListener('input', (event) => {
    S.filters.flowQ = event.target.value.trim();
    clearTimeout(timer);
    timer = setTimeout(() => loadTraffic().then(updateTraffic), 220);
  });
}

function updateTraffic() {
  $$('#flow-filters .fchip').forEach((btn) => {
    if (btn.hasAttribute('data-remote')) btn.classList.toggle('active', S.filters.flowRemote);
    else {
      const value = btn.getAttribute('data-proto') === 'all' ? '' : btn.getAttribute('data-proto');
      btn.classList.toggle('active', value === S.filters.flowProto);
    }
  });
  const data = S.flows;
  if (!data) return;
  let flows = data.flows || [];
  if (S.filters.flowRemote) flows = flows.filter((f) => f.remote);
  $('#flow-list').innerHTML = flows.length
    ? flows.map((f) => '<div class="row">' +
        '<span class="left">' + t(f.proto, f.proto) + ' ' +
        (f.owner_name ? '<b>' + esc(f.owner_name) + '</b> ' : '') +
        '→ ' + esc(f.peer_name || f.peer_ip) +
        (f.service ? ' <span class="dim">(' + esc(f.service) + ')</span>' : '') +
        (f.remote ? '' : ' <span class="dim">on this network</span>') + '</span>' +
        '<span class="right">' + esc(f.bytes_human) + ' <span class="dim">↑' + esc(hb(f.up_bytes)) + ' ↓' + esc(hb(f.down_bytes)) + '</span></span>' +
        '</div>').join('')
    : '<div class="empty">' + (data.total_flows ? 'No conversation matches that search.' : 'No conversations yet.') + '</div>';
  $$('#flow-list [data-term]').forEach((el) => el.addEventListener('click', (event) => {
    event.stopPropagation();
    openTerm(el.getAttribute('data-term'));
  }));
}

async function loadTraffic() {
  const params = new URLSearchParams();
  if (S.filters.flowQ) params.set('q', S.filters.flowQ);
  if (S.filters.flowProto) params.set('proto', S.filters.flowProto);
  params.set('limit', '80');
  S.flows = await api('/api/flows?' + params.toString());
}

/* ────────────────────────────── alerts ────────────────────────────── */

const ALERTS_SHELL =
  '<div class="toolbar"><div class="filters" id="alert-filters">' +
    [['all', 'Everything'], ['alert', 'Needs a look'], ['notable', 'Worth knowing'], ['info', 'Background']]
      .map((s) => '<button class="fchip" data-sev="' + s[0] + '">' + s[1] + '</button>').join('') +
  '</div><select id="alert-kind"><option value="">every kind</option></select></div>' +
  '<div id="alert-list"></div>';

function mountAlerts() {
  $('#panel-alerts').innerHTML = ALERTS_SHELL;
  $$('#alert-filters .fchip').forEach((btn) => {
    btn.addEventListener('click', () => { S.filters.alertSev = btn.getAttribute('data-sev'); updateAlerts(); });
  });
  $('#alert-kind').addEventListener('change', (event) => {
    S.filters.alertKind = event.target.value;
    updateAlerts();
  });
}

function updateAlerts() {
  const data = S.alerts;
  if (!data) return;
  const kinds = data.kinds || [];
  const select = $('#alert-kind');
  if (select.options.length <= 1) {
    kinds.forEach((k) => {
      const option = document.createElement('option');
      option.value = k.kind;
      option.textContent = k.kind.replace(/_/g, ' ');
      select.appendChild(option);
    });
  }
  select.value = S.filters.alertKind;

  $$('#alert-filters .fchip').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-sev') === S.filters.alertSev);
  });

  const why = {};
  kinds.forEach((k) => { why[k.kind] = k.why; });

  let list = data.alerts || [];
  if (S.filters.alertSev !== 'all') list = list.filter((a) => a.severity === S.filters.alertSev);
  if (S.filters.alertKind) list = list.filter((a) => a.kind === S.filters.alertKind);

  const counts = data.counts || {};
  $('#alert-list').innerHTML =
    '<div class="legend"><span>' + (counts.alert || 0) + ' need a look · ' + (counts.notable || 0) + ' worth knowing · ' + (counts.info || 0) + ' background</span></div>' +
    (list.length ? list.map((a) => {
      const who = a.name ? esc(a.name) : (a.subject || 'netwatch');
      return '<div class="alert ' + esc(a.severity) + '">' +
        '<div class="head"><span class="who"' + (a.mac ? ' data-mac="' + esc(a.mac) + '" style="cursor:pointer"' : '') + '>' + who + '</span>' +
        (a.muted ? '<span class="tag quiet">kept quiet</span>' : '') +
        '<span class="when" title="' + esc(when(a.ts)) + '">' + esc(ago(a.ts)) + '</span></div>' +
        '<div class="kind">' + esc(a.kind.replace(/_/g, ' ')) + (a.address ? ' · ' + esc(a.address) : '') + '</div>' +
        '<div class="detail">' + esc(a.detail) + '</div>' +
        '<details><summary>Why did this fire?</summary><div class="why">' + esc(a.why || why[a.kind] || '') + '</div></details>' +
        '</div>';
    }).join('')
    : '<div class="empty">Nothing matches. Alerts appear here the moment something happens, and a quiet dashboard is a good sign.</div>');

  $$('#alert-list [data-mac]').forEach((el) => el.addEventListener('click', () => openDevice(el.getAttribute('data-mac'))));
}

/* ────────────────────────────── glossary ────────────────────────────── */

function mountGlossary() {
  $('#panel-glossary').innerHTML =
    '<div class="toolbar"><input type="search" id="gloss-search" placeholder="Search the glossary — MAC, flow, DHCP, flapping…" autocomplete="off"></div>' +
    '<div class="helpbox">Every word netwatch uses, in plain language. Nothing here is a definition for its own sake: each entry says what the thing is and why it matters here. ' +
    'You can also click any ' + t('Alert', 'dotted term') + ' anywhere on the page.</div>' +
    '<div id="gloss-list" style="margin-top:10px"></div>';
  $('#gloss-search').addEventListener('input', (event) => {
    S.filters.glossq = event.target.value.trim().toLowerCase();
    updateGlossary();
  });
  updateGlossary();
}

function updateGlossary() {
  const terms = (S.glossary && S.glossary.terms) || [];
  const q = S.filters.glossq;
  const list = q
    ? terms.filter((x) => (x.term + ' ' + x.short + ' ' + x.body + ' ' + (x.see || []).join(' ')).toLowerCase().indexOf(q) !== -1)
    : terms;
  $('#gloss-list').innerHTML = list.length
    ? list.map((x) => '<div class="glossitem" id="gloss-' + esc(x.term.replace(/\s+/g, '-')) + '">' +
        '<h3>' + esc(x.term) + '</h3><div class="short">' + esc(x.short) + '</div>' +
        '<div class="body">' + esc(x.body) + '</div>' +
        ((x.see || []).length ? '<div class="see">See also ' + x.see.map((s) => t(s)).join('') + '</div>' : '') +
        '</div>').join('')
    : '<div class="empty">No term matches "' + esc(q) + '".</div>';
}

/** Open a glossary entry in the drawer, without losing the page underneath. */
function openTerm(term) {
  const terms = (S.glossary && S.glossary.terms) || [];
  const found = terms.filter((x) => x.term.toLowerCase() === String(term).toLowerCase())[0];
  const drawer = $('#drawer');
  S.openMac = null;
  S.detail = null;
  drawer.classList.remove('hidden');
  drawer.setAttribute('aria-hidden', 'false');
  if (!found) {
    drawer.innerHTML = '<div class="drawer-head"><h2>' + esc(term) + '</h2><button class="ghost" id="drawer-close">✕</button></div>' +
      '<div class="empty">No glossary entry for that term yet.</div>';
  } else {
    drawer.innerHTML = '<div class="drawer-head"><h2>' + esc(found.term) + '</h2><button class="ghost" id="drawer-close">✕</button></div>' +
      '<div class="glossitem" style="border:0"><div class="short">' + esc(found.short) + '</div>' +
      '<div class="body" style="font-size:13.5px">' + esc(found.body) + '</div>' +
      ((found.see || []).length ? '<div class="see">See also ' + found.see.map((s) => t(s)).join('') + '</div>' : '') +
      '</div>';
  }
  $('#drawer-close').addEventListener('click', closeDrawer);
  $$('#drawer [data-term]').forEach((el) => el.addEventListener('click', () => openTerm(el.getAttribute('data-term'))));
}

/* ────────────────────────────── tabs and polling ────────────────────────────── */

function showTab(name) {
  S.tab = name;
  $$('#tabs .tab').forEach((btn) => btn.classList.toggle('active', btn.getAttribute('data-tab') === name));
  ['overview', 'devices', 'traffic', 'alerts', 'glossary'].forEach((tab) => {
    $('#panel-' + tab).classList.toggle('hidden', tab !== name);
  });
  if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
  reloadCurrentTab();
}

async function reloadCurrentTab() {
  try {
    if (S.tab === 'devices') {
      S.devices = await api('/api/devices');
      updateDevices();
    } else if (S.tab === 'traffic') {
      await loadTraffic();
      updateTraffic();
    } else if (S.tab === 'alerts') {
      S.alerts = await api('/api/alerts?limit=150');
      updateAlerts();
    } else if (S.tab === 'glossary' && !S.glossary) {
      S.glossary = await api('/api/glossary');
      updateGlossary();
    }
  } catch (error) {
    S.failures += 1;
    renderHeader();
  }
}

async function tick() {
  if (document.hidden) return;
  try {
    S.summary = await api('/api/summary');
    S.failures = 0;
  } catch (error) {
    S.failures += 1;
    renderHeader();
    return;
  }
  renderHeader();
  if (S.tab === 'overview') updateOverview();
  if (S.openMac && S.detail && !S.drawerDirty) {
    api('/api/devices/' + encodeURIComponent(S.openMac)).then((d) => {
      S.detail = d;
      renderDrawerDevice();
    }).catch(() => {});
  }
}

function init() {
  mountOverview();
  mountDevices();
  mountTraffic();
  mountAlerts();
  mountGlossary();

  $$('#tabs .tab').forEach((btn) => btn.addEventListener('click', () => showTab(btn.getAttribute('data-tab'))));
  $('#helpBtn').addEventListener('click', () => { showTab('glossary'); $('#gloss-search').focus(); });
  document.addEventListener('click', (event) => {
    const el = event.target.closest('[data-term]');
    if (el && !el.closest('#drawer')) {
      event.preventDefault();
      openTerm(el.getAttribute('data-term'));
    }
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
  });

  api('/api/glossary').then((g) => { S.glossary = g; updateGlossary(); }).catch(() => {});

  tick();
  setInterval(tick, 3000);
  setInterval(() => { if (!document.hidden) reloadCurrentTab(); }, 7000);

  const hash = (location.hash || '').replace('#', '');
  if (['overview', 'devices', 'traffic', 'alerts', 'glossary'].indexOf(hash) !== -1) showTab(hash);
}

document.addEventListener('DOMContentLoaded', init);
