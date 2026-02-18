const I18N = {
  fa: {
    'doc.title': 'پنل NoDelay',
    'app.title': '🚀 پنل NoDelay',
    'app.subtitle': 'مانیتورینگ منابع، وضعیت تونل‌ها و مدیریت سرویس‌ها',
    'app.lang': '🌐 زبان',
    'btn.refresh': '🔄 بروزرسانی',
    'btn.create_tunnel': '➕ ساخت تونل',
    'btn.load_logs': '📥 بارگذاری',
    'btn.cancel': 'لغو',
    'btn.create_apply': '✅ ایجاد / اعمال',
    'btn.save': '💾 ذخیره',
    'resources.title': '📊 منابع سرور',
    'resources.cpu': '🧠 CPU',
    'resources.mem': '🧮 حافظه',
    'resources.disk': '💾 دیسک',
    'resources.load': '⚖️ Load',
    'resources.uptime': '⏱️ آپ‌تایم',
    'resources.net': '📡 ترافیک میزبان',
    'tunnels.title': '🛣️ تونل‌ها',
    'table.service': 'سرویس',
    'table.role': 'نقش',
    'table.status': 'وضعیت',
    'table.profile_mode': 'پروفایل / مود',
    'table.endpoints': 'اندپوینت‌ها',
    'table.throughput': 'نرخ عبور',
    'table.actions': 'اقدامات',
    'logs.title': '📜 لاگ‌ها',
    'logs.hint': 'یک تونل انتخاب کنید و لاگ را بارگذاری کنید.',
    'create.title': '🧩 ساخت تونل',
    'edit.title': '📝 ویرایش کانفیگ',
    'edit.restart': 'ری‌استارت سرویس بعد از ذخیره',
    'role.server': 'سرور',
    'role.client': 'کلاینت',
    'form.role': 'نقش',
    'form.instance': 'اینستنس',
    'form.tunnel_mode': 'مود تونل',
    'form.profile': 'پروفایل',
    'form.transport': 'ترنسپورت',
    'form.port': 'پورت',
    'form.server_addr': 'آدرس سرور (کلاینت)',
    'form.listen_host': 'Listen Host (سرور)',
    'form.path': 'مسیر',
    'form.psk': 'PSK',
    'form.pool_size': 'Pool Size (کلاینت)',
    'form.strategy': 'استراتژی (کلاینت)',
    'form.mux': 'Mux',
    'form.advanced_yaml': 'YAML پیشرفته (اختیاری)',
    'ph.instance': 'default',
    'ph.server_addr': '1.2.3.4',
    'ph.listen_host': 'empty = all interfaces',
    'ph.psk': 'optional',
    'ph.advanced_yaml': 'اگر مقدار داشته باشد، همان YAML مستقیم ذخیره می‌شود.',
    'updated.prefix': '⏰ بروزرسانی',
    'table.no_tunnels': 'هیچ سرویس تونلی پیدا نشد.',
    'thr.down': 'دانلود',
    'thr.up': 'آپلود',
    'thr.total': 'حجم کل',
    'action.start': 'شروع',
    'action.stop': 'توقف',
    'action.restart': 'ری‌استارت',
    'action.edit': 'ویرایش',
    'action.delete': 'حذف',
    'logs.select_error': 'برای لاگ، تونل انتخاب نشده است.',
    'logs.no_output': '(خروجی لاگی وجود ندارد)',
    'editor.empty': 'YAML کانفیگ نمی‌تواند خالی باشد.',
    'toast.created': 'تونل ایجاد/بروزرسانی شد',
    'toast.saved': 'ذخیره شد: {{service}}',
    'toast.deleted': 'حذف شد: {{service}}',
    'toast.action': '{{service}}: {{action}} ارسال شد',
    'confirm.delete': 'سرویس {{service}} و کانفیگ آن حذف شود؟',
    'status.unknown': 'نامشخص',
    'time.day': 'روز',
    'time.hour': 'ساعت',
    'time.min': 'دقیقه',
  },
  en: {
    'doc.title': 'NoDelay Web Panel',
    'app.title': '🚀 NoDelay Web Panel',
    'app.subtitle': 'Monitor resources, tunnel status, throughput, and manage instances',
    'app.lang': '🌐 Language',
    'btn.refresh': '🔄 Refresh',
    'btn.create_tunnel': '➕ Create Tunnel',
    'btn.load_logs': '📥 Load',
    'btn.cancel': 'Cancel',
    'btn.create_apply': '✅ Create / Apply',
    'btn.save': '💾 Save',
    'resources.title': '📊 Server Resources',
    'resources.cpu': '🧠 CPU',
    'resources.mem': '🧮 Memory',
    'resources.disk': '💾 Disk',
    'resources.load': '⚖️ Load',
    'resources.uptime': '⏱️ Uptime',
    'resources.net': '📡 Host Throughput',
    'tunnels.title': '🛣️ Tunnels',
    'table.service': 'Service',
    'table.role': 'Role',
    'table.status': 'Status',
    'table.profile_mode': 'Profile / Mode',
    'table.endpoints': 'Endpoints',
    'table.throughput': 'Throughput',
    'table.actions': 'Actions',
    'logs.title': '📜 Logs',
    'logs.hint': 'Select a tunnel and load logs.',
    'create.title': '🧩 Create Tunnel',
    'edit.title': '📝 Edit Config',
    'edit.restart': 'Restart service after save',
    'role.server': 'Server',
    'role.client': 'Client',
    'form.role': 'Role',
    'form.instance': 'Instance',
    'form.tunnel_mode': 'Tunnel Mode',
    'form.profile': 'Profile',
    'form.transport': 'Transport',
    'form.port': 'Port',
    'form.server_addr': 'Server Addr (client)',
    'form.listen_host': 'Listen Host (server)',
    'form.path': 'Path',
    'form.psk': 'PSK',
    'form.pool_size': 'Pool Size (client)',
    'form.strategy': 'Strategy (client)',
    'form.mux': 'Mux',
    'form.advanced_yaml': 'Advanced YAML override (optional)',
    'ph.instance': 'default',
    'ph.server_addr': '1.2.3.4',
    'ph.listen_host': 'empty = all interfaces',
    'ph.psk': 'optional',
    'ph.advanced_yaml': 'If set, this YAML is written directly.',
    'updated.prefix': '⏰ Updated',
    'table.no_tunnels': 'No tunnel services found.',
    'thr.down': 'Down',
    'thr.up': 'Up',
    'thr.total': 'Total',
    'action.start': 'Start',
    'action.stop': 'Stop',
    'action.restart': 'Restart',
    'action.edit': 'Edit',
    'action.delete': 'Delete',
    'logs.select_error': 'No tunnel selected for logs',
    'logs.no_output': '(no log output)',
    'editor.empty': 'Config YAML cannot be empty',
    'toast.created': 'Tunnel created/updated',
    'toast.saved': 'Saved: {{service}}',
    'toast.deleted': 'Deleted: {{service}}',
    'toast.action': '{{service}}: {{action}} requested',
    'confirm.delete': 'Delete {{service}}.service and its config?',
    'status.unknown': 'unknown',
    'time.day': 'd',
    'time.hour': 'h',
    'time.min': 'm',
  },
};

const state = {
  tunnels: [],
  editService: null,
  refreshTimer: null,
  lang: 'fa',
};

const els = {
  cpuVal: document.getElementById('cpuVal'),
  memVal: document.getElementById('memVal'),
  diskVal: document.getElementById('diskVal'),
  loadVal: document.getElementById('loadVal'),
  uptimeVal: document.getElementById('uptimeVal'),
  hostNetVal: document.getElementById('hostNetVal'),
  tunnelRows: document.getElementById('tunnelRows'),
  logService: document.getElementById('logService'),
  logsBox: document.getElementById('logsBox'),
  lastUpdated: document.getElementById('lastUpdated'),
  toast: document.getElementById('toast'),

  refreshBtn: document.getElementById('refreshBtn'),
  createBtn: document.getElementById('createBtn'),
  loadLogsBtn: document.getElementById('loadLogsBtn'),
  langSelect: document.getElementById('langSelect'),

  createModal: document.getElementById('createModal'),
  createForm: document.getElementById('createForm'),
  closeCreate: document.getElementById('closeCreate'),
  cancelCreate: document.getElementById('cancelCreate'),

  editModal: document.getElementById('editModal'),
  editForm: document.getElementById('editForm'),
  editTitle: document.getElementById('editTitle'),
  editConfigText: document.getElementById('editConfigText'),
  editRestart: document.getElementById('editRestart'),
  closeEdit: document.getElementById('closeEdit'),
  cancelEdit: document.getElementById('cancelEdit'),
};

function tr(key, vars = {}) {
  const dict = I18N[state.lang] || I18N.fa;
  const fallback = I18N.en[key] || key;
  let text = dict[key] || fallback;
  Object.entries(vars).forEach(([k, v]) => {
    text = text.replaceAll(`{{${k}}}`, String(v));
  });
  return text;
}

function applyI18n() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === 'fa' ? 'rtl' : 'ltr';
  document.body.classList.toggle('lang-fa', state.lang === 'fa');

  document.title = tr('doc.title');
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (key) el.textContent = tr(key);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key) el.setAttribute('placeholder', tr(key));
  });
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {}
  if (!res.ok || data.ok === false) {
    const msg = data.error || `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}

function fmtBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n.toFixed(0)} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function fmtBps(bps) {
  const n = Number(bps || 0);
  if (n < 1024) return `${n.toFixed(0)} B/s`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB/s`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB/s`;
  return `${(n / 1024 ** 3).toFixed(2)} GB/s`;
}

function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds || 0)));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (state.lang === 'fa') {
    if (d > 0) return `${d} ${tr('time.day')} ${h} ${tr('time.hour')} ${m} ${tr('time.min')}`;
    if (h > 0) return `${h} ${tr('time.hour')} ${m} ${tr('time.min')}`;
    return `${m} ${tr('time.min')}`;
  }
  if (d > 0) return `${d}${tr('time.day')} ${h}${tr('time.hour')} ${m}${tr('time.min')}`;
  if (h > 0) return `${h}${tr('time.hour')} ${m}${tr('time.min')}`;
  return `${m}${tr('time.min')}`;
}

function statusBadge(active, sub) {
  const a = String(active || '').toLowerCase() || tr('status.unknown');
  const s = String(sub || '').toLowerCase() || tr('status.unknown');
  if (a === 'active') return `<span class="badge ok">✅ ${a}/${s}</span>`;
  if (a === 'activating' || a === 'reloading') return `<span class="badge warn">🟡 ${a}/${s}</span>`;
  return `<span class="badge err">🔴 ${a}/${s}</span>`;
}

function showToast(message, isError = false) {
  els.toast.textContent = message;
  els.toast.classList.add('show');
  els.toast.classList.toggle('error', isError);
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    els.toast.classList.remove('show');
  }, 2600);
}

function renderResources(resources = {}) {
  const mem = resources.memory || {};
  const disk = resources.disk || {};
  const load = resources.load || { '1m': 0, '5m': 0, '15m': 0 };
  const net = resources.network || {};
  els.cpuVal.textContent = `${Number(resources.cpu_percent || 0).toFixed(1)}%`;
  els.memVal.textContent = `${Number(mem.used_percent || 0).toFixed(1)}% (${fmtBytes(mem.used)} / ${fmtBytes(mem.total)})`;
  els.diskVal.textContent = `${Number(disk.used_percent || 0).toFixed(1)}% (${fmtBytes(disk.used)} / ${fmtBytes(disk.total)})`;
  els.loadVal.textContent = `${Number(load['1m'] || 0).toFixed(2)} / ${Number(load['5m'] || 0).toFixed(2)} / ${Number(load['15m'] || 0).toFixed(2)}`;
  els.uptimeVal.textContent = fmtUptime(resources.uptime_seconds);
  els.hostNetVal.textContent = `↓ ${fmtBps(net.rx_bps)} • ↑ ${fmtBps(net.tx_bps)}`;
}

function renderLogServiceSelect() {
  const current = els.logService.value;
  els.logService.innerHTML = '';
  state.tunnels.forEach((t) => {
    const opt = document.createElement('option');
    opt.value = t.service;
    opt.textContent = `${t.service} (${t.role})`;
    els.logService.appendChild(opt);
  });
  if (current && state.tunnels.some((t) => t.service === current)) {
    els.logService.value = current;
  }
}

function tunnelActionButtons(service) {
  return `
    <div class="inline-actions">
      <button class="btn" data-action="start" data-service="${service}">▶️ ${tr('action.start')}</button>
      <button class="btn" data-action="stop" data-service="${service}">⏹️ ${tr('action.stop')}</button>
      <button class="btn" data-action="restart" data-service="${service}">♻️ ${tr('action.restart')}</button>
      <button class="btn" data-action="edit" data-service="${service}">✏️ ${tr('action.edit')}</button>
      <button class="btn btn-danger" data-action="delete" data-service="${service}">🗑️ ${tr('action.delete')}</button>
    </div>
  `;
}

function renderTunnels(tunnels) {
  state.tunnels = tunnels;
  renderLogServiceSelect();

  if (!tunnels.length) {
    els.tunnelRows.innerHTML = `<tr><td colspan="7" class="muted">${tr('table.no_tunnels')}</td></tr>`;
    return;
  }

  const rows = tunnels
    .map((t) => {
      const profile = t.config?.profile || '-';
      const tunnelMode = t.config?.tunnel_mode || '-';
      const endpoints = (t.config?.endpoints || []).map((ep) => `<span class="endpoint-pill">${ep}</span>`).join(' ');
      const thr = t.throughput || { rx_bps: 0, tx_bps: 0, rx_total: 0, tx_total: 0 };

      return `
        <tr>
          <td>
            <div class="service-name">${t.service}</div>
            <div class="muted">${t.config?.config_path || ''}</div>
          </td>
          <td>${t.role}:${t.instance}</td>
          <td>${statusBadge(t.active, t.sub)}</td>
          <td><span class="profile-chip">${profile}</span> / <span class="mode-chip">${tunnelMode}</span></td>
          <td>${endpoints || '<span class="muted">-</span>'}</td>
          <td class="thr-cell">
            <div>🟢 ${tr('thr.down')}: ${fmtBps(thr.rx_bps)}</div>
            <div>🟠 ${tr('thr.up')}: ${fmtBps(thr.tx_bps)}</div>
            <div class="muted">${tr('thr.total')}: ↓${fmtBytes(thr.rx_total)} / ↑${fmtBytes(thr.tx_total)}</div>
          </td>
          <td>${tunnelActionButtons(t.service)}</td>
        </tr>
      `;
    })
    .join('');

  els.tunnelRows.innerHTML = rows;
}

async function loadResources() {
  const data = await api('/api/resources');
  renderResources(data.resources || {});
}

async function loadTunnels() {
  const data = await api('/api/tunnels');
  renderTunnels(data.tunnels || []);
}

async function loadAll() {
  try {
    await Promise.all([loadResources(), loadTunnels()]);
    const timeStr = new Date().toLocaleTimeString(state.lang === 'fa' ? 'fa-IR' : 'en-US');
    els.lastUpdated.textContent = `${tr('updated.prefix')}: ${timeStr}`;
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function loadLogs() {
  const service = els.logService.value;
  if (!service) {
    showToast(tr('logs.select_error'), true);
    return;
  }
  try {
    const data = await api(`/api/tunnels/${encodeURIComponent(service)}/logs?lines=220`);
    els.logsBox.textContent = data.logs || tr('logs.no_output');
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function actOnService(service, action) {
  try {
    await api(`/api/tunnels/${encodeURIComponent(service)}/action`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
    showToast(tr('toast.action', { service, action }));
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function deleteService(service) {
  if (!confirm(tr('confirm.delete', { service }))) return;
  try {
    await api(`/api/tunnels/${encodeURIComponent(service)}`, { method: 'DELETE' });
    showToast(tr('toast.deleted', { service }));
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function openEditor(service) {
  try {
    const data = await api(`/api/tunnels/${encodeURIComponent(service)}/config`);
    state.editService = service;
    els.editTitle.textContent = `${tr('edit.title')}: ${service}`;
    els.editConfigText.value = data.config_text || '';
    els.editModal.showModal();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

function closeEditor() {
  state.editService = null;
  els.editModal.close();
}

async function saveEditor() {
  if (!state.editService) return;
  const configText = els.editConfigText.value;
  if (!configText.trim()) {
    showToast(tr('editor.empty'), true);
    return;
  }
  try {
    await api(`/api/tunnels/${encodeURIComponent(state.editService)}/config`, {
      method: 'PUT',
      body: JSON.stringify({
        config_text: configText,
        restart: els.editRestart.checked,
      }),
    });
    showToast(tr('toast.saved', { service: state.editService }));
    closeEditor();
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

function formToPayload(form) {
  const fd = new FormData(form);
  const payload = {};
  for (const [k, v] of fd.entries()) payload[k] = String(v || '').trim();
  if (payload.port) payload.port = Number(payload.port);
  if (payload.pool_size) payload.pool_size = Number(payload.pool_size);
  return payload;
}

async function submitCreate(event) {
  event.preventDefault();
  const payload = formToPayload(els.createForm);
  try {
    await api('/api/tunnels', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    showToast(tr('toast.created'));
    els.createModal.close();
    els.createForm.reset();
    els.createForm.querySelector('select[name="profile"]').value = 'balanced';
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

function setLanguage(lang) {
  const normalized = lang === 'en' ? 'en' : 'fa';
  state.lang = normalized;
  localStorage.setItem('nodelay.webpanel.lang', normalized);
  if (els.langSelect.value !== normalized) {
    els.langSelect.value = normalized;
  }
  applyI18n();
  renderTunnels(state.tunnels);
}

function bindEvents() {
  els.refreshBtn.addEventListener('click', loadAll);
  els.createBtn.addEventListener('click', () => els.createModal.showModal());
  els.loadLogsBtn.addEventListener('click', loadLogs);
  els.langSelect.addEventListener('change', (event) => setLanguage(event.target.value));

  els.closeCreate.addEventListener('click', () => els.createModal.close());
  els.cancelCreate.addEventListener('click', () => els.createModal.close());
  els.createForm.addEventListener('submit', submitCreate);

  els.closeEdit.addEventListener('click', closeEditor);
  els.cancelEdit.addEventListener('click', closeEditor);
  els.editForm.addEventListener('submit', (e) => {
    e.preventDefault();
    saveEditor();
  });

  els.tunnelRows.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    const service = button.dataset.service;

    if (action === 'edit') return openEditor(service);
    if (action === 'delete') return deleteService(service);
    if (action === 'start' || action === 'stop' || action === 'restart') {
      return actOnService(service, action);
    }
    return undefined;
  });
}

async function init() {
  const storedLang = localStorage.getItem('nodelay.webpanel.lang') || 'fa';
  state.lang = storedLang === 'en' ? 'en' : 'fa';
  els.langSelect.value = state.lang;
  applyI18n();
  bindEvents();
  await loadAll();
  state.refreshTimer = setInterval(loadAll, 3000);
}

init();
