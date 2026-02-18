const state = {
  tunnels: [],
  editService: null,
  refreshTimer: null,
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

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch (_) {}
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
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function statusBadge(active, sub) {
  const a = String(active || '').toLowerCase();
  if (a === 'active') return `<span class="badge ok">${a}/${sub}</span>`;
  if (a === 'activating' || a === 'reloading') return `<span class="badge warn">${a}/${sub}</span>`;
  return `<span class="badge err">${a || 'unknown'}/${sub || 'unknown'}</span>`;
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

function renderResources(resources) {
  els.cpuVal.textContent = `${Number(resources.cpu_percent || 0).toFixed(1)}%`;
  els.memVal.textContent = `${Number(resources.memory.used_percent || 0).toFixed(1)}% (${fmtBytes(resources.memory.used)} / ${fmtBytes(resources.memory.total)})`;
  els.diskVal.textContent = `${Number(resources.disk.used_percent || 0).toFixed(1)}% (${fmtBytes(resources.disk.used)} / ${fmtBytes(resources.disk.total)})`;
  els.loadVal.textContent = `${resources.load['1m'].toFixed(2)} / ${resources.load['5m'].toFixed(2)} / ${resources.load['15m'].toFixed(2)}`;
  els.uptimeVal.textContent = fmtUptime(resources.uptime_seconds);
  els.hostNetVal.textContent = `↓ ${fmtBps(resources.network.rx_bps)} • ↑ ${fmtBps(resources.network.tx_bps)}`;
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
  if (current && state.tunnels.some(t => t.service === current)) {
    els.logService.value = current;
  }
}

function tunnelActionButtons(service) {
  return `
    <div class="inline-actions">
      <button class="btn" data-action="start" data-service="${service}">Start</button>
      <button class="btn" data-action="stop" data-service="${service}">Stop</button>
      <button class="btn" data-action="restart" data-service="${service}">Restart</button>
      <button class="btn" data-action="edit" data-service="${service}">Edit</button>
      <button class="btn btn-danger" data-action="delete" data-service="${service}">Delete</button>
    </div>
  `;
}

function renderTunnels(tunnels) {
  state.tunnels = tunnels;
  renderLogServiceSelect();

  if (!tunnels.length) {
    els.tunnelRows.innerHTML = `<tr><td colspan="7" class="muted">No tunnel services found.</td></tr>`;
    return;
  }

  const rows = tunnels.map((t) => {
    const profile = t.config?.profile || '-';
    const tunnelMode = t.config?.tunnel_mode || '-';
    const endpoints = (t.config?.endpoints || []).map(ep => `<span class="endpoint-pill">${ep}</span>`).join(' ');
    const thr = t.throughput || { rx_bps: 0, tx_bps: 0 };

    return `
      <tr>
        <td>
          <div class="service-name">${t.service}</div>
          <div class="muted">${t.config?.config_path || ''}</div>
        </td>
        <td>${t.role}:${t.instance}</td>
        <td>${statusBadge(t.active, t.sub)}</td>
        <td>${profile} / ${tunnelMode}</td>
        <td>${endpoints || '<span class="muted">-</span>'}</td>
        <td>
          <div>↓ ${fmtBps(thr.rx_bps)}</div>
          <div>↑ ${fmtBps(thr.tx_bps)}</div>
        </td>
        <td>${tunnelActionButtons(t.service)}</td>
      </tr>
    `;
  }).join('');

  els.tunnelRows.innerHTML = rows;
}

async function loadResources() {
  const data = await api('/api/resources');
  renderResources(data.resources);
}

async function loadTunnels() {
  const data = await api('/api/tunnels');
  renderTunnels(data.tunnels || []);
}

async function loadAll() {
  try {
    await Promise.all([loadResources(), loadTunnels()]);
    els.lastUpdated.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function loadLogs() {
  const service = els.logService.value;
  if (!service) {
    showToast('No tunnel selected for logs', true);
    return;
  }
  try {
    const data = await api(`/api/tunnels/${encodeURIComponent(service)}/logs?lines=220`);
    els.logsBox.textContent = data.logs || '(no log output)';
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
    showToast(`${service}: ${action} requested`);
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function deleteService(service) {
  if (!confirm(`Delete ${service}.service and its config?`)) return;
  try {
    await api(`/api/tunnels/${encodeURIComponent(service)}`, { method: 'DELETE' });
    showToast(`${service} deleted`);
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

async function openEditor(service) {
  try {
    const data = await api(`/api/tunnels/${encodeURIComponent(service)}/config`);
    state.editService = service;
    els.editTitle.textContent = `Edit Config: ${service}`;
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
    showToast('Config YAML cannot be empty', true);
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
    showToast(`Saved ${state.editService}`);
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
    showToast('Tunnel created/updated');
    els.createModal.close();
    els.createForm.reset();
    await loadAll();
  } catch (err) {
    showToast(err.message || String(err), true);
  }
}

function bindEvents() {
  els.refreshBtn.addEventListener('click', loadAll);
  els.createBtn.addEventListener('click', () => els.createModal.showModal());
  els.loadLogsBtn.addEventListener('click', loadLogs);

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
  });
}

async function init() {
  bindEvents();
  await loadAll();
  state.refreshTimer = setInterval(loadAll, 3000);
}

init();
