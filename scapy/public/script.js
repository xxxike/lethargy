(() => {
  const apiBase = (window.__CONFIG__ && window.__CONFIG__.apiBase) || '';
  const $ = (sel) => document.querySelector(sel);
  const logBody = $('#log-body');
  const btnStart = $('#start');
  const btnStop = $('#stop');
  const btnClear = $('#clear');
  const inpIface = $('#iface');
  const inpFilter = $('#filter');
  const statusEl = $('#status');

  let es = null;
  let running = false;
  const enrichCache = new Map();

  function setStatus(text) { statusEl.textContent = text; }
  function setRunning(on) {
    running = !!on;
    btnStart.disabled = running;
    btnStop.disabled = !running;
  }

  function addRow(item) {
    const tr = document.createElement('tr');
    const proto = (item.proto || '').toLowerCase();
    if (proto.startsWith('tcp')) tr.classList.add('proto-tcp');
    else if (proto.startsWith('udp')) tr.classList.add('proto-udp');
    else if (proto.includes('icmp')) tr.classList.add('proto-icmp');
    else if (proto.includes('arp')) tr.classList.add('proto-arp');
    const srcCell = `<div class="ip"><span class="val" title="${item.src || ''}">${item.src || ''}</span><small class="sub" data-ip="${item.src || ''}"></small></div>`;
    const dstCell = `<div class="ip"><span class="val" title="${item.dst || ''}">${item.dst || ''}</span><small class="sub" data-ip="${item.dst || ''}"></small></div>`;
    tr.innerHTML = `<td>${item.time || ''}</td><td>${item.src_mac || ''}</td><td>${item.dst_mac || ''}</td><td>${srcCell}</td><td>${dstCell}</td><td class="owner"></td><td>${item.proto || ''}</td><td>${item.length || ''}</td>`;
    logBody.prepend(tr);
    const max = 1000;
    while (logBody.rows && logBody.rows.length > max) {
      logBody.deleteRow(logBody.rows.length - 1);
    }
  }

  function isPrivateIp(ip) {
    return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|169\.254\.)/.test(ip);
  }

  function pickOwner(data) {
    return data.org || data.asn_description || data.network_name || data.asn || '';
  }

  async function enrichIp(ip, smallEl, ownerCell) {
    if (!ip || isPrivateIp(ip)) return;
    if (enrichCache.has(ip)) {
      const cached = enrichCache.get(ip);
      if (smallEl) smallEl.textContent = cached.sub || '';
      if (ownerCell && !ownerCell.textContent) ownerCell.textContent = cached.owner || '';
      return;
    }
    try {
      const res = await fetch(`${apiBase}/enrich`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return;
      const parts = [];
      if (data.reverse) parts.push(data.reverse);
      if (data.org) parts.push(data.org);
      if (data.asn_description) parts.push(data.asn_description);
      if (data.country) parts.push(data.country);
      const sub = parts.join(' • ');
      const owner = pickOwner(data);
      enrichCache.set(ip, { sub, owner });
      if (smallEl) smallEl.textContent = sub;
      if (ownerCell && !ownerCell.textContent) ownerCell.textContent = owner;
    } catch (_) {}
  }

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;
        const smalls = node.querySelectorAll('small.sub[data-ip]');
        const ownerCell = node.querySelector('td.owner');
        smalls.forEach((s) => enrichIp(s.getAttribute('data-ip'), s, ownerCell));
      }
    }
  });
  observer.observe(logBody, { childList: true });

  function connectSSE() {
    if (es) es.close();
    es = new EventSource(`${apiBase}/events`);
    es.onmessage = (e) => {
      try { addRow(JSON.parse(e.data)); } catch (_) {}
    };
    es.addEventListener('ping', () => {});
    es.onerror = () => { };
  }

  async function start() {
    setStatus('Запуск...');
    const payload = { iface: inpIface.value || undefined, filter: inpFilter.value || undefined };
    const res = await fetch(`${apiBase}/start`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setStatus(data.error || `Не удалось запустить (${res.status})`);
      return;
    }
    connectSSE();
    setRunning(true);
    setStatus('Работает');
  }

  async function stop() {
    setStatus('Остановка...');
    await fetch(`${apiBase}/stop`, { method: 'POST' });
    setRunning(false);
    setStatus('Остановлен');
  }

  function clearLog() {
    logBody.innerHTML = '';
  }

  btnStart.addEventListener('click', start);
  btnStop.addEventListener('click', stop);
  btnClear.addEventListener('click', clearLog);

  setRunning(false);
  setStatus('Ожидание');
})();

