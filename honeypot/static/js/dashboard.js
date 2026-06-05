async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return await res.json();
}

let currentFingerprintFilters = {
  days: 30,
  category: 'all',
  strategy: 'all',
  min_score: '',
  max_score: '',
  min_depth: '',
  min_rpm: '',
  max_rpm: '',
  js: 'all',
  cookies: 'all',
};
let fingerprintPresets = [];

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  }
}

function drawGraph(edges) {
  const svg = d3.select('#path-graph');
  svg.selectAll('*').remove();

  ensureGraphControls();

  const rect = svg.node().getBoundingClientRect();
  const width = Math.max(rect.width, 900);
  const height = 460;

  const nodeSet = new Set();
  edges.forEach((e) => {
    nodeSet.add(e.source);
    nodeSet.add(e.target);
  });

  const nodes = Array.from(nodeSet).map((id) => ({ id }));
  const links = edges.map((e) => ({ source: e.source, target: e.target, weight: e.weight }));

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id((d) => d.id).distance((d) => 120 - Math.min(d.weight, 20)))
    .force('charge', d3.forceManyBody().strength(-250))
    .force('center', d3.forceCenter(width / 2, height / 2));

  const graphGroup = svg.append('g').attr('class', 'graph-group');

  const link = graphGroup.append('g')
    .attr('stroke', '#ffd339')
    .attr('stroke-opacity', 0.5)
    .selectAll('line')
    .data(links)
    .join('line')
    .attr('stroke-width', (d) => Math.max(1, Math.log2(d.weight + 1)));

  const node = graphGroup.append('g')
    .selectAll('circle')
    .data(nodes)
    .join('circle')
    .attr('r', 4)
    .attr('fill', '#fffef7');

  const label = graphGroup.append('g')
    .selectAll('text')
    .data(nodes)
    .join('text')
    .text((d) => d.id.split('/').slice(-2).join('/'))
    .attr('font-size', 10)
    .attr('fill', '#f7f7f7');

  sim.on('tick', () => {
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);

    node
      .attr('cx', (d) => d.x)
      .attr('cy', (d) => d.y);

    label
      .attr('x', (d) => d.x + 6)
      .attr('y', (d) => d.y + 2);
  });

  setupZoom(svg, graphGroup);
}

function ensureGraphControls() {
  if (document.getElementById('graph-controls')) {
    return;
  }

  const svgEl = document.getElementById('path-graph');
  if (!svgEl || !svgEl.parentElement) {
    return;
  }

  const controls = document.createElement('div');
  controls.id = 'graph-controls';
  controls.style.display = 'flex';
  controls.style.gap = '0.5rem';
  controls.style.marginBottom = '0.75rem';

  const zoomInBtn = document.createElement('button');
  zoomInBtn.id = 'graph-zoom-in';
  zoomInBtn.className = 'btn';
  zoomInBtn.type = 'button';
  zoomInBtn.textContent = 'Zoom +';

  const zoomOutBtn = document.createElement('button');
  zoomOutBtn.id = 'graph-zoom-out';
  zoomOutBtn.className = 'btn';
  zoomOutBtn.type = 'button';
  zoomOutBtn.textContent = 'Zoom -';

  const resetBtn = document.createElement('button');
  resetBtn.id = 'graph-zoom-reset';
  resetBtn.className = 'btn';
  resetBtn.type = 'button';
  resetBtn.textContent = 'Reset';

  controls.append(zoomInBtn, zoomOutBtn, resetBtn);
  svgEl.parentElement.insertBefore(controls, svgEl);
}

function setupZoom(svg, graphGroup) {
  const zoomBehavior = d3.zoom()
    .scaleExtent([0.25, 5])
    .on('zoom', (event) => {
      graphGroup.attr('transform', event.transform);
    });

  svg.call(zoomBehavior);

  const zoomInBtn = resetButtonNode('graph-zoom-in');
  const zoomOutBtn = resetButtonNode('graph-zoom-out');
  const resetBtn = resetButtonNode('graph-zoom-reset');

  zoomInBtn?.addEventListener('click', () => {
    svg.transition().duration(180).call(zoomBehavior.scaleBy, 1.25);
  });

  zoomOutBtn?.addEventListener('click', () => {
    svg.transition().duration(180).call(zoomBehavior.scaleBy, 0.8);
  });

  resetBtn?.addEventListener('click', () => {
    svg.transition().duration(220).call(zoomBehavior.transform, d3.zoomIdentity);
  });
}

function resetButtonNode(id) {
  const oldNode = document.getElementById(id);
  if (!oldNode || !oldNode.parentNode) {
    return oldNode;
  }
  const newNode = oldNode.cloneNode(true);
  oldNode.parentNode.replaceChild(newNode, oldNode);
  return newNode;
}

async function loadDashboard() {
  await loadFingerprintPresets();
  const fingerprintUrl = buildFingerprintingUrl(currentFingerprintFilters);
  const [overview, topUA, behavior, advanced, robots, families, recurring, pathMap, realtime, fingerprinting] = await Promise.all([
    getJson('/api/stats/overview'),
    getJson('/api/stats/top-user-agents?limit=20'),
    getJson('/api/stats/behavior'),
    getJson('/api/stats/advanced'),
    getJson('/api/stats/robots'),
    getJson('/api/stats/families'),
    getJson('/api/stats/recurring'),
    getJson('/api/stats/path-map'),
    getJson('/api/stats/realtime?window=300'),
    getJson(fingerprintUrl),
  ]);

  setText('total-visits', overview.total_visits);
  setText('unique-visitors', overview.unique_visitors);
  setText('unique-ua', overview.unique_user_agents);
  setText('js-rate', behavior.js_execution_rate);

  setText('categories', overview.category_distribution);
  setText('top-ua', topUA);
  setText('behavior', behavior);
  setText('advanced', advanced);
  setText('robots', robots);
  setText('families', families);
  setText('recurring', recurring);
  setText('realtime', realtime);
  applyFingerprintingData(fingerprinting);

  setText('active-bots', realtime.active_bots);
  setText('active-visitors', realtime.active_visitors);
  setText('active-js', realtime.active_visitors_with_js);
  setText('suspicious-window', realtime.suspicious?.recent_window?.hits || 0);
  setText('suspicious-top', realtime.suspicious?.top_suspicious_paths_24h || []);

  drawGraph(pathMap.edges || []);
}

function buildFingerprintingUrl(filters) {
  const params = new URLSearchParams();
  params.set('limit', '200');
  params.set('days', String(filters.days || 30));

  const optionalKeys = [
    'category',
    'strategy',
    'min_score',
    'max_score',
    'min_depth',
    'min_rpm',
    'max_rpm',
    'js',
    'cookies',
  ];

  optionalKeys.forEach((key) => {
    const value = filters[key];
    if (value !== undefined && value !== null && value !== '' && value !== 'all') {
      params.set(key, String(value));
    }
  });

  return `/api/stats/fingerprinting?${params.toString()}`;
}

function buildFingerprintingExportUrl(format, filters) {
  const params = new URLSearchParams();
  params.set('limit', '2000');
  params.set('days', String(filters.days || 30));

  const optionalKeys = [
    'category',
    'strategy',
    'min_score',
    'max_score',
    'min_depth',
    'min_rpm',
    'max_rpm',
    'js',
    'cookies',
  ];

  optionalKeys.forEach((key) => {
    const value = filters[key];
    if (value !== undefined && value !== null && value !== '' && value !== 'all') {
      params.set(key, String(value));
    }
  });

  return `/api/fingerprinting/export/${format}?${params.toString()}`;
}

function applyFingerprintingData(fingerprinting) {
  setText('fingerprint-summary', {
    ...(fingerprinting.summary || {}),
    active_filters: fingerprinting.filters || {},
  });
  setText('fingerprint-top', fingerprinting.top_profiles || []);
}

function collectFingerprintFilters() {
  const form = document.getElementById('fingerprint-filters');
  if (!form) {
    return currentFingerprintFilters;
  }

  const formData = new FormData(form);
  return {
    days: Number.isFinite(parseInt(formData.get('days') || '30', 10))
      ? parseInt(formData.get('days') || '30', 10)
      : 30,
    category: formData.get('category') || 'all',
    strategy: formData.get('strategy') || 'all',
    min_score: formData.get('min_score') || '',
    max_score: formData.get('max_score') || '',
    min_depth: formData.get('min_depth') || '',
    min_rpm: formData.get('min_rpm') || '',
    max_rpm: formData.get('max_rpm') || '',
    js: formData.get('js') || 'all',
    cookies: formData.get('cookies') || 'all',
  };
}

function fillFingerprintForm(filters) {
  const form = document.getElementById('fingerprint-filters');
  if (!form || !filters) {
    return;
  }

  const set = (name, value) => {
    const el = form.elements[name];
    if (!el) {
      return;
    }
    if (value === undefined || value === null || value === '') {
      if (el.tagName === 'SELECT') {
        el.value = 'all';
      } else {
        el.value = '';
      }
      return;
    }
    el.value = String(value);
  };

  set('days', filters.days ?? 30);
  set('category', filters.category ?? 'all');
  set('strategy', filters.strategy ?? 'all');
  set('min_score', filters.min_score);
  set('max_score', filters.max_score);
  set('min_depth', filters.min_depth);
  set('min_rpm', filters.min_rpm);
  set('max_rpm', filters.max_rpm);
  set('js', filters.js ?? 'all');
  set('cookies', filters.cookies ?? 'all');
}

async function loadFingerprintPresets() {
  try {
    const data = await getJson('/api/fingerprinting/presets');
    fingerprintPresets = Array.isArray(data.presets) ? data.presets : [];
    renderFingerprintPresetSelect();
  } catch (err) {
    console.error('failed to load presets', err);
  }
}

function renderFingerprintPresetSelect() {
  const select = document.getElementById('fingerprint-preset-select');
  if (!select) {
    return;
  }
  const previous = select.value;
  select.innerHTML = '<option value="">Aucun</option>';
  fingerprintPresets.forEach((preset) => {
    const opt = document.createElement('option');
    opt.value = String(preset.id);
    opt.textContent = preset.name;
    select.appendChild(opt);
  });
  select.value = previous;
}

async function saveCurrentPreset() {
  const nameInput = document.getElementById('fingerprint-preset-name');
  const name = (nameInput?.value || '').trim();
  if (!name) {
    alert('Nom de preset requis');
    return;
  }

  const filters = collectFingerprintFilters();
  const res = await fetch('/api/fingerprinting/presets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, filters }),
  });
  const data = await res.json();
  if (!res.ok || !data.ok) {
    alert('Echec sauvegarde preset');
    return;
  }
  await loadFingerprintPresets();
  alert('Preset sauvegarde');
}

async function deleteSelectedPreset() {
  const select = document.getElementById('fingerprint-preset-select');
  const id = select?.value;
  if (!id) {
    alert('Selectionne un preset');
    return;
  }

  const res = await fetch(`/api/fingerprinting/presets/${id}`, { method: 'DELETE' });
  const data = await res.json();
  if (!res.ok || !data.ok) {
    alert('Echec suppression preset');
    return;
  }

  if (select) {
    select.value = '';
  }
  await loadFingerprintPresets();
  alert('Preset supprime');
}

function applySelectedPreset() {
  const select = document.getElementById('fingerprint-preset-select');
  const id = select?.value;
  if (!id) {
    return;
  }
  const preset = fingerprintPresets.find((p) => String(p.id) === String(id));
  if (!preset) {
    return;
  }
  fillFingerprintForm(preset.filters || {});
  applyFingerprintFilters();
}

function triggerFingerprintExport(format) {
  currentFingerprintFilters = collectFingerprintFilters();
  window.location.href = buildFingerprintingExportUrl(format, currentFingerprintFilters);
}

async function applyFingerprintFilters() {
  currentFingerprintFilters = collectFingerprintFilters();
  try {
    const data = await getJson(buildFingerprintingUrl(currentFingerprintFilters));
    applyFingerprintingData(data);
  } catch (err) {
    console.error('fingerprint filter request failed', err);
    alert('Erreur filtres fingerprinting');
  }
}

function resetFingerprintFilters() {
  const form = document.getElementById('fingerprint-filters');
  if (form) {
    form.reset();
    const daysInput = form.querySelector('input[name="days"]');
    if (daysInput) {
      daysInput.value = '30';
    }
  }
  currentFingerprintFilters = {
    days: 30,
    category: 'all',
    strategy: 'all',
    min_score: '',
    max_score: '',
    min_depth: '',
    min_rpm: '',
    max_rpm: '',
    js: 'all',
    cookies: 'all',
  };
  applyFingerprintFilters();
}

async function refreshRealtime() {
  try {
    const realtime = await getJson('/api/stats/realtime?window=300');
    setText('realtime', realtime);
    setText('active-bots', realtime.active_bots);
    setText('active-visitors', realtime.active_visitors);
    setText('active-js', realtime.active_visitors_with_js);
    setText('suspicious-window', realtime.suspicious?.recent_window?.hits || 0);
    setText('suspicious-top', realtime.suspicious?.top_suspicious_paths_24h || []);
  } catch (err) {
    console.error('realtime refresh failed', err);
  }
}

document.getElementById('daily-report-btn')?.addEventListener('click', async () => {
  try {
    const res = await fetch('/api/reports/daily', { method: 'POST' });
    const data = await res.json();
    alert(`Rapport genere: ${data.file}`);
  } catch (_e) {
    alert('Echec generation rapport');
  }
});

document.getElementById('fingerprint-filters')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  await applyFingerprintFilters();
});

document.getElementById('fingerprint-reset')?.addEventListener('click', () => {
  resetFingerprintFilters();
});

document.getElementById('fingerprint-save-preset')?.addEventListener('click', async () => {
  await saveCurrentPreset();
});

document.getElementById('fingerprint-delete-preset')?.addEventListener('click', async () => {
  await deleteSelectedPreset();
});

document.getElementById('fingerprint-preset-select')?.addEventListener('change', () => {
  applySelectedPreset();
});

document.getElementById('fingerprint-export-json')?.addEventListener('click', () => {
  triggerFingerprintExport('json');
});

document.getElementById('fingerprint-export-csv')?.addEventListener('click', () => {
  triggerFingerprintExport('csv');
});

loadDashboard().catch((err) => {
  console.error(err);
  alert('Erreur de chargement dashboard');
});

window.setInterval(refreshRealtime, 10000);
