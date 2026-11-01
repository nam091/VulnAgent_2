/* VulnAgent dashboard.
   Hash routing so any view survives a reload; live progress over SSE with a
   polling fallback so a job is never lost to a dropped stream. */

'use strict';

const view = document.getElementById('view');
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLOR = {
  CRITICAL: '#c84a52', HIGH: '#c1803e', MEDIUM: '#b09a45',
  LOW: '#4e9478', INFO: '#626973'
};
const PHASES = [
  ['discovery', 'Discover'], ['rules', 'Rules'], ['llm', 'LLM'],
  ['fusion', 'Fuse'], ['verify', 'Verify'], ['done', 'Done']
];

let liveStream = null;
let pollTimer = null;

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const api = async (path, options) => {
  const res = await fetch(path, options);
  let body = null;
  try { body = await res.json(); } catch (e) { /* empty body */ }
  if (!res.ok) throw new Error((body && body.detail) || `HTTP ${res.status}`);
  return body;
};

const ago = iso => {
  if (!iso) return '';
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${Math.floor(secs)}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
};

/* ---------------- charts (inline SVG, no libraries) ---------------- */

function severityStack(counts) {
  const entries = SEV_ORDER.filter(s => counts[s]).map(s => [s, counts[s]]);
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  if (!total) {
    return `<div class="empty" style="padding:26px"><div class="empty-icon">∅</div>
      <div>No findings</div><div>No vulnerabilities detected in scanned scope</div></div>`;
  }
  return `
    <div class="stack">
      ${entries.map(([sev, n]) => `
        <div class="stack-seg" style="flex:${n};background:${SEV_COLOR[sev]}"
             title="${sev}: ${n}"><span>${n}</span></div>`).join('')}
    </div>
    <div class="stack-key">
      ${entries.map(([sev, n]) => `
        <div class="stack-key-item">
          <span class="swatch" style="background:${SEV_COLOR[sev]};color:${SEV_COLOR[sev]}"></span>
          ${sev} <b style="color:var(--text)">${n}</b>
        </div>`).join('')}
    </div>`;
}

/* Risk arc. Drawn as a stroked path so the sweep animates from a dash
   offset rather than needing a library. */
function riskGauge(score, max = 100, levelOverride = null) {
  const pct = Math.max(0, Math.min(1, score / max));
  const R = 62, CX = 78, CY = 78;
  const arc = Math.PI * R;            // half circle

  let band = 'var(--low)';
  let level = 'LOW';
  if (score >= 90 || levelOverride === 'CRITICAL') {
    band = 'var(--crit)';
    level = 'CRITICAL';
  } else if (score >= 70 || levelOverride === 'HIGH') {
    band = 'var(--high)';
    level = 'HIGH';
  } else if (score >= 40 || levelOverride === 'MODERATE' || levelOverride === 'MEDIUM') {
    band = 'var(--med)';
    level = 'MODERATE';
  } else if (score > 0 || levelOverride === 'LOW') {
    band = 'var(--low)';
    level = 'LOW';
  } else {
    band = 'var(--low)';
    level = 'CLEAN';
  }
  if (levelOverride) level = levelOverride;

  return `
    <div class="gauge-wrap">
      <svg width="172" height="102" viewBox="-8 -8 172 102" style="flex-shrink:0">
        <path d="M 16 78 A ${R} ${R} 0 0 1 140 78" fill="none"
              stroke="var(--edge)" stroke-width="9"/>
        <path d="M 16 78 A ${R} ${R} 0 0 1 140 78" fill="none"
              stroke="${band}" stroke-width="9" stroke-linecap="square"
              stroke-dasharray="${arc}" stroke-dashoffset="${arc * (1 - pct)}"
              style="transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)"/>
        ${[0, 0.5, 1].map(t => {
          const a = Math.PI * (1 - t);
          return `<line x1="${CX + Math.cos(a) * (R + 7)}" y1="${CY - Math.sin(a) * (R + 7)}"
            x2="${CX + Math.cos(a) * (R + 12)}" y2="${CY - Math.sin(a) * (R + 12)}"
            stroke="var(--edge-hot)" stroke-width="1"/>`;
        }).join('')}
      </svg>
      <div class="gauge-read">
        <div class="gauge-value" style="color:${band}">${score}</div>
        <div class="gauge-label">Peak risk · ${level}</div>
      </div>
    </div>`;
}

function bars(items, labelKey, valueKey) {
  if (!items.length) return '<div class="empty" style="padding:26px">Nothing recorded yet</div>';
  const max = Math.max(...items.map(i => i[valueKey]));
  return items.map(i => `
    <div class="bar-row">
      <div class="bar-name" title="${esc(i[labelKey])}">${esc(i[labelKey])}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(i[valueKey] / max) * 100}%"></div></div>
      <div class="bar-value">${i[valueKey]}</div>
    </div>`).join('');
}

/* ---------------- dashboard ---------------- */

async function renderDashboard() {
  view.innerHTML = `<div class="page-head"><h1>Dashboard</h1>
    <p>Everything scanned so far, across every run.</p></div>
    <div class="empty"><span class="spinner"></span>Loading</div>`;

  const [stats, jobList] = await Promise.all([
    api('/api/stats'), api('/api/jobs?limit=8')
  ]);
  const jobs = jobList.jobs || [];
  const sources = stats.sources || {};
  const sourceTotal = Object.values(sources).reduce((a, b) => a + b, 0) || 1;
  const confirmedPct = Math.round(((sources.confirmed || 0) / sourceTotal) * 100);

  const sev = stats.severity || {};
  let peakScore = 0;
  let peakLevel = 'CLEAN';
  if ((sev.CRITICAL || 0) > 0) {
    peakScore = 100;
    peakLevel = 'CRITICAL';
  } else if ((sev.HIGH || 0) > 0) {
    peakScore = 80;
    peakLevel = 'HIGH';
  } else if ((sev.MEDIUM || 0) > 0) {
    peakScore = 55;
    peakLevel = 'MODERATE';
  } else if ((sev.LOW || 0) > 0) {
    peakScore = 25;
    peakLevel = 'LOW';
  }

  view.innerHTML = `
    <div class="page-head">
      <h1>Dashboard</h1>
      <p>Everything scanned so far, across every run.</p>
    </div>

    <div class="metrics">
      <div class="metric"><div class="metric-value">${stats.scans}</div>
        <div class="metric-label">Scans</div>
        <div class="metric-sub">${stats.total_seconds}s of analysis</div></div>
      <div class="metric ${stats.findings ? 'high' : 'ok'}"><div class="metric-value">${stats.findings}</div>
        <div class="metric-label">Findings</div>
        <div class="metric-sub">${stats.chains} attack chain(s)</div></div>
      <div class="metric crit"><div class="metric-value">${(stats.severity || {}).CRITICAL || 0}</div>
        <div class="metric-label">Critical</div>
        <div class="metric-sub">${(stats.severity || {}).HIGH || 0} high severity</div></div>
      <div class="metric ${confirmedPct >= 50 ? 'ok' : (stats.findings ? 'high' : '')}">
        <div class="metric-value">${confirmedPct}%</div>
        <div class="metric-label">Corroborated</div>
        <div class="metric-sub">${sources.confirmed || 0} confirmed by both engines</div></div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-title">Threat level</div>
        ${riskGauge(peakScore, 100, peakLevel)}
        <div style="margin-top:20px">${severityStack(stats.severity || {})}</div>
      </div>
      <div class="card">
        <div class="card-title">Evidence strength</div>
        ${['confirmed', 'rule-only', 'llm-only'].map(key => {
          const n = sources[key] || 0;
          const pct = Math.round((n / sourceTotal) * 100);
          const note = {
            'confirmed': 'Both engines reached it independently. Strongest signal.',
            'rule-only': 'Matched a rule. High precision, but rules cannot express every defect.',
            'llm-only': 'Semantic judgement, uncorroborated. Where false positives live.'
          }[key];
          return `
            <div style="padding:13px 0;border-bottom:1px solid var(--edge)">
              <div class="row" style="gap:9px">
                <span class="tag ${key}">${key}</span>
                <div class="spacer"></div>
                <span style="font:700 17px/1 var(--mono);font-variant-numeric:tabular-nums">${n}</span>
                <span class="muted" style="min-width:34px;text-align:right">${pct}%</span>
              </div>
              <div class="bar-track" style="margin-top:9px"><div class="bar-fill"
                style="width:${pct}%"></div></div>
              <p class="muted" style="margin-top:8px">${note}</p>
            </div>`;
        }).join('')}
        <p class="muted" style="margin-top:13px">
          Gate CI on corroborated findings; treat llm-only as a lead to review.
        </p>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Most common vulnerability types</div>
      ${bars(stats.top_types || [], 'type', 'count')}
    </div>

    <div class="card">
      <div class="row" style="margin-bottom:14px">
        <div class="card-title" style="margin:0">Recent scans</div>
        <div class="spacer"></div>
        <a class="btn ghost sm" href="#/jobs">View all</a>
      </div>
      ${jobs.length ? jobs.map(jobRow).join('') : emptyState('No scans yet', 'Start one from the New scan tab.')}
    </div>`;
}

const emptyState = (title, sub) =>
  `<div class="empty"><div class="empty-icon">∅</div>
   <div style="font-weight:600;color:var(--fg-dim)">${esc(title)}</div>
   <div style="font-size:13px;margin-top:5px">${esc(sub)}</div></div>`;

function jobRow(job) {
  const counts = job.counts || {};
  const badges = SEV_ORDER.filter(s => counts[s])
    .map(s => `<span class="pill ${s}">${counts[s]}</span>`).join(' ');
  return `
    <div class="job" onclick="location.hash='#/job/${esc(job.id)}'">
      <span class="job-status ${esc(job.status)}"></span>
      <div style="min-width:0">
        <div class="job-label">${esc(job.label)}</div>
        <div class="job-meta">${esc(job.kind)} · ${esc(job.status)}${
          job.status === 'running' ? ` · ${Math.round(job.percent)}%` : ''} · ${ago(job.created_at)}</div>
      </div>
      <div class="job-right">
        ${badges || `<span class="muted">${job.status === 'done' ? 'clean' : ''}</span>`}
        <button class="btn-edit-label" title="Rename scan" onclick="openRenameModal('${esc(job.id)}', '${esc(job.label)}', event)">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
        </button>
        <button class="btn-del" title="Delete scan" onclick="deleteJob('${esc(job.id)}', event)">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      </div>
    </div>`;
}

/* ---------------- new scan ---------------- */

let pendingFiles = [];

async function renderScan() {
  pendingFiles = [];

  let modelOptionsHtml = `
    <option value="oc/glm-5.3-flash-free" selected>GLM-5.3 Flash (Zhipu Free)</option>
    <option value="cmc/reflection/beam:free">Beam Free (Reflection Reasoning)</option>
    <option value="oc/deepseek-v4.1-flash-free">DeepSeek V4.1 Flash (Code Specialist)</option>
    <option value="nous/upstage/solar-mini4:free">Solar Mini (Upstage Free)</option>
    <option value="ollama/gemma4">Gemma4 (Local 9Router)</option>
    <option value="cx/gpt-5.6-luna">Codex Luna (GPT-5.6 Luna)</option>
  `;

  try {
    const res = await api('/api/models');
    if (res && res.models && res.models.length) {
      modelOptionsHtml = res.models.map(p => `
        <option value="${esc(p.model)}" ${p.is_default ? 'selected' : ''}>
          ${esc(p.name)} (${esc(p.model)})
        </option>
      `).join('');
    }
  } catch (e) {
    // fallback to preset list
  }

  view.innerHTML = `
    <div class="page-head">
      <h1>New scan</h1>
      <p>Upload a folder, paste a snippet, or point at a public repository.</p>
    </div>
    <div class="card">
      <div class="tabs">
        <button class="tab on" data-pane="folder">Upload folder</button>
        <button class="tab" data-pane="snippet">Paste code</button>
        <button class="tab" data-pane="repo">Repository</button>
      </div>

      <div id="pane-folder">
        <div class="dropzone" id="drop">
          <div class="dropzone-icon">⬚</div>
          <div class="dropzone-main">Drop a folder here, or click to choose</div>
          <div class="dropzone-sub">Up to 400 files / 20 MB. Vendored directories are skipped automatically.</div>
        </div>
        <input type="file" id="picker" webkitdirectory directory multiple class="hide">
        <div id="filelist"></div>
      </div>

      <div id="pane-snippet" class="hide">
        <textarea id="code" spellcheck="false" placeholder="Paste Python source here…"></textarea>
        <label class="field">Filename (used for language detection)</label>
        <input type="text" id="snippet-name" value="snippet.py">
      </div>

      <div id="pane-repo" class="hide">
        <label class="field">Repository URL</label>
        <input type="text" id="repo-url" placeholder="https://github.com/owner/repo">
        <label class="field">Branch</label>
        <input type="text" id="repo-branch" placeholder="main">
        <p class="muted" style="margin-top:9px">Public repositories on github, gitlab or bitbucket.</p>
      </div>

      <div class="controls">
        <button class="btn" id="go">Start scan</button>
        <select id="mode" style="width:auto">
          <option value="deep-verify" selected>VulnAgent DeepVerify — AST Slicer + LLM + Verifier</option>
          <option value="llm">LLM only — Semantic analysis</option>
          <option value="semgrep">Semgrep only — Rule engine only</option>
        </select>
        <div id="model-select-group" style="display:inline-flex;align-items:center;gap:6px">
          <span style="font:600 12.5px/1 var(--ui-font);color:var(--text-dim)">Model:</span>
          <select id="scan-model" style="width:auto">
            ${modelOptionsHtml}
          </select>
        </div>
        <label class="check"><input type="checkbox" id="verify" checked> Verification agent</label>
        <label style="display:inline-flex;align-items:center;gap:6px;font:500 12px/1 var(--sans);color:var(--text-dim);margin-left:4px">
          <span>Threads:</span>
          <input type="number" id="concurrency" value="16" min="1" max="50" style="width:58px;padding:6px 8px;font:600 12px/1 var(--mono);background:var(--raised);border:var(--border) solid var(--edge);border-radius:var(--radius-sm);color:var(--text);outline:none">
        </label>
        <div class="spacer"></div>
        <span id="scan-msg" class="muted"></span>
      </div>
      <p class="muted" style="margin-top:11px">
        The verification agent re-reads the code around each LLM-only finding and tries to
        refute it. It removes false positives and traces a taint path, at the cost of extra time.
      </p>
    </div>`;

  let pane = 'folder';
  view.querySelectorAll('.tab').forEach(btn => btn.onclick = () => {
    view.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
    pane = btn.dataset.pane;
    ['folder', 'snippet', 'repo'].forEach(p =>
      document.getElementById('pane-' + p).classList.toggle('hide', p !== pane));
  });

  const modeSelect = document.getElementById('mode');
  const verifyCheck = document.getElementById('verify');
  const modelGroup = document.getElementById('model-select-group');

  function updateModelControls() {
    const m = modeSelect.value;
    if (m === 'deep-verify') {
      verifyCheck.checked = true;
      verifyCheck.disabled = false;
      if (modelGroup) modelGroup.classList.remove('hide');
    } else if (m === 'llm') {
      verifyCheck.checked = false;
      verifyCheck.disabled = false;
      if (modelGroup) modelGroup.classList.remove('hide');
    } else if (m === 'semgrep') {
      verifyCheck.checked = false;
      verifyCheck.disabled = true;
      if (modelGroup) modelGroup.classList.add('hide');
    }
  }

  modeSelect.onchange = updateModelControls;
  updateModelControls();
  verifyCheck.onchange = () => {
    if (verifyCheck.checked && modeSelect.value === 'llm') {
      modeSelect.value = 'deep-verify';
    } else if (!verifyCheck.checked && modeSelect.value === 'deep-verify') {
      modeSelect.value = 'llm';
    }
  };

  const drop = document.getElementById('drop');
  const picker = document.getElementById('picker');
  drop.onclick = () => picker.click();
  picker.onchange = () => setFiles([...picker.files]);

  drop.ondragover = e => { e.preventDefault(); drop.classList.add('hot'); };
  drop.ondragleave = () => drop.classList.remove('hot');
  drop.ondrop = async e => {
    e.preventDefault();
    drop.classList.remove('hot');
    setFiles(await filesFromDrop(e.dataTransfer));
  };

  document.getElementById('go').onclick = () => submit(pane);
}

// No artificial client-side cap: the server decides. Chrome's own directory
// picker stops at 1,000 files, which is a browser limit nothing here can
// raise, so a larger tree has to go through the CLI.
const CHROME_PICKER_CAP = 1000;

function setFiles(files) {
  // Keep only what the backend can scan, so the count shown is honest.
  const keep = /\.(py|pyi|txt|cfg|ini|toml|ya?ml)$/i;
  const skip = /(^|\/)(venv|\.venv|node_modules|\.git|__pycache__|dist|build)(\/|$)/i;
  const eligible = files.filter(f => {
    const path = f.webkitRelativePath || f.name;
    return keep.test(path) && !skip.test(path);
  });

  pendingFiles = eligible;

  const list = document.getElementById('filelist');
  if (!pendingFiles.length) {
    list.innerHTML = `<div class="banner warn" style="margin:12px 0 0">
      No scannable source files in that selection.
      ${files.length ? `Looked at ${files.length} file(s).` : ''}</div>`;
    return;
  }
  const shown = pendingFiles.slice(0, 40)
    .map(f => `<div>${esc(f.webkitRelativePath || f.name)}</div>`).join('');
  list.innerHTML = `<div class="filelist">${shown}${
    pendingFiles.length > 40 ? `<div style="color:var(--fg-faint)">…and ${pendingFiles.length - 40} more</div>` : ''
  }</div>
  ${files.length >= CHROME_PICKER_CAP ? `<div class="banner warn" style="margin:10px 0 0">
      The browser handed over exactly ${files.length} files, which is Chrome's
      own directory-picker limit. <b>Your folder may contain more that were
      never offered.</b> To be certain the whole tree is covered, scan it from
      the command line: <code>vulnagent scan &lt;path&gt;</code></div>` : ''}
  <p class="muted" style="margin-top:8px">${pendingFiles.length} file(s) ready${
    files.length > eligible.length
      ? `, ${files.length - eligible.length} skipped as not scannable` : ''}.</p>`;
}

async function filesFromDrop(transfer) {
  // Directory entries only come through the webkit entry API; a plain
  // dataTransfer.files on a folder drop is empty.
  const entries = [...(transfer.items || [])]
    .map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (!entries.length) return [...transfer.files];

  const out = [];
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      const file = await new Promise(res => entry.file(res));
      Object.defineProperty(file, 'webkitRelativePath', { value: prefix + entry.name });
      out.push(file);
      return;
    }
    const reader = entry.createReader();
    let batch;
    do {
      batch = await new Promise(res => reader.readEntries(res));
      for (const child of batch) await walk(child, prefix + entry.name + '/');
    } while (batch.length);
  };

  for (const entry of entries) await walk(entry, '');
  return out;
}

async function submit(pane) {
  const button = document.getElementById('go');
  const msg = document.getElementById('scan-msg');
  const mode = document.getElementById('mode').value;
  const verify = (mode === 'deep-verify') || document.getElementById('verify').checked;
  const concurrency = parseInt(document.getElementById('concurrency')?.value, 10) || 16;
  const scanModelEl = document.getElementById('scan-model');
  const chosenModel = (mode !== 'semgrep' && scanModelEl && scanModelEl.value !== 'custom')
    ? scanModelEl.value
    : null;

  button.disabled = true;
  msg.innerHTML = '<span class="spinner"></span>Submitting';

  try {
    let job;
    if (pane === 'folder') {
      if (!pendingFiles.length) throw new Error('Choose a folder first');
      const form = new FormData();
      // The third argument becomes the multipart filename, which is how the
      // folder structure survives the upload.
      pendingFiles.forEach(f => form.append('files', f, f.webkitRelativePath || f.name));
      form.append('mode', mode);
      form.append('verify', String(verify));
      form.append('concurrency', String(concurrency));
      if (chosenModel) form.append('model', chosenModel);
      job = await api('/api/jobs/folder', { method: 'POST', body: form });
    } else if (pane === 'snippet') {
      const code = document.getElementById('code').value;
      if (!code.trim()) throw new Error('Paste some code first');
      job = await api('/api/jobs/snippet', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code, filename: document.getElementById('snippet-name').value || 'snippet.py',
          mode, verify, concurrency, model: chosenModel
        })
      });
    } else {
      const url = document.getElementById('repo-url').value.trim();
      if (!url) throw new Error('Enter a repository URL');
      job = await api('/api/jobs/repository', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository_url: url,
          branch: document.getElementById('repo-branch').value.trim() || 'main',
          mode, verify, concurrency, model: chosenModel
        })
      });
    }
    location.hash = `#/job/${job.id}`;
  } catch (e) {
    msg.innerHTML = `<span style="color:var(--crit)">${esc(e.message)}</span>`;
    button.disabled = false;
  }
}

/* ---------------- job list ---------------- */

async function renderJobs() {
  view.innerHTML = `<div class="page-head"><h1>Scans</h1><p>Every scan this server has run.</p></div>
    <div class="empty"><span class="spinner"></span>Loading</div>`;
  const { jobs } = await api('/api/jobs?limit=100');
  view.innerHTML = `
    <div class="page-head">
      <div class="row">
        <div>
          <h1>Scans</h1>
          <p>Every scan this server has run across all benchmarks and targets.</p>
        </div>
        <div class="spacer"></div>
        ${jobs.length ? `<button class="btn ghost sm danger" onclick="clearAllJobs()">Clear history</button>` : ''}
      </div>
    </div>
    <div class="card">
      ${jobs.length ? jobs.map(jobRow).join('')
        : emptyState('No scans yet', 'Start one from the New scan tab.')}
    </div>`;
}

/* ---------------- job detail ---------------- */

let currentJobDetailTab = 'findings';
let currentLoadedJob = null;

async function renderJob(id, subtab) {
  view.innerHTML = `<div class="empty"><span class="spinner"></span>Loading scan</div>`;
  let job;
  try {
    job = await api(`/api/jobs/${id}`);
  } catch (e) {
    view.innerHTML = `<div class="banner err">${esc(e.message)}</div>
      <a class="btn ghost" href="#/jobs">Back to scans</a>`;
    return;
  }

  currentLoadedJob = job;
  currentJobDetailTab = (subtab === 'benchmark' || location.hash.includes('/benchmark')) ? 'benchmark' : 'findings';
  paintJob(job);
  if (job.status === 'running' || job.status === 'queued') follow(id);
}

function switchJobDetailTab(tab) {
  currentJobDetailTab = tab;
  const fTab = document.getElementById('job-tab-findings-content');
  const bTab = document.getElementById('job-tab-benchmark-content');
  const tabBtns = document.querySelectorAll('#job-detail-tabs .tab');
  if (fTab && bTab) {
    if (tab === 'benchmark') {
      fTab.classList.add('hide');
      bTab.classList.remove('hide');
      if (tabBtns[0]) tabBtns[0].classList.remove('on');
      if (tabBtns[1]) tabBtns[1].classList.add('on');
    } else {
      fTab.classList.remove('hide');
      bTab.classList.add('hide');
      if (tabBtns[0]) tabBtns[0].classList.add('on');
      if (tabBtns[1]) tabBtns[1].classList.remove('on');
    }
  }
}

function paintJob(job) {
  const running = job.status === 'running' || job.status === 'queued';
  const result = job.result || {};

  const bench = job.benchmark_evaluation;
  const isBenchSupported = bench && bench.supported;

  function getTrustRank(f) {
    const isConfirmed = f.source === 'confirmed' || f.corroborated;
    const isAgentVerified = f.verification && f.verification.verdict === 'confirmed';
    if (isConfirmed && isAgentVerified) return 1;
    if (isConfirmed) return 2;
    if (isAgentVerified) return 3;
    if (f.source === 'rule-only' || f.source === 'semgrep') return 4;
    return 5;
  }

  const findings = [...(result.findings || [])].sort((a, b) => {
    const rankA = getTrustRank(a);
    const rankB = getTrustRank(b);
    if (rankA !== rankB) return rankA - rankB; // Confirmed & Agent-Verified ALWAYS at the top!
    const sevA = SEV_ORDER.indexOf(a.severity);
    const sevB = SEV_ORDER.indexOf(b.severity);
    if (sevA !== sevB) return sevA - sevB;
    return (a.file || '').localeCompare(b.file || '') || ((a.start_line || 0) - (b.start_line || 0));
  });

  const totalFindings = findings.length;

  view.innerHTML = `
    <div class="page-head">
      <div class="row">
        <div style="min-width:0">
          <h1 id="job-title-header">${esc(job.label)}</h1>
          <p>${esc(job.kind)} · ${esc(job.status)} · started ${ago(job.created_at)}</p>
        </div>
        <div class="spacer"></div>
        <button class="btn ghost sm" onclick="openRenameModal('${esc(job.id)}', '${esc(job.label)}')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg> Rename
        </button>
        <button class="btn ghost sm" id="detail-ai-name-btn" onclick="aiAutoNameAndSave('${esc(job.id)}')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"></path></svg> AI Name
        </button>
        <button class="btn ghost sm danger" onclick="deleteJob('${esc(job.id)}', event)">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> Delete scan
        </button>
        <a class="btn ghost sm" href="#/jobs">All scans</a>
      </div>
      ${isBenchSupported ? `
      <div class="tabs" id="job-detail-tabs" style="margin-top:16px;margin-bottom:0">
        <button type="button" class="tab ${currentJobDetailTab === 'findings' ? 'on' : ''}" onclick="switchJobDetailTab('findings')">
          Findings &amp; Code Analysis (${totalFindings})
        </button>
        <button type="button" class="tab ${currentJobDetailTab === 'benchmark' ? 'on' : ''}" onclick="switchJobDetailTab('benchmark')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> Benchmark Evaluation (${esc(bench.dataset_key)}: TP ${bench.metrics.tp}, F1 ${(bench.metrics.f1 * 100).toFixed(1)}%)
        </button>
      </div>` : ''}
    </div>
    <div id="job-body"></div>`;

  const body = document.getElementById('job-body');

  if (job.status === 'failed') {
    body.innerHTML = `<div class="banner err"><b>Scan failed.</b> ${esc(job.error || job.message)}</div>`;
    return;
  }

  if (running) {
    body.innerHTML = progressCard(job) + partialResults(job);
    body.querySelectorAll('.f-head').forEach(head => head.onclick = () =>
      head.nextElementSibling.classList.toggle('hide'));
    return;
  }

  if (!job.result) {
    body.innerHTML = emptyState('No result stored', 'This scan finished without a result payload.');
    return;
  }

  const counts = result.counts || {};
  const sources = result.sources || {};
  const stats = result.stats || {};
  const countConfirmed = findings.filter(f => f.source === 'confirmed' || f.corroborated).length;
  const countVerified = findings.filter(f => f.verification && f.verification.verdict === 'confirmed').length;
  const countLlm = findings.filter(f => f.source === 'llm-only' || f.source === 'llm').length;
  const countRule = findings.filter(f => f.source === 'rule-only' || f.source === 'semgrep').length;

  let peakScore = 0;
  let peakLevel = 'CLEAN';
  if (findings.length > 0) {
    const maxCvss = Math.max(...findings.map(f => typeof f.cvss === 'number' ? f.cvss : 0), 0);
    if ((counts.CRITICAL || 0) > 0) {
      peakScore = Math.max(90, Math.round((maxCvss || 9.5) * 10));
      peakLevel = 'CRITICAL';
    } else if ((counts.HIGH || 0) > 0) {
      peakScore = Math.max(70, Math.round((maxCvss || 8.0) * 10));
      peakLevel = 'HIGH';
    } else if ((counts.MEDIUM || 0) > 0) {
      peakScore = Math.max(40, Math.round((maxCvss || 5.0) * 10));
      peakLevel = 'MODERATE';
    } else if ((counts.LOW || 0) > 0) {
      peakScore = Math.max(15, Math.round((maxCvss || 2.5) * 10));
      peakLevel = 'LOW';
    } else {
      peakScore = 10;
      peakLevel = 'INFO';
    }
    peakScore = Math.min(100, peakScore);
  }

  const degradedFiles = (result.files || []).filter(f => {
    const tiers = f.tiers || {};
    return Object.values(tiers).some(st => {
      const code = String(st).split(':')[0].trim();
      return !['ok', 'disabled', 'not routed', 'not_routed', 'completed', 'syntax_skipped'].includes(code);
    });
  });

  const findingsTabHtml = `
    ${(result.degraded && degradedFiles.length) ? `<div class="banner warn" style="margin-bottom:18px">
      <b>Analysis Coverage Note:</b> ${degradedFiles.length} file(s) encountered a local tier limitation (e.g., syntax or timeout), while remaining tiers completed and guarded results.</div>` : ''}

    <div class="metrics">
      <div class="metric ${findings.length ? 'high' : 'ok'}">
        <div class="metric-value">${findings.length}</div>
        <div class="metric-label">Findings</div>
        <div class="metric-sub">${(result.files || []).length} file(s) affected</div></div>
      <div class="metric crit"><div class="metric-value">${counts.CRITICAL || 0}</div>
        <div class="metric-label">Critical</div>
        <div class="metric-sub">${counts.HIGH || 0} high</div></div>
      <div class="metric ok"><div class="metric-value">${sources.confirmed || 0}</div>
        <div class="metric-label">Confirmed</div>
        <div class="metric-sub">by both engines independently</div></div>
      <div class="metric"><div class="metric-value">${stats.total_seconds ?? '—'}s</div>
        <div class="metric-label">Duration</div>
        <div class="metric-sub">${stats.files_sent_to_llm ?? 0} file(s) to the LLM</div></div>
    </div>

    ${stats.verified_candidates ? `<div class="card">
      <div class="card-title">Verification agent</div>
      <div class="row" style="gap:26px">
        <div><div class="metric-value" style="font-size:21px">${stats.verify_confirmed || 0}</div>
          <div class="metric-label">Upheld</div></div>
        <div><div class="metric-value" style="font-size:21px">${stats.verify_refuted || 0}</div>
          <div class="metric-label">Refuted</div></div>
        <div><div class="metric-value" style="font-size:21px">${stats.verify_uncertain || 0}</div>
          <div class="metric-label">Uncertain</div></div>
        <div><div class="metric-value" style="font-size:21px">${stats.verify_tool_calls || 0}</div>
          <div class="metric-label">Tool calls</div></div>
      </div>
      <p class="muted" style="margin-top:12px">The agent read the surrounding code and tried to
        refute each candidate. Refuted findings were removed; a refutation without a named
        mitigating control is downgraded to uncertain and the finding kept.</p>
    </div>` : ''}

    <div class="grid-2">
      <div class="card"><div class="card-title">Threat level</div>
        ${riskGauge(peakScore, 100, peakLevel)}
        <div style="margin-top:20px">${severityStack(counts)}</div></div>
      <div class="card"><div class="card-title">Files</div>
        ${bars((result.files || []).filter(f => f.findings)
          .sort((a, b) => b.findings - a.findings).slice(0, 10)
          .map(f => ({ name: f.file, count: f.findings })), 'name', 'count')}</div>
    </div>

    ${(result.chains || []).length ? `<div class="card">
      <div class="card-title">Attack chains</div>
      ${result.chains.map(chainCard).join('')}</div>` : ''}

    <div class="card">
      <div class="row" style="margin-bottom:12px;align-items:baseline">
        <div class="card-title" style="margin:0">Findings</div>
        <div class="spacer"></div>
        <span id="findings-counter-badge" class="filter-status-text">Showing ${totalFindings} of ${totalFindings} findings</span>
      </div>

      <div class="findings-toolbar">
        <div class="search-wrap">
          <svg class="search-svg-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <input type="text" id="finding-search-input" class="search-input" placeholder="Search by file, type, CWE, line, description..." autocomplete="off">
          <button type="button" id="finding-search-clear" class="search-clear-btn hide" onclick="clearFindingSearch()" title="Clear search">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        <div class="filter-pills" id="finding-filter-pills">
          <button type="button" class="filter-pill active" data-filter="all" onclick="setFindingFilter('all')">
            All <span class="pill-count">${totalFindings}</span>
          </button>
          <button type="button" class="filter-pill" data-filter="confirmed" onclick="setFindingFilter('confirmed')">
            <span class="dot-indicator green"></span> Confirmed <span class="pill-count">${countConfirmed}</span>
          </button>
          <button type="button" class="filter-pill" data-filter="verified" onclick="setFindingFilter('verified')">
            <span class="dot-indicator teal"></span> Agent-Verified <span class="pill-count">${countVerified}</span>
          </button>
          <button type="button" class="filter-pill" data-filter="llm" onclick="setFindingFilter('llm')">
            <span class="dot-indicator purple"></span> LLM-only <span class="pill-count">${countLlm}</span>
          </button>
          <button type="button" class="filter-pill" data-filter="rule" onclick="setFindingFilter('rule')">
            <span class="dot-indicator slate"></span> Rule-only <span class="pill-count">${countRule}</span>
          </button>
        </div>

        <div class="filter-select-wrap">
          <select id="finding-severity-select" onchange="applyFindingsFilter()">
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
      </div>

      <div id="findings-list">
        ${findings.length ? findings.map(f => findingCard(f, job.id)).join('')
          : emptyState('No vulnerabilities found', (result && (result.status === 'failed' || result.degraded)) ? 'Scan completed with degraded coverage or failed engine.' : 'Scanned scope came back clean.')}
      </div>
    </div>`;

  const benchmarkTabHtml = isBenchSupported ? renderBenchmarkTabContent(job) : '';

  body.innerHTML = `
    <div id="job-tab-findings-content" class="${currentJobDetailTab === 'findings' ? '' : 'hide'}">
      ${findingsTabHtml}
    </div>
    <div id="job-tab-benchmark-content" class="${currentJobDetailTab === 'benchmark' ? '' : 'hide'}">
      ${benchmarkTabHtml}
    </div>`;

  const searchInput = body.querySelector('#finding-search-input');
  if (searchInput) {
    searchInput.oninput = () => applyFindingsFilter();
  }

  body.querySelectorAll('.f-head').forEach(head => head.onclick = () =>
    head.nextElementSibling.classList.toggle('hide'));

  body.querySelectorAll('[data-copy]').forEach(btn => btn.onclick = async e => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(decodeURIComponent(btn.dataset.copy));
      const was = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = was; }, 1400);
    } catch (err) {
      btn.textContent = 'Copy failed';
    }
  });
}

/* Findings already merged, shown while verification is still running. */
function partialResults(job) {
  const result = job.result;
  const found = (result && result.findings) || [];
  if (!found.length) return '';

  const counts = result.counts || {};
  const sorted = [...found].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  return `
    <div class="card">
      <div class="card-title">Found so far &mdash; scan still running</div>
      ${severityStack(counts)}
      <div style="margin-top:16px">${sorted.map(f => findingCard(f, job.id)).join('')}</div>
      <p class="muted" style="margin-top:12px">
        These are merged results. The verification agent may still remove some
        of them, and later phases may add more.</p>
    </div>`;
}

function progressCard(job) {
  const current = PHASES.findIndex(([key]) => key === job.phase);
  return `
    <div class="card">
      <div class="row" style="margin-bottom:12px">
        <span class="spinner"></span>
        <b>${esc(job.message || 'Working')}</b>
        <div class="spacer"></div>
        <span style="font-variant-numeric:tabular-nums;font-weight:650">${Math.round(job.percent)}%</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill live" style="width:${job.percent}%"></div>
      </div>
      <div class="phases">
        ${PHASES.map(([key, label], i) => {
          const done = current > i;
          const active = key === job.phase;
          const note = phaseNote(job, key);
          return `<span class="phase ${active ? 'active' : (done ? 'done' : '')}">
            ${done ? `<svg class="svg-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:-1px"><polyline points="20 6 9 17 4 12"></polyline></svg>` : (active ? '●' : '○')} ${label}
            ${note ? `<br><span style="opacity:.75">${esc(note)}</span>` : ''}
          </span>`;
        }).join('')}
      </div>
      <div class="log" id="log">
        <div><span class="t"></span><span class="cursor"></span></div>
        ${(job.events || []).slice(-40).reverse()
          .map(e => `<div><span class="t">${Math.round(e.percent)}%</span>${esc(e.message)}</div>`)
          .join('')}
      </div>
      <p class="muted" style="margin-top:12px">
        This page is safe to reload or close — the scan keeps running and this view
        reconnects to it.</p>
    </div>`;
}

/* Pull the headline number each finished phase reported, so the strip shows
   what happened rather than only how far along the scan is. */
function phaseNote(job, phase) {
  const events = (job.events || []).filter(e => e.phase === phase);
  if (!events.length) return '';
  const last = events[events.length - 1];
  if (phase === 'discovery' && last.files_discovered) return `${last.files_discovered} files`;
  if (phase === 'rules' && last.rule_findings !== undefined) return `${last.rule_findings} found`;
  if (phase === 'llm' && last.total) return `${last.current || 0}/${last.total}`;
  if (phase === 'fusion' && last.findings !== undefined) return `${last.findings} merged`;
  if (phase === 'verify' && last.total) {
    return `${last.current || 0}/${last.total}` +
      (last.refuted ? ` · ${last.refuted} cut` : '');
  }
  if (phase === 'done' && last.findings !== undefined) return `${last.findings} findings`;
  return '';
}

function findingCard(f, jobId = '') {
  const verified = f.verification && f.verification.verdict === 'confirmed';
  const assessmentStatus = f.assessment_status || (f.assessment && f.assessment.status);
  const corroborated = f.corroborated || (f.provenance && f.provenance.corroborated);
  const isConfirmed = f.source === 'confirmed' || corroborated;
  const isLlm = f.source === 'llm-only' || f.source === 'llm';
  const isRule = f.source === 'rule-only' || f.source === 'semgrep';

  const searchText = [
    f.file, f.type, f.cwe, f.severity, f.source, f.description, f.impact, f.remediation, f.start_line, f.end_line,
    ...(f.taint_path || []).map(s => `${s.kind} ${s.step} ${s.symbol} ${s.file} ${s.line}`)
  ].join(' ').toLowerCase();

  return `
    <div class="finding ${esc(f.severity)}"
         data-severity="${esc(f.severity)}"
         data-source="${esc(f.source)}"
         data-confirmed="${isConfirmed ? 'true' : 'false'}"
         data-verified="${verified ? 'true' : 'false'}"
         data-llm="${isLlm ? 'true' : 'false'}"
         data-rule="${isRule ? 'true' : 'false'}"
         data-search="${esc(searchText)}">
      <div class="f-head">
        <span class="pill ${esc(f.severity)}">${esc(f.severity)}</span>
        <span class="f-type">${esc(f.type)}</span>
        <span class="tag ${esc(f.source)}">${esc(f.source)} ${f.confidence}</span>
        ${corroborated ? '<span class="tag corroborated">corroborated</span>' : ''}
        ${assessmentStatus ? `<span class="tag assessment-${esc(assessmentStatus)}">${esc(assessmentStatus)}</span>` : ''}
        ${verified ? '<span class="tag verified">agent-verified</span>' : ''}
        ${f.cwe ? `<span class="tag">${esc(f.cwe)}</span>` : ''}
        <span class="f-loc">${esc(f.file)}:${f.start_line}</span>
      </div>
      <div class="f-body hide">
        ${f.description ? `<div>${esc(f.description)}</div>` : ''}
        ${f.impact ? `<h4>Impact</h4><div>${esc(f.impact)}</div>` : ''}
        ${f.remediation ? `<h4>Fix</h4><div>${esc(f.remediation)}</div>` : ''}
        ${f.assessment ? `
          <h4>Assessment Audit</h4>
          <div><b>Status:</b> ${esc(f.assessment.status || assessmentStatus)}</div>
          ${f.assessment.reason ? `<div><b>Reason:</b> ${esc(f.assessment.reason)}</div>` : ''}
          ${f.assessment.mitigating_control ? `<div><b>Mitigating Control:</b> ${esc(f.assessment.mitigating_control)}</div>` : ''}
          ${(f.assessment.evidence_ids || []).length ? `<div><b>Evidence IDs:</b> ${esc(f.assessment.evidence_ids.join(', '))}</div>` : ''}
        ` : ''}
        ${(f.taint_path || []).length ? `
          <div class="taint-header">
            <h4>Traced dataflow</h4>
            <span class="taint-hint">Click any step to inspect source code line</span>
          </div>
          <div class="taint">
            ${f.taint_path.map((s, idx) => {
              const stepFile = s.file || f.file || '';
              const stepLine = s.line || f.start_line || 1;
              const stepKind = (s.kind || 'step').toLowerCase();
              const stepDesc = s.description || s.step || s.symbol || '';
              const embeddedCode = s.code || '';
              return `
                <div class="taint-step-wrapper">
                  <div class="taint-step clickable" onclick="toggleTaintStepCode(this)"
                       data-file="${esc(stepFile)}"
                       data-line="${stepLine}"
                       data-job-id="${esc(jobId)}">
                    <span class="taint-kind ${esc(stepKind)}">${esc(stepKind)}</span>
                    <span class="taint-desc">${esc(stepDesc)}</span>
                    <span class="taint-loc">
                      ${esc(stepFile)}:${stepLine}
                      <span class="taint-code-badge">Code ▾</span>
                    </span>
                  </div>
                  <div class="taint-step-code-box hide">
                    ${embeddedCode ? `<pre class="taint-code-view"><code>${esc(embeddedCode)}</code></pre>` : `<div class="taint-code-loading"><span class="spinner"></span>Loading code...</div>`}
                  </div>
                </div>`;
            }).join('')}
          </div>` : ''}
        ${f.verification && f.verification.reason ? `
          <h4>Verification</h4>
          <div><b>${esc(f.verification.verdict)}</b> — ${esc(f.verification.reason)}</div>` : ''}
        ${f.snippet ? `<h4>Code</h4><pre>${esc(f.snippet)}</pre>` : ''}
        ${fixBlock(f)}
      </div>
    </div>`;
}

/* Suggested fix. Shown as a diff rather than a bare block of replacement
   code, because what matters is what changes - and the safety verdict says
   whether it is a clean substitution or something that needs reading. */
function fixBlock(f) {
  const fix = f.fix;
  if (!fix) return '';

  const safe = fix.risk === 'safe';
  const diff = (fix.diff || '').split('\n').filter(l =>
    l.trim() && !l.startsWith('---') && !l.startsWith('+++') && !l.startsWith('@@'));

  return `
    <h4>Suggested fix
      <span class="tag ${safe ? 'confirmed' : 'llm-only'}" style="margin-left:8px">
        ${safe ? 'clean substitution' : 'needs review'}</span></h4>
    ${fix.risk_reasons.length ? `<ul class="fix-warn">
      ${fix.risk_reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
    ${diff.length ? `<pre class="diff">${diff.map(l => {
      const cls = l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : '';
      return `<span class="${cls}">${esc(l)}</span>`;
    }).join('\n')}</pre>` : `<pre>${esc(fix.replacement)}</pre>`}
    <div class="row" style="margin-top:10px">
      <button class="btn ghost sm" data-copy="${encodeURIComponent(fix.replacement)}">
        Copy fix</button>
      <span class="muted">Apply with <b>vulnagent fix</b> to get validation and rollback.</span>
    </div>`;
}

/* ---------------- findings search & filtering ---------------- */

let currentFindingFilter = 'all';

function setFindingFilter(filterName) {
  currentFindingFilter = filterName;
  document.querySelectorAll('#finding-filter-pills .filter-pill').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filterName);
  });
  applyFindingsFilter();
}

function clearFindingSearch() {
  const input = document.getElementById('finding-search-input');
  if (input) {
    input.value = '';
    applyFindingsFilter();
  }
}

function applyFindingsFilter() {
  const searchInput = document.getElementById('finding-search-input');
  const clearBtn = document.getElementById('finding-search-clear');
  const sevSelect = document.getElementById('finding-severity-select');
  const counterBadge = document.getElementById('findings-counter-badge');
  const container = document.getElementById('findings-list');
  if (!container) return;

  const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
  if (clearBtn) clearBtn.classList.toggle('hide', !query);

  const selectedSev = sevSelect ? sevSelect.value : 'all';
  const cards = container.querySelectorAll('.finding');
  let visibleCount = 0;

  cards.forEach(card => {
    const sev = card.dataset.severity;
    const isConfirmed = card.dataset.confirmed === 'true';
    const isVerified = card.dataset.verified === 'true';
    const isLlm = card.dataset.llm === 'true';
    const isRule = card.dataset.rule === 'true';
    const searchText = card.dataset.search || '';

    // Check filter pill
    let matchesPill = true;
    if (currentFindingFilter === 'confirmed') matchesPill = isConfirmed;
    else if (currentFindingFilter === 'verified') matchesPill = isVerified;
    else if (currentFindingFilter === 'llm') matchesPill = isLlm;
    else if (currentFindingFilter === 'rule') matchesPill = isRule;

    // Check severity
    let matchesSev = true;
    if (selectedSev !== 'all') matchesSev = (sev === selectedSev);

    // Check search query
    let matchesSearch = true;
    if (query) {
      matchesSearch = searchText.includes(query);
    }

    const show = matchesPill && matchesSev && matchesSearch;
    card.classList.toggle('hide', !show);
    if (show) visibleCount++;
  });

  if (counterBadge) {
    counterBadge.textContent = `Showing ${visibleCount} of ${cards.length} findings`;
  }
}

/* ---------------- interactive taint step code viewer ---------------- */

async function toggleTaintStepCode(stepEl) {
  const wrapper = stepEl.closest('.taint-step-wrapper');
  if (!wrapper) return;
  const box = wrapper.querySelector('.taint-step-code-box');
  const badge = stepEl.querySelector('.taint-code-badge');
  if (!box) return;

  const isHidden = box.classList.contains('hide');
  if (isHidden) {
    box.classList.remove('hide');
    if (badge) badge.textContent = 'Code ▴';
    const pre = box.querySelector('pre');
    if (!pre) {
      const file = stepEl.dataset.file || '';
      const line = stepEl.dataset.line || '1';
      const jobId = stepEl.dataset.jobId || '';
      try {
        const res = await api(`/api/file_context?file=${encodeURIComponent(file)}&line=${line}&job_id=${encodeURIComponent(jobId)}`);
        if (res && res.code) {
          box.innerHTML = `<pre class="taint-code-view"><code>${esc(res.code)}</code></pre>`;
        } else {
          box.innerHTML = `<div class="taint-code-err">Line ${line} not available in local workspace</div>`;
        }
      } catch (err) {
        box.innerHTML = `<div class="taint-code-err">Could not load code for ${esc(file)}:${line}</div>`;
      }
    }
  } else {
    box.classList.add('hide');
    if (badge) badge.textContent = 'Code ▾';
  }
}

const chainCard = c => `
  <div class="chain">
    <div class="row">
      <span class="pill ${esc(c.severity)}">${esc(c.severity)}</span>
      <span class="muted">likelihood ${c.likelihood} · priority ${c.mitigation_priority}</span>
    </div>
    <div class="chain-steps">
      ${c.steps.map(s => `<span class="chain-step">${esc(s.type)}
        <span class="muted">L${s.line}</span></span>`).join('<span class="arrow">→</span>')}
    </div>
  </div>`;

/* ---------------- live updates ---------------- */

function stopFollowing() {
  if (liveStream) { liveStream.close(); liveStream = null; }
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function follow(id) {
  stopFollowing();

  const refresh = async () => {
    const job = await api(`/api/jobs/${id}`);
    paintJob(job);
    if (job.status !== 'running' && job.status !== 'queued') stopFollowing();
  };

  liveStream = new EventSource(`/api/jobs/${id}/events`);
  let lastPhase = null;
  liveStream.onmessage = event => {
    const update = JSON.parse(event.data);

    // Cheap path: move the bar and the message in place.
    const bar = document.querySelector('.progress-fill');
    if (bar) {
      bar.style.width = update.percent + '%';
      const row = view.querySelector('#job-body .row b');
      if (row) row.textContent = update.message || 'Working';
      const pct = view.querySelector('#job-body .row span[style*="tabular-nums"]');
      if (pct) pct.textContent = Math.round(update.percent) + '%';
    }

    // Update job title live if AI renamed it automatically
    if (update.label) {
      const headerTitle = document.getElementById('job-title-header');
      if (headerTitle && headerTitle.textContent !== update.label) {
        headerTitle.textContent = update.label;
      }
    }

    // A phase boundary changes the log, the phase strip and possibly the
    // partial results, so re-fetch rather than patching each piece.
    if (update.phase !== lastPhase) {
      lastPhase = update.phase;
      refresh().catch(() => {});
    }

    if (update.status !== 'running' && update.status !== 'queued') {
      stopFollowing();
      refresh().catch(() => {});
    }
  };
  // A dropped stream must not strand the page on a stale bar, so a slow poll
  // runs alongside it and takes over if the stream dies.
  liveStream.onerror = () => {
    if (liveStream) { liveStream.close(); liveStream = null; }
    if (!pollTimer) pollTimer = setInterval(() => refresh().catch(() => {}), 3000);
  };
  pollTimer = setInterval(() => refresh().catch(() => {}), 6000);
}

/* ---------------- job management, rename & deletion ---------------- */

let currentRenameJobId = null;

function openRenameModal(jobId, currentLabel, e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  currentRenameJobId = jobId;
  closeRenameModal();

  const modalHtml = `
    <div class="modal-backdrop" id="rename-modal" onclick="onModalBackdropClick(event)">
      <div class="modal-card">
        <div class="modal-head">
          <h3>Rename Scan</h3>
          <button type="button" class="modal-close" onclick="closeRenameModal()">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
          </button>
        </div>
        <div class="modal-body">
          <label class="field" style="font-weight:700">Scan Label</label>
          <div style="margin-bottom:14px">
            <input type="text" id="rename-input" value="${esc(currentLabel)}" placeholder="Enter scan title..." autocomplete="off">
          </div>
          <div class="row" style="align-items:center;gap:10px">
            <button type="button" class="btn ghost sm" id="modal-ai-btn" onclick="aiSuggestInModal('${esc(jobId)}')">
              <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"></path></svg> Auto-Generate with AI
            </button>
            <span id="modal-ai-status" class="muted"></span>
          </div>
          <p class="muted" style="margin-top:10px">
            Click <b>Auto-Generate with AI</b> to automatically generate a concise, professional title based on the scanned files and discovered defects.
          </p>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn ghost sm" onclick="closeRenameModal()">Cancel</button>
          <button type="button" class="btn sm" id="modal-save-btn" onclick="saveRenameFromModal('${esc(jobId)}')">Save Title</button>
        </div>
      </div>
    </div>`;

  document.body.insertAdjacentHTML('beforeend', modalHtml);
  const input = document.getElementById('rename-input');
  if (input) {
    input.focus();
    input.select();
    input.onkeydown = (ev) => {
      if (ev.key === 'Enter') saveRenameFromModal(jobId);
      else if (ev.key === 'Escape') closeRenameModal();
    };
  }
}

function closeRenameModal() {
  const modal = document.getElementById('rename-modal');
  if (modal) modal.remove();
  currentRenameJobId = null;
}

function onModalBackdropClick(e) {
  if (e.target && e.target.id === 'rename-modal') {
    closeRenameModal();
  }
}

async function aiSuggestInModal(jobId) {
  const aiBtn = document.getElementById('modal-ai-btn');
  const statusEl = document.getElementById('modal-ai-status');
  const input = document.getElementById('rename-input');
  if (!input) return;

  if (aiBtn) aiBtn.disabled = true;
  if (statusEl) statusEl.innerHTML = '<span class="spinner"></span>Analyzing code with AI...';

  try {
    const res = await api(`/api/jobs/${jobId}/suggest_name`, { method: 'POST' });
    if (res && res.suggested_label) {
      input.value = res.suggested_label;
      if (statusEl) statusEl.innerHTML = '<span style="color:var(--low)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Title generated</span>';
    } else {
      if (statusEl) statusEl.innerHTML = '<span style="color:var(--crit)">Could not generate title</span>';
    }
  } catch (err) {
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--crit)">Error: ${esc(err.message)}</span>`;
  } finally {
    if (aiBtn) aiBtn.disabled = false;
  }
}

async function saveRenameFromModal(jobId) {
  const input = document.getElementById('rename-input');
  const saveBtn = document.getElementById('modal-save-btn');
  if (!input) return;

  const newLabel = input.value.trim();
  if (!newLabel) {
    alert('Please enter a valid title.');
    return;
  }

  if (saveBtn) saveBtn.disabled = true;

  try {
    await api(`/api/jobs/${jobId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: newLabel })
    });
    closeRenameModal();

    const headerTitle = document.getElementById('job-title-header');
    if (headerTitle) {
      headerTitle.textContent = newLabel;
    }
    if (location.hash === '#/jobs' || location.hash === '#/' || location.hash === '') {
      route();
    }
  } catch (err) {
    alert('Failed to save title: ' + err.message);
    if (saveBtn) saveBtn.disabled = false;
  }
}

async function aiAutoNameAndSave(jobId) {
  const btn = document.getElementById('detail-ai-name-btn');
  const wasText = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Naming with AI...';
  }

  try {
    const res = await api(`/api/jobs/${jobId}/suggest_name`, { method: 'POST' });
    if (res && res.suggested_label) {
      await api(`/api/jobs/${jobId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: res.suggested_label })
      });
      const headerTitle = document.getElementById('job-title-header');
      if (headerTitle) {
        headerTitle.textContent = res.suggested_label;
      }
      if (btn) btn.innerHTML = '<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Renamed!';
      setTimeout(() => { if (btn) { btn.innerHTML = wasText; btn.disabled = false; } }, 1500);
    }
  } catch (err) {
    alert('AI naming failed: ' + err.message);
    if (btn) { btn.innerHTML = wasText; btn.disabled = false; }
  }
}

async function deleteJob(id, e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  if (!confirm('Are you sure you want to delete this scan from the system?')) return;
  try {
    await api(`/api/jobs/${id}`, { method: 'DELETE' });
    if (location.hash.startsWith('#/job/')) {
      location.hash = '#/jobs';
    } else {
      await renderJobs();
    }
  } catch (err) {
    alert('Failed to delete scan: ' + err.message);
  }
}

async function clearAllJobs() {
  if (!confirm('WARNING: Are you sure you want to clear ALL scan history? This action cannot be undone.')) return;
  try {
    await api('/api/jobs/clear', { method: 'POST' });
    await renderJobs();
  } catch (err) {
    alert('Failed to clear scans: ' + err.message);
  }
}

/* ---------------- settings view & model profiles ---------------- */

let cachedModelProfiles = [];

async function renderSettings() {
  view.innerHTML = `
    <div class="page-head">
      <div class="row" style="align-items:flex-start">
        <div style="min-width:0;flex:1">
          <h1>AI Model Profiles &amp; Settings</h1>
          <p>Pre-configured models saved in the system. Edit any profile below or add new model endpoints.</p>
        </div>
        <button type="button" class="btn sm" onclick="openModelProfileModal()">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg> Add Model Profile
        </button>
      </div>
    </div>
    <div class="empty"><span class="spinner"></span>Loading configuration...</div>`;

  let currentSettings = {
    openai_base_url: 'http://127.0.0.1:20128/v1',
    openai_model: 'oc/glm-5.3-flash-free',
    openai_api_key: '',
    masked_api_key: '',
    is_configured: false
  };

  let modelsList = [];
  try {
    const [resSet, resMod] = await Promise.all([
      api('/api/settings'),
      api('/api/models')
    ]);
    if (resSet) currentSettings = resSet;
    if (resMod && resMod.models) {
      modelsList = resMod.models;
      cachedModelProfiles = modelsList;
    }
  } catch (e) {
    // fallback
  }

  const modelRowsHtml = modelsList.map(p => {
    return `
      <div class="card" style="margin-bottom:10px;padding:12px 16px;background:var(--raised);box-shadow:none">
        <div class="row" style="align-items:center">
          <div style="min-width:0;flex:1">
            <div class="row" style="align-items:center;gap:8px">
              <span style="font-weight:700;font-size:14.5px;color:var(--text)">${esc(p.name)}</span>
              ${p.is_default ? `<span class="bench-status-badge perfect" style="font-size:10.5px">Active Default</span>` : ''}
            </div>
            <div class="muted" style="margin-top:4px;font-size:12px">
              Model: <code>${esc(p.model)}</code> · Endpoint: <code>${esc(p.base_url)}</code> · Key: <code>${esc(p.masked_api_key || 'none')}</code>
            </div>
          </div>
          <div class="row" style="gap:6px;flex-shrink:0">
            ${!p.is_default ? `<button type="button" class="btn ghost sm" onclick="setActiveDefaultProfile('${esc(p.id)}')">Set Default</button>` : ''}
            <button type="button" class="btn ghost sm" id="test-prof-btn-${esc(p.id)}" onclick="testSingleProfile('${esc(p.id)}')">Test</button>
            <button type="button" class="btn ghost sm" onclick="openModelProfileModal('${esc(p.id)}')" title="Edit profile">
              <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg> Edit
            </button>
            <button type="button" class="btn ghost sm danger" onclick="deleteSingleProfile('${esc(p.id)}')" title="Delete profile">
              <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>
        </div>
        <div id="test-status-${esc(p.id)}" class="muted" style="margin-top:4px"></div>
      </div>`;
  }).join('');

  view.innerHTML = `
    <div class="page-head">
      <div class="row" style="align-items:flex-start">
        <div style="min-width:0;flex:1">
          <h1>AI Model Profiles &amp; Settings</h1>
          <p>Pre-configured models saved in the system. Edit any profile below or add new model endpoints.</p>
        </div>
        <button type="button" class="btn sm" onclick="openModelProfileModal()">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg> Add Model Profile
        </button>
      </div>
    </div>

    <!-- Saved Profiles Section -->
    <div class="card" style="margin-bottom:24px">
      <div class="row" style="margin-bottom:14px;align-items:center">
        <div>
          <div class="card-title" style="margin:0">Configured Model Profiles (${modelsList.length})</div>
          <p class="muted" style="margin-top:3px">Saved models available in the New Scan dropdown. Edit or customize any profile.</p>
        </div>
      </div>
      <div>
        ${modelRowsHtml || '<div class="muted">No model profiles configured yet. Click Add Model Profile above.</div>'}
      </div>
    </div>

    <!-- Direct Fallback Settings Card -->
    <div class="card" style="max-width:760px">
      <div class="card-title">Default Inference Endpoint (.env)</div>
      <div id="settings-banner"></div>

      <div style="margin-bottom:20px">
        <label class="field" style="font-weight:700">OpenAI-Compatible Base URL</label>
        <input type="text" id="setting-url" value="${esc(currentSettings.openai_base_url || '')}" placeholder="http://127.0.0.1:20128/v1">
        <p class="muted" style="margin-top:6px">
          Primary server endpoint (9Router, local Ollama, vLLM, or official OpenAI API).
        </p>
      </div>

      <div style="margin-bottom:20px">
        <label class="field" style="font-weight:700">Model Identifier</label>
        <input type="text" id="setting-model" value="${esc(currentSettings.openai_model || '')}" placeholder="oc/glm-5.3-flash-free">
        <p class="muted" style="margin-top:6px">
          Model ID string (e.g. <code>oc/glm-5.3-flash-free</code>, <code>cmc/reflection/beam:free</code>, <code>ollama/gemma4</code>).
        </p>
      </div>

      <div style="margin-bottom:24px">
        <label class="field" style="font-weight:700">API Key</label>
        <div class="password-wrap">
          <input type="password" id="setting-key" value="${esc(currentSettings.openai_api_key || '')}" placeholder="sk-..." autocomplete="off">
          <button type="button" class="password-toggle-btn" id="toggle-key-btn" onclick="toggleKeyVisibility()">Show</button>
        </div>
        <p class="muted" style="margin-top:6px">
          API key is masked by default as a password field for security during presentations.
        </p>
      </div>

      <div class="row" style="gap:12px;align-items:center">
        <button class="btn" id="save-settings-btn" onclick="saveSettings()">Save Configuration</button>
        <button class="btn ghost" id="test-settings-btn" onclick="testConnection()">Test Connection</button>
        <div class="spacer"></div>
        <span id="settings-status" class="muted"></span>
      </div>
    </div>`;
}

function openModelProfileModal(profileId) {
  closeModelProfileModal();
  let existing = null;
  if (profileId) {
    existing = cachedModelProfiles.find(p => p.id === profileId);
  }

  const isEdit = !!existing;
  const nameVal = isEdit ? existing.name : '';
  const modelVal = isEdit ? existing.model : '';
  const urlVal = isEdit ? existing.base_url : 'http://127.0.0.1:20128/v1';
  const keyVal = isEdit ? (existing.api_key || '') : 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
  const isDef = isEdit ? existing.is_default : false;

  const modalHtml = `
    <div class="modal-backdrop" id="model-profile-modal" onclick="onModelModalBackdropClick(event)">
      <div class="modal-card">
        <div class="modal-head">
          <h3>${isEdit ? 'Edit Model Profile' : 'Add New Model Profile'}</h3>
          <button type="button" class="modal-close" onclick="closeModelProfileModal()">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
          </button>
        </div>
        <div class="modal-body">
          <div style="margin-bottom:14px">
            <label class="field" style="font-weight:700">Profile Display Name</label>
            <input type="text" id="modal-prof-name" value="${esc(nameVal)}" placeholder="e.g. GLM-5.3 Flash (Zhipu Free)" autocomplete="off">
          </div>
          <div style="margin-bottom:14px">
            <label class="field" style="font-weight:700">Model Identifier</label>
            <input type="text" id="modal-prof-model" value="${esc(modelVal)}" placeholder="e.g. oc/glm-5.3-flash-free" autocomplete="off">
          </div>
          <div style="margin-bottom:14px">
            <label class="field" style="font-weight:700">OpenAI-Compatible Base URL</label>
            <input type="text" id="modal-prof-url" value="${esc(urlVal)}" placeholder="http://127.0.0.1:20128/v1" autocomplete="off">
          </div>
          <div style="margin-bottom:14px">
            <label class="field" style="font-weight:700">API Key</label>
            <div class="password-wrap">
              <input type="password" id="modal-prof-key" value="${esc(keyVal)}" placeholder="sk-..." autocomplete="off">
              <button type="button" class="password-toggle-btn" onclick="toggleModalKeyVisibility()">Show</button>
            </div>
          </div>
          <div style="margin-bottom:16px">
            <label class="check">
              <input type="checkbox" id="modal-prof-default" ${isDef ? 'checked' : ''}>
              Set as active default model
            </label>
          </div>
          <div class="row" style="gap:8px;align-items:center">
            <button type="button" class="btn ghost sm" id="modal-prof-test-btn" onclick="testModalProfileConnection()">
              Test Connection
            </button>
            <span id="modal-prof-status" class="muted"></span>
          </div>
        </div>
        <div class="modal-foot">
          <button type="button" class="btn ghost sm" onclick="closeModelProfileModal()">Cancel</button>
          <button type="button" class="btn sm" id="modal-prof-save-btn" onclick="saveModelProfile('${esc(profileId || '')}')">Save Profile</button>
        </div>
      </div>
    </div>`;

  document.body.insertAdjacentHTML('beforeend', modalHtml);
  const nameInput = document.getElementById('modal-prof-name');
  if (nameInput) nameInput.focus();
}

function closeModelProfileModal() {
  const modal = document.getElementById('model-profile-modal');
  if (modal) modal.remove();
}

function onModelModalBackdropClick(e) {
  if (e.target && e.target.id === 'model-profile-modal') {
    closeModelProfileModal();
  }
}

function toggleModalKeyVisibility() {
  const input = document.getElementById('modal-prof-key');
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}

async function testModalProfileConnection() {
  const btn = document.getElementById('modal-prof-test-btn');
  const statusEl = document.getElementById('modal-prof-status');
  const url = document.getElementById('modal-prof-url')?.value.trim();
  const model = document.getElementById('modal-prof-model')?.value.trim();
  const key = document.getElementById('modal-prof-key')?.value.trim();

  if (!url || !model) {
    if (statusEl) statusEl.innerHTML = '<span style="color:var(--crit)">Please enter URL and Model ID</span>';
    return;
  }

  if (btn) btn.disabled = true;
  if (statusEl) statusEl.innerHTML = '<span class="spinner"></span>Testing...';

  try {
    const res = await api('/api/settings/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ openai_base_url: url, openai_model: model, openai_api_key: key })
    });
    if (res.status === 'ok') {
      statusEl.innerHTML = `<span style="color:var(--low)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Connected (${res.latency_sec}s)</span>`;
    } else {
      statusEl.innerHTML = `<span style="color:var(--crit)">${esc(res.message)}</span>`;
    }
  } catch (err) {
    statusEl.innerHTML = `<span style="color:var(--crit)">Failed: ${esc(err.message)}</span>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function saveModelProfile(existingId) {
  const name = document.getElementById('modal-prof-name')?.value.trim();
  const model = document.getElementById('modal-prof-model')?.value.trim();
  const url = document.getElementById('modal-prof-url')?.value.trim();
  const key = document.getElementById('modal-prof-key')?.value.trim();
  const isDefault = document.getElementById('modal-prof-default')?.checked;

  if (!name || !model || !url) {
    alert('Please enter Profile Name, Model Identifier, and Base URL.');
    return;
  }

  try {
    if (existingId) {
      await api(`/api/models/${existingId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, model, base_url: url, api_key: key, is_default: isDefault })
      });
    } else {
      await api('/api/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, model, base_url: url, api_key: key, is_default: isDefault })
      });
    }
    closeModelProfileModal();
    await renderSettings();
  } catch (err) {
    alert('Failed to save model profile: ' + err.message);
  }
}

async function testSingleProfile(profileId) {
  const btn = document.getElementById(`test-prof-btn-${profileId}`);
  const statusEl = document.getElementById(`test-status-${profileId}`);
  const p = cachedModelProfiles.find(x => x.id === profileId);
  if (!p) return;

  if (btn) btn.disabled = true;
  if (statusEl) statusEl.innerHTML = '<span class="spinner"></span>Testing connection...';

  try {
    const res = await api('/api/settings/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ openai_base_url: p.base_url, openai_model: p.model, openai_api_key: p.api_key || '' })
    });
    if (res.status === 'ok') {
      statusEl.innerHTML = `<span style="color:var(--low)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Connected (${res.latency_sec}s): "${esc(res.reply)}"</span>`;
    } else {
      statusEl.innerHTML = `<span style="color:var(--crit)">${esc(res.message)}</span>`;
    }
  } catch (err) {
    statusEl.innerHTML = `<span style="color:var(--crit)">Connection error: ${esc(err.message)}</span>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function setActiveDefaultProfile(profileId) {
  try {
    await api(`/api/models/${profileId}/activate`, { method: 'POST' });
    await renderSettings();
  } catch (err) {
    alert('Failed to activate model: ' + err.message);
  }
}

async function deleteSingleProfile(profileId) {
  if (!confirm('Are you sure you want to delete this model profile?')) return;
  try {
    await api(`/api/models/${profileId}`, { method: 'DELETE' });
    await renderSettings();
  } catch (err) {
    alert('Failed to delete model profile: ' + err.message);
  }
}

function toggleKeyVisibility() {
  const input = document.getElementById('setting-key');
  const btn = document.getElementById('toggle-key-btn');
  if (!input || !btn) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = 'Hide';
  } else {
    input.type = 'password';
    btn.textContent = 'Show';
  }
}

function applyPreset(preset) {
  const urlEl = document.getElementById('setting-url');
  const modelEl = document.getElementById('setting-model');
  const keyEl = document.getElementById('setting-key');
  if (!urlEl || !modelEl) return;

  if (preset === '9router') {
    urlEl.value = 'http://127.0.0.1:20128/v1';
    modelEl.value = 'cmc/reflection/beam:free';
    if (!keyEl.value || keyEl.value.trim() === '') {
      keyEl.value = 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
    }
  } else if (preset === 'solar') {
    urlEl.value = 'http://127.0.0.1:20128/v1';
    modelEl.value = 'nous/upstage/solar-mini4:free';
    if (!keyEl.value || keyEl.value.trim() === '') {
      keyEl.value = 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
    }
  } else if (preset === 'glm53') {
    urlEl.value = 'http://localhost:8080/v1';
    modelEl.value = 'glm-5.3';
    keyEl.value = 'your-proxy-secret';
  } else if (preset === 'glm53flash') {
    urlEl.value = 'http://localhost:8080/v1';
    modelEl.value = 'glm-5.3-flash';
    keyEl.value = 'your-proxy-secret';
  } else if (preset === 'glm53flash9r') {
    urlEl.value = 'http://127.0.0.1:20128/v1';
    modelEl.value = 'oc/glm-5.3-flash-free';
    if (!keyEl.value || keyEl.value.trim() === '') {
      keyEl.value = 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
    }
  } else if (preset === 'deepseek') {
    urlEl.value = 'http://127.0.0.1:20128/v1';
    modelEl.value = 'oc/deepseek-v4.1-flash-free';
    if (!keyEl.value || keyEl.value.trim() === '') {
      keyEl.value = 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
    }
  } else if (preset === 'ollama') {
    urlEl.value = 'http://127.0.0.1:20128/v1';
    modelEl.value = 'ollama/gemma4';
    if (!keyEl.value || keyEl.value.trim() === '') {
      keyEl.value = 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
    }
  } else if (preset === 'luna') {
    urlEl.value = 'http://127.0.0.1:20128/v1';
    modelEl.value = 'cx/gpt-5.6-luna';
    if (!keyEl.value || keyEl.value.trim() === '') {
      keyEl.value = 'sk-d8d38c4dbe7182c6-5wpch9-c84f2f0a';
    }
  }
}

async function saveSettings() {
  const saveBtn = document.getElementById('save-settings-btn');
  const statusEl = document.getElementById('settings-status');
  const banner = document.getElementById('settings-banner');
  const url = document.getElementById('setting-url').value.trim();
  const model = document.getElementById('setting-model').value.trim();
  const key = document.getElementById('setting-key').value.trim();

  saveBtn.disabled = true;
  statusEl.innerHTML = '<span class="spinner"></span>Saving...';

  try {
    await api('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        openai_base_url: url,
        openai_model: model,
        openai_api_key: key
      })
    });
    statusEl.innerHTML = '<span style="color:var(--low)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Saved successfully</span>';
    banner.innerHTML = `<div class="banner" style="background:rgba(16,185,129,0.1);border-color:var(--low);color:var(--text);margin-bottom:16px">
      <b>Configuration saved!</b> Active model: <code>${esc(model)}</code> (Endpoint: <code>${esc(url)}</code>)
    </div>`;
    await checkHealth();
  } catch (err) {
    statusEl.innerHTML = `<span style="color:var(--crit)">Error: ${esc(err.message)}</span>`;
  } finally {
    saveBtn.disabled = false;
  }
}

async function testConnection() {
  const testBtn = document.getElementById('test-settings-btn');
  const statusEl = document.getElementById('settings-status');
  const url = document.getElementById('setting-url').value.trim();
  const model = document.getElementById('setting-model').value.trim();
  const key = document.getElementById('setting-key').value.trim();

  testBtn.disabled = true;
  statusEl.innerHTML = '<span class="spinner"></span>Testing connection...';

  try {
    const res = await api('/api/settings/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        openai_base_url: url,
        openai_model: model,
        openai_api_key: key
      })
    });
    if (res.status === 'ok') {
      statusEl.innerHTML = `<span style="color:var(--low)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> ${esc(res.message)}</span>`;
    } else {
      statusEl.innerHTML = `<span style="color:var(--crit)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> ${esc(res.message)}</span>`;
    }
  } catch (err) {
    statusEl.innerHTML = `<span style="color:var(--crit)"><svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> Connection failed: ${esc(err.message)}</span>`;
  } finally {
    testBtn.disabled = false;
  }
}

/* ---------------- benchmark evaluation view & center ---------------- */

function renderBenchmarkTabContent(job) {
  const bench = job.benchmark_evaluation;
  if (!bench || !bench.supported) {
    return `<div class="banner info">Automatic benchmark evaluation is only supported for benchmark100 and benchmark1000 datasets.</div>`;
  }

  const m = bench.metrics || {};
  const perCwe = bench.per_cwe || {};
  const totalGroundTruth = bench.total_ground_truth || 0;
  const tp = m.tp || 0;
  const fp = m.fp || 0;
  const fn = m.fn || 0;
  const prec = (m.precision * 100).toFixed(1);
  const rec = (m.recall * 100).toFixed(1);
  const f1 = (m.f1 || 0).toFixed(4);

  const totalDetections = tp + fp + fn || 1;
  const tpPct = ((tp / totalDetections) * 100).toFixed(1);
  const fpPct = ((fp / totalDetections) * 100).toFixed(1);
  const fnPct = ((fn / totalDetections) * 100).toFixed(1);

  const cweRows = Object.values(perCwe).sort((a, b) => b.total - a.total).map(row => {
    const rate = ((row.recall || 0) * 100).toFixed(1);
    const badgeClass = row.recall >= 1.0 ? 'perfect' : (row.recall > 0 ? 'partial' : 'zero');
    const badgeText = row.recall >= 1.0 ? '100% Detected' : (row.recall > 0 ? `${rate}% Partial` : '0% Missed');
    return `
      <tr>
        <td style="font-weight:700"><code>${esc(row.cwe)}</code></td>
        <td>${esc((row.types || []).join(', ') || row.cwe)}</td>
        <td style="font-weight:700">${row.total}</td>
        <td style="color:var(--low);font-weight:700">${row.tp}</td>
        <td style="color:${row.fn > 0 ? 'var(--crit)' : 'var(--text-faint)'}">${row.fn}</td>
        <td style="font-weight:700;font-variant-numeric:tabular-nums">${rate}%</td>
        <td><span class="bench-status-badge ${badgeClass}">${badgeText}</span></td>
      </tr>`;
  }).join('');

  const spuriousItems = (bench.spurious || []).slice(0, 30).map(s => `<li><code>${esc(s)}</code></li>`).join('');
  const missedItems = (bench.missed || []).slice(0, 30).map(m => `<li><code>${esc(m)}</code></li>`).join('');

  return `
    <div class="bench-header-box">
      <div class="row" style="align-items:flex-start">
        <div style="min-width:0;flex:1">
          <div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:4px">
            <svg class="svg-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> Automated Ground-Truth Benchmark Evaluation
          </div>
          <p class="muted" style="margin:0">
            Dataset: <b>${esc(bench.dataset_name)}</b> (<code>${esc(bench.dataset_key)}</code>) ·
            Ground-Truth Labels: <b>${totalGroundTruth}</b> · Evaluated via bipartite sink-matching (&plusmn;3 lines tolerance, CWE equivalence classes).
          </p>
        </div>
        <div class="row" style="gap:8px">
          <button type="button" class="btn ghost sm" onclick="copyBenchmarkMarkdown('${esc(job.id)}')">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy Thesis Markdown Table
          </button>
        </div>
      </div>
    </div>

    <div class="bench-grid">
      <div class="bench-metric-card good">
        <div class="bench-metric-val">${prec}%</div>
        <div class="bench-metric-label">Precision</div>
        <div class="bench-metric-sub">True Positives / All Findings</div>
      </div>
      <div class="bench-metric-card good">
        <div class="bench-metric-val">${rec}%</div>
        <div class="bench-metric-label">Recall (Coverage)</div>
        <div class="bench-metric-sub">Captured ${tp} of ${totalGroundTruth} actual defects</div>
      </div>
      <div class="bench-metric-card neutral">
        <div class="bench-metric-val">${f1}</div>
        <div class="bench-metric-label">F1-Score</div>
        <div class="bench-metric-sub">Harmonic mean of P &amp; R</div>
      </div>
      <div class="bench-metric-card warn">
        <div class="bench-metric-val">${tp} / ${fp} / ${fn}</div>
        <div class="bench-metric-label">TP / FP / FN</div>
        <div class="bench-metric-sub">Clean-file FP: ${m.fp_on_clean_files || 0}</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Detection Accuracy Distribution</div>
      <div class="bench-bar-track">
        <div class="bench-bar-seg bench-bar-tp" style="width:${tpPct}%" title="True Positives: ${tp} (${tpPct}%)">
          ${tp > 0 ? `TP: ${tp}` : ''}
        </div>
        <div class="bench-bar-seg bench-bar-fp" style="width:${fpPct}%" title="False Positives: ${fp} (${fpPct}%)">
          ${fp > 0 ? `FP: ${fp}` : ''}
        </div>
        <div class="bench-bar-seg bench-bar-fn" style="width:${fnPct}%" title="False Negatives: ${fn} (${fnPct}%)">
          ${fn > 0 ? `FN: ${fn}` : ''}
        </div>
      </div>
      <div class="row muted" style="justify-content:space-between;font-size:11.5px">
        <span style="color:var(--low)">■ True Positives: <b>${tp}</b> (${tpPct}%)</span>
        <span style="color:var(--crit)">■ False Positives: <b>${fp}</b> (${fpPct}%)</span>
        <span style="color:var(--text-faint)">■ False Negatives (Missed): <b>${fn}</b> (${fnPct}%)</span>
      </div>
    </div>

    <div class="card">
      <div class="row" style="margin-bottom:8px">
        <div class="card-title" style="margin:0">Defect Breakdown by CWE Category</div>
        <div class="spacer"></div>
        <span class="muted">${Object.keys(perCwe).length} categories evaluated</span>
      </div>
      <div class="bench-table-wrap">
        <table class="bench-table">
          <thead>
            <tr>
              <th>CWE ID</th>
              <th>Vulnerability Category</th>
              <th>Ground Truth</th>
              <th>Detected (TP)</th>
              <th>Missed (FN)</th>
              <th>Recall Rate</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${cweRows || '<tr><td colspan="7" class="muted" style="text-align:center">No CWE breakdown data.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-title">False Positives (Spurious Findings: ${fp})</div>
        <p class="muted">Detections that did not match any ground-truth labeled defect:</p>
        ${spuriousItems ? `<ul style="max-height:220px;overflow-y:auto;padding-left:20px;font-size:12px">${spuriousItems}</ul>` : `<div class="muted">Zero false positives recorded!</div>`}
      </div>
      <div class="card">
        <div class="card-title">False Negatives (Missed Defects: ${fn})</div>
        <p class="muted">Ground-truth vulnerabilities not captured in this run:</p>
        ${missedItems ? `<ul style="max-height:220px;overflow-y:auto;padding-left:20px;font-size:12px">${missedItems}</ul>` : `<div class="muted" style="color:var(--low)">100% of ground-truth defects were captured!</div>`}
      </div>
    </div>`;
}

async function copyBenchmarkMarkdown(jobId) {
  try {
    const res = await api(`/api/jobs/${jobId}/benchmark`);
    if (!res || !res.supported) {
      alert('Benchmark evaluation not available for this job.');
      return;
    }
    const m = res.metrics || {};
    let md = `### Quantitative Benchmark Evaluation Report (${res.dataset_key})\n\n`;
    md += `| Metric | Score | Note |\n`;
    md += `| :--- | :--- | :--- |\n`;
    md += `| **Precision** | **${(m.precision * 100).toFixed(2)}%** | True Positives / Total Alarms |\n`;
    md += `| **Recall** | **${(m.recall * 100).toFixed(2)}%** | Captured ${m.tp} / ${res.total_ground_truth} Ground-Truth Defects |\n`;
    md += `| **F1-Score** | **${m.f1.toFixed(4)}** | Harmonic Mean |\n`;
    md += `| **True Positives (TP)** | **${m.tp}** | Confirmed correct detections |\n`;
    md += `| **False Positives (FP)** | **${m.fp}** | Spurious findings (Clean-file FP: ${m.fp_on_clean_files || 0}) |\n`;
    md += `| **False Negatives (FN)** | **${m.fn}** | Missed ground-truth defects |\n\n`;

    md += `#### Per-CWE Vulnerability Breakdown\n\n`;
    md += `| CWE ID | Category Name | Ground Truth | Detected (TP) | Missed (FN) | Recall Rate |\n`;
    md += `| :--- | :--- | :---: | :---: | :---: | :---: |\n`;
    for (const [cwe, r] of Object.entries(res.per_cwe || {})) {
      md += `| ${cwe} | ${(r.types || []).join(', ')} | ${r.total} | ${r.tp} | ${r.fn} | ${((r.recall || 0) * 100).toFixed(1)}% |\n`;
    }

    await navigator.clipboard.writeText(md);
    alert('Benchmark Markdown summary copied to clipboard! You can paste it directly into Chapter 4 of your thesis.');
  } catch (err) {
    alert('Copy failed: ' + err.message);
  }
}

let cachedBenchmarkAggregations = {};

function toggleSuiteMatrix(datasetKey) {
  const container = document.getElementById(`matrix-container-${datasetKey}`);
  const btn = document.getElementById(`btn-toggle-matrix-${datasetKey}`);
  if (!container) return;
  const isHidden = container.classList.contains('hide');
  if (isHidden) {
    container.classList.remove('hide');
    if (btn) btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"></polyline></svg> Hide Comparative Matrix ▴`;
  } else {
    container.classList.add('hide');
    const count = (cachedBenchmarkAggregations[datasetKey]?.runs || []).length;
    if (btn) btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> View Comparative Matrix (${count} runs) ▾`;
  }
}

function renderBenchmarkSuiteAggregation(agg, datasetKey) {
  if (!agg || !agg.runs || !agg.runs.length) {
    return `<div class="card muted" style="margin-bottom:24px">No completed runs found for <code>${esc(datasetKey)}</code> yet. Run a scan targeting this benchmark to generate comparative metrics.</div>`;
  }

  const runs = agg.runs;
  const cweMatrix = agg.cwe_matrix || [];
  const bestRunId = agg.best_run_id;

  const summaryRows = runs.map(r => {
    const m = r.metrics || {};
    const prec = (m.precision * 100).toFixed(1);
    const rec = (m.recall * 100).toFixed(1);
    const f1 = (m.f1 || 0).toFixed(4);
    const isBest = r.id === bestRunId && runs.length > 1;

    return `
      <tr style="${isBest ? 'background:rgba(78,148,120,0.08)' : ''}">
        <td class="wrap-cell">
          <div style="font-weight:700">
            <a href="#/job/${esc(r.id)}/benchmark" style="color:var(--text);text-decoration:none">${esc(r.label)}</a>
            ${isBest ? `<span class="bench-status-badge perfect" style="margin-left:6px;font-size:10px">Best F1</span>` : ''}
          </div>
          <div class="muted" style="font-size:11px">${ago(r.finished_at || r.created_at)} · ID: <code>${esc(r.id)}</code></div>
        </td>
        <td style="font-weight:700;text-align:center">${r.findings_count}</td>
        <td style="color:var(--low);font-weight:700;text-align:center">${m.tp}</td>
        <td style="color:${m.fp > 0 ? 'var(--crit)' : 'var(--text-faint)'};font-weight:700;text-align:center">${m.fp}</td>
        <td style="color:${m.fn > 0 ? 'var(--text-dim)' : 'var(--text-faint)'};text-align:center">${m.fn}</td>
        <td style="font-variant-numeric:tabular-nums;font-weight:700;text-align:center">${prec}%</td>
        <td style="font-variant-numeric:tabular-nums;font-weight:700;text-align:center">${rec}%</td>
        <td style="font-variant-numeric:tabular-nums;font-weight:700;color:var(--signal);text-align:center">${f1}</td>
        <td style="color:${m.fp_on_clean_files > 0 ? 'var(--high)' : 'var(--text-faint)'};text-align:center">${m.fp_on_clean_files || 0}</td>
        <td style="text-align:center">
          <a class="btn ghost sm" href="#/job/${esc(r.id)}/benchmark" style="padding:4px 9px">
            View <svg class="svg-icon" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:2px;margin-right:0"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </a>
        </td>
      </tr>`;
  }).join('');

  const cweMatrixRows = cweMatrix.map(row => {
    const scanCells = runs.map(r => {
      const sc = (row.scans || {})[r.id] || {};
      const tp = sc.tp || 0;
      const rec = ((sc.recall || 0) * 100).toFixed(1);
      const badgeCls = sc.recall >= 1.0 ? 'perfect' : (sc.recall > 0 ? 'partial' : 'zero');
      return `
        <td style="text-align:center">
          <span class="bench-status-badge ${badgeCls}" title="${tp} of ${row.total} detected">
            ${tp}/${row.total} (${rec}%)
          </span>
        </td>`;
    }).join('');

    return `
      <tr>
        <td style="font-weight:700"><code>${esc(row.cwe)}</code></td>
        <td class="wrap-cell">${esc(row.category)}</td>
        <td style="font-weight:700;text-align:center">${row.total}</td>
        ${scanCells}
      </tr>`;
  }).join('');

  return `
    <div class="card" style="margin-bottom:30px">
      <div class="row" style="margin-bottom:14px;align-items:flex-start">
        <div style="min-width:0;flex:1">
          <h2 style="font-size:18px;font-weight:700;margin:0;color:var(--text)">
            ${esc(agg.dataset_name)}
          </h2>
          <p class="muted" style="margin-top:4px;font-size:12px">
            Suite: <code>${esc(datasetKey)}</code> · <b>${agg.total_ground_truth}</b> Ground-Truth Defects · <b>${runs.length}</b> Comparative Scan Run(s) Grouped
          </p>
        </div>
        <div class="row" style="gap:8px">
          <button type="button" class="btn sm" id="btn-toggle-matrix-${esc(datasetKey)}" onclick="toggleSuiteMatrix('${esc(datasetKey)}')">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span>View Comparative Matrix (${runs.length} runs) ▾</span>
          </button>
        </div>
      </div>

      <!-- Collapsible Comparative Matrix Container (Hidden by Default) -->
      <div id="matrix-container-${esc(datasetKey)}" class="hide" style="margin-top:16px;border-top:var(--border) solid var(--edge);padding-top:16px">
        <div class="row" style="margin-bottom:12px;gap:8px">
          <button type="button" class="btn ghost sm" onclick="copySuiteMarkdown('${esc(datasetKey)}')">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy Markdown Table
          </button>
          <button type="button" class="btn ghost sm" onclick="exportSuiteCSV('${esc(datasetKey)}')">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Export CSV
          </button>
        </div>

        <div class="bench-table-wrap">
          <table class="bench-table">
            <thead>
              <tr>
                <th class="wrap-cell">Configuration / Model</th>
                <th style="text-align:center">Findings</th>
                <th style="color:var(--low);text-align:center">TP</th>
                <th style="color:var(--crit);text-align:center">FP</th>
                <th style="text-align:center">FN</th>
                <th style="text-align:center">Precision</th>
                <th style="text-align:center">Recall</th>
                <th style="text-align:center">F1-Score</th>
                <th style="text-align:center">Clean FP</th>
                <th style="text-align:center">Action</th>
              </tr>
            </thead>
            <tbody>
              ${summaryRows}
            </tbody>
          </table>
        </div>

        ${cweMatrix.length && runs.length > 0 ? `
        <div style="margin-top:24px">
          <div class="row" style="margin-bottom:8px">
            <div class="card-title" style="margin:0">Head-to-Head Per-CWE Recall Comparison Matrix</div>
            <div class="spacer"></div>
            <span class="muted" style="font-size:11.5px">${cweMatrix.length} CWE categories mapped</span>
          </div>
          <div class="bench-table-wrap">
            <table class="bench-table">
              <thead>
                <tr>
                  <th style="width:90px">CWE ID</th>
                  <th class="wrap-cell">Category</th>
                  <th style="text-align:center;width:65px">Total</th>
                  ${runs.map(r => `<th style="text-align:center">${esc(r.label.split(' · ')[1] || r.label)}</th>`).join('')}
                </tr>
              </thead>
              <tbody>
                ${cweMatrixRows}
              </tbody>
            </table>
          </div>
        </div>` : ''}
      </div>
    </div>`;
}

async function copySuiteMarkdown(datasetKey) {
  const agg = cachedBenchmarkAggregations[datasetKey];
  if (!agg || !agg.runs || !agg.runs.length) {
    alert('No benchmark aggregation data available for ' + datasetKey);
    return;
  }

  let md = `### Benchmark Comparative Summary: ${agg.dataset_name} (${agg.total_ground_truth} Ground-Truth Defects)\n\n`;
  md += `| Configuration / Scan Run | Findings | TP | FP | FN | Precision | Recall | F1-Score | Clean-File FP |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
  for (const r of agg.runs) {
    const m = r.metrics || {};
    md += `| **${r.label}** | ${r.findings_count} | ${m.tp} | ${m.fp} | ${m.fn} | ${(m.precision * 100).toFixed(2)}% | ${(m.recall * 100).toFixed(2)}% | **${(m.f1 || 0).toFixed(4)}** | ${m.fp_on_clean_files || 0} |\n`;
  }

  if (agg.cwe_matrix && agg.cwe_matrix.length) {
    md += `\n#### Head-to-Head Per-CWE Recall Comparison Matrix\n\n`;
    const runHeaders = agg.runs.map(r => r.label.split(' · ')[1] || r.label).join(' | ');
    md += `| CWE ID | Vulnerability Category | Ground Truth | ${runHeaders} |\n`;
    md += `| :--- | :--- | :---: | ${agg.runs.map(() => ':---:').join(' | ')} |\n`;
    for (const row of agg.cwe_matrix) {
      const runCols = agg.runs.map(r => {
        const sc = (row.scans || {})[r.id] || {};
        const tp = sc.tp || 0;
        const rec = ((sc.recall || 0) * 100).toFixed(1);
        return `${tp}/${row.total} (${rec}%)`;
      }).join(' | ');
      md += `| ${row.cwe} | ${row.category} | ${row.total} | ${runCols} |\n`;
    }
  }

  try {
    await navigator.clipboard.writeText(md);
    alert('Benchmark comparative Markdown tables copied to clipboard! You can paste them directly into Chapter 4 of your thesis.');
  } catch (err) {
    alert('Copy failed: ' + err.message);
  }
}

function exportSuiteCSV(datasetKey) {
  const agg = cachedBenchmarkAggregations[datasetKey];
  if (!agg || !agg.runs || !agg.runs.length) {
    alert('No benchmark data to export for ' + datasetKey);
    return;
  }
  let csv = "Scan_Label,Dataset,Findings,True_Positives,False_Positives,False_Negatives,Precision,Recall,F1_Score,Clean_File_FP\n";
  for (const r of agg.runs) {
    const m = r.metrics || {};
    csv += `"${r.label.replace(/"/g, '""')}","${agg.dataset_key}",${r.findings_count},${m.tp},${m.fp},${m.fn},${m.precision},${m.recall},${m.f1},${m.fp_on_clean_files || 0}\n`;
  }
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `benchmark_${datasetKey}_comparison.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

async function renderBenchmarkCenter() {
  view.innerHTML = `
    <div class="page-head">
      <h1><svg class="svg-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> Benchmark Evaluation Center</h1>
      <p>Automated ground-truth scoring and aggregated comparative matrices for <b>benchmark100</b> and <b>benchmark1000</b>.</p>
    </div>
    <div class="empty"><span class="spinner"></span>Loading benchmark evaluations...</div>`;

  let benchJobs = [];
  let aggregations = {};
  try {
    const res = await api('/api/benchmarks');
    if (res) {
      benchJobs = res.benchmark_jobs || [];
      aggregations = res.aggregations || {};
      cachedBenchmarkAggregations = aggregations;
    }
  } catch (err) {
    view.innerHTML = `<div class="banner err">Failed to load benchmark evaluations: ${esc(err.message)}</div>`;
    return;
  }

  const b100Agg = aggregations.benchmark100 || { dataset_key: 'benchmark100', dataset_name: 'OWASP Benchmark 100 Selected Suite', total_ground_truth: 50, runs: [] };
  const b1000Agg = aggregations.benchmark1000 || { dataset_key: 'benchmark1000', dataset_name: 'OWASP Benchmark 1000 Full Suite', total_ground_truth: 452, runs: [] };

  view.innerHTML = `
    <div class="page-head">
      <h1><svg class="svg-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> Benchmark Evaluation Center</h1>
      <p>Automated ground-truth scoring and aggregated comparative matrices for <b>benchmark100</b> and <b>benchmark1000</b>.</p>
    </div>

    <div class="card" style="margin-bottom:22px;background:var(--raised)">
      <div style="font-weight:700;margin-bottom:4px">Strict Benchmark Dataset Scope &amp; Run Aggregation</div>
      <p class="muted" style="margin:0">
        In accordance with research methodology, automated ground-truth scoring and comparative matrix aggregation are strictly applied to <b>benchmark100</b> (50 vulnerable + 50 clean testcases) and <b>benchmark1000</b> (OWASP 1,230 files). All runs targeting the same benchmark suite are aggregated together below.
      </p>
    </div>

    <div style="margin-bottom:32px">
      ${renderBenchmarkSuiteAggregation(b100Agg, 'benchmark100')}
    </div>

    <div>
      ${renderBenchmarkSuiteAggregation(b1000Agg, 'benchmark1000')}
    </div>`;
}

/* ---------------- routing ---------------- */

async function route() {
  stopFollowing();
  const hash = location.hash || '#/';
  const parts = hash.slice(2).split('/').filter(Boolean);
  const page = parts[0] || 'dashboard';

  document.querySelectorAll('.nav-item').forEach(a => {
    const target = a.dataset.route;
    a.classList.toggle('on',
      target === page || (page === '' && target === 'dashboard') ||
      (page === 'job' && target === 'jobs') ||
      (page === 'benchmark' && target === 'benchmark'));
  });

  try {
    if (page === 'scan') renderScan();
    else if (page === 'jobs') await renderJobs();
    else if (page === 'job' && parts[1]) await renderJob(parts[1], parts[2]);
    else if (page === 'benchmark') await renderBenchmarkCenter();
    else if (page === 'settings') await renderSettings();
    else await renderDashboard();
  } catch (e) {
    view.innerHTML = `<div class="banner err">${esc(e.message)}</div>`;
  }
}

async function checkHealth() {
  const el = document.getElementById('health');
  const model = document.getElementById('health-model');
  try {
    const h = await api('/health');
    el.innerHTML = `<span class="dot ${h.rule_engine ? 'up' : 'down'}"></span>` +
      `rule engine ${h.rule_engine ? 'ready' : 'missing'}`;
    model.innerHTML = `<span class="dot ${h.llm_configured ? 'up' : 'down'}"></span>` +
      esc(h.llm_configured ? h.model : 'LLM not configured');
  } catch (e) {
    el.innerHTML = '<span class="dot down"></span>server unreachable';
  }
}

/* ---------------- theme ---------------- */

const THEMES = ['dark', 'light'];

function applyTheme(name) {
  const theme = THEMES.includes(name) ? name : 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('vulnagent-theme', theme); } catch (e) { /* private mode */ }
  document.querySelectorAll('.theme-btn').forEach(b =>
    b.classList.toggle('on', b.dataset.themeName === theme));
}

function initTheme() {
  // Follow the operating system on a first visit, then respect whatever the
  // user picked here afterwards.
  const preferred = window.matchMedia
    && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  let saved = null;
  try { saved = localStorage.getItem('vulnagent-theme'); } catch (e) { /* private mode */ }
  applyTheme(saved || preferred);
  document.querySelectorAll('.theme-btn').forEach(b =>
    b.onclick = () => applyTheme(b.dataset.themeName));
}

window.addEventListener('hashchange', route);
window.addEventListener('beforeunload', stopFollowing);
initTheme();
route();
checkHealth();
setInterval(checkHealth, 30000);
