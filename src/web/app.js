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
        <button class="btn-del" title="${job.status === 'running' ? 'Stop & delete running scan' : 'Delete scan'}" onclick="deleteJob('${esc(job.id)}', event)">
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
    <option value="oc/glm-5.3-flash-free" selected>GLM-5.3 Flash</option>
    <option value="cmc/reflection/beam:free">Beam Free</option>
    <option value="oc/deepseek-v4.1-flash-free">DeepSeek V4.1 Flash</option>
    <option value="nous/upstage/solar-mini4:free">Solar Mini</option>
    <option value="ollama/gemma4">Gemma4</option>
    <option value="cx/gpt-5.6-luna">gpt-5.6-luna</option>
  `;

  try {
    const res = await api('/api/models');
    if (res && res.models && res.models.length) {
      modelOptionsHtml = res.models.map(p => `<option value="${esc(p.model)}" ${p.is_default ? 'selected' : ''}>${esc(p.name)}</option>`).join('');
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
        <button class="tab" data-pane="benchmark">Sample Benchmark</button>
      </div>

      <div id="pane-folder">
        <div class="dropzone" id="drop">
          <div class="dropzone-icon"><svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path><polyline points="12 11 12 17"></polyline><polyline points="9 14 12 11 15 14"></polyline></svg></div>
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

      <div id="pane-benchmark" class="hide">
        <div style="font-weight:700;font-size:15px;color:var(--text);margin-bottom:8px">
          Pre-Loaded Official Benchmark Suites
        </div>
        <p class="muted" style="margin-bottom:16px">
          Select an official OWASP benchmark testbed located on the local disk to run immediate evaluation without manual uploads.
        </p>

        <div class="grid-2" style="gap:14px;margin-bottom:16px">
          <label class="card" id="card-bench-100" style="padding:16px 18px;cursor:pointer;border:2px solid var(--signal)">
            <div class="row" style="align-items:flex-start;gap:12px">
              <input type="radio" name="bench-suite" value="benchmark100" checked style="width:18px;height:18px;margin-top:2px;accent-color:var(--signal)">
              <div style="min-width:0;flex:1">
                <div style="font-weight:700;font-size:15.5px;color:var(--text);margin-bottom:4px">
                  OWASP Benchmark 100
                </div>
                <p class="muted" style="margin:0;font-size:13px">
                  Balanced academic benchmark containing <b>100 Python testcases</b> (50 vulnerable + 50 clean files).
                  Ideal for quick evaluations (~1-3 minutes).
                </p>
                <div class="muted" style="margin-top:6px;font-size:12px">
                  Path: <code>eval/datasets/benchmark100/samples</code>
                </div>
              </div>
            </div>
          </label>

          <label class="card" id="card-bench-1000" style="padding:16px 18px;cursor:pointer;border:1px solid var(--edge)">
            <div class="row" style="align-items:flex-start;gap:12px">
              <input type="radio" name="bench-suite" value="benchmark1000" style="width:18px;height:18px;margin-top:2px;accent-color:var(--signal)">
              <div style="min-width:0;flex:1">
                <div style="font-weight:700;font-size:15.5px;color:var(--text);margin-bottom:4px">
                  OWASP Benchmark 1000
                </div>
                <p class="muted" style="margin:0;font-size:13px">
                  Full comprehensive suite containing <b>1,230 Python testcases</b> (452 vulnerable + 778 clean files).
                  Full-scale thesis audit.
                </p>
                <div class="muted" style="margin-top:6px;font-size:12px">
                  Path: <code>eval/datasets/benchmark/samples</code>
                </div>
              </div>
            </div>
          </label>
        </div>
      </div>

      <div style="margin-top:16px;margin-bottom:18px">
        <label class="field" style="font-weight:700">Scan Title (optional)</label>
        <input type="text" id="scan-custom-title" placeholder="Leave empty for standard title (e.g. source · mode by model)" autocomplete="off">
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
        <label class="check"><input type="checkbox" id="use-cache" checked> Use cache</label>
        <label style="display:inline-flex;align-items:center;gap:6px;font:500 12px/1 var(--sans);color:var(--text-dim);margin-left:4px">
          <span>Threads:</span>
          <input type="number" id="concurrency" value="4" min="1" max="50" style="width:58px;padding:6px 8px;font:600 12px/1 var(--mono);background:var(--raised);border:var(--border) solid var(--edge);border-radius:var(--radius-sm);color:var(--text);outline:none">
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
    ['folder', 'snippet', 'repo', 'benchmark'].forEach(p => {
      const el = document.getElementById('pane-' + p);
      if (el) el.classList.toggle('hide', p !== pane);
    });
  });

  const card100 = document.getElementById('card-bench-100');
  const card1000 = document.getElementById('card-bench-1000');
  document.querySelectorAll('input[name="bench-suite"]').forEach(radio => {
    radio.onchange = () => {
      const is100 = radio.value === 'benchmark100';
      if (card100) card100.style.border = is100 ? '2px solid var(--signal)' : '1px solid var(--edge)';
      if (card1000) card1000.style.border = !is100 ? '2px solid var(--signal)' : '1px solid var(--edge)';
    };
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
  const concurrency = parseInt(document.getElementById('concurrency')?.value, 10) || 4;
  const useCache = document.getElementById('use-cache') ? document.getElementById('use-cache').checked : true;
  const scanModelEl = document.getElementById('scan-model');
  const chosenModel = (mode !== 'semgrep' && scanModelEl && scanModelEl.value !== 'custom')
    ? scanModelEl.value
    : null;
  const customTitle = document.getElementById('scan-custom-title')?.value.trim() || '';

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
      form.append('use_cache', String(useCache));
      if (chosenModel) form.append('model', chosenModel);
      job = await api('/api/jobs/folder', { method: 'POST', body: form });
    } else if (pane === 'snippet') {
      const code = document.getElementById('code').value;
      if (!code.trim()) throw new Error('Paste some code first');
      job = await api('/api/jobs/snippet', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code, filename: document.getElementById('snippet-name').value || 'snippet.py',
          mode, verify, concurrency, model: chosenModel, use_cache: useCache
        })
      });
    } else if (pane === 'benchmark') {
      const suite = document.querySelector('input[name="bench-suite"]:checked')?.value || 'benchmark100';
      job = await api('/api/jobs/benchmark', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dataset: suite,
          mode,
          verify,
          concurrency,
          model: chosenModel,
          use_cache: useCache
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
          mode, verify, concurrency, model: chosenModel, use_cache: useCache
        })
      });
    }
    if (customTitle && job && job.id) {
      try {
        await api(`/api/jobs/${job.id}/rename`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label: customTitle })
        });
        job.label = customTitle;
      } catch (e) {}
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
  currentJobDetailTab = (subtab === 'benchmark' || location.hash.includes('/benchmark'))
    ? 'benchmark'
    : ((subtab === 'history' || location.hash.includes('/history')) ? 'history' : 'findings');
  paintJob(job);
  if (job.status === 'running' || job.status === 'queued') follow(id);
}

function switchJobDetailTab(tab) {
  currentJobDetailTab = tab;
  const fTab = document.getElementById('job-tab-findings-content');
  const bTab = document.getElementById('job-tab-benchmark-content');
  const hTab = document.getElementById('job-tab-history-content');
  const tabBtns = document.querySelectorAll('#job-detail-tabs .tab');

  if (fTab) fTab.classList.toggle('hide', tab !== 'findings');
  if (bTab) bTab.classList.toggle('hide', tab !== 'benchmark');
  if (hTab) hTab.classList.toggle('hide', tab !== 'history');

  tabBtns.forEach(btn => {
    btn.classList.toggle('on',
      (tab === 'findings' && btn.textContent.includes('Findings')) ||
      (tab === 'benchmark' && btn.textContent.includes('Benchmark')) ||
      (tab === 'history' && btn.textContent.includes('Run History'))
    );
  });
}

function paintJob(job) {
  const running = job.status === 'running' || job.status === 'queued';
  const result = job.result || {};

  const bench = job.benchmark_evaluation;
  const isBenchSupported = bench && bench.supported;
  const history = job.configuration_history;
  const hasHistory = history && history.has_multiple_runs;

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
        <button class="btn ghost sm danger" onclick="deleteJob('${esc(job.id)}', event)">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg> ${running ? 'Stop & Delete' : 'Delete scan'}
        </button>
        <a class="btn ghost sm" href="#/jobs">All scans</a>
      </div>
      ${(isBenchSupported || hasHistory) ? `
      <div class="tabs" id="job-detail-tabs" style="margin-top:16px;margin-bottom:0">
        <button type="button" class="tab ${currentJobDetailTab === 'findings' ? 'on' : ''}" onclick="switchJobDetailTab('findings')">
          Findings &amp; Code Analysis (${totalFindings})
        </button>
        ${isBenchSupported ? `
        <button type="button" class="tab ${currentJobDetailTab === 'benchmark' ? 'on' : ''}" onclick="switchJobDetailTab('benchmark')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> Benchmark Evaluation (${esc(bench.dataset_key)}: TP ${bench.metrics.tp}, F1 ${(bench.metrics.f1 * 100).toFixed(1)}%)
        </button>` : ''}
        ${hasHistory ? `
        <button type="button" class="tab ${currentJobDetailTab === 'history' ? 'on' : ''}" onclick="switchJobDetailTab('history')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Run History &amp; Model Variance (${history.total_runs} runs)
        </button>` : ''}
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

    ${(job.events || []).length ? `
    <div class="card">
      <div class="row" style="cursor:pointer;user-select:none" onclick="document.getElementById('job-events-log-body').classList.toggle('hide')">
        <div class="card-title" style="margin:0">
          <svg class="svg-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
          Execution Timeline &amp; Event Logs (${job.events.length} events)
        </div>
        <div class="spacer"></div>
        <span class="muted" style="font-size:12.5px">Toggle logs <svg class="svg-icon" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="margin-left:2px;margin-right:0"><polyline points="6 9 12 15 18 9"></polyline></svg></span>
      </div>
      <div id="job-events-log-body" class="hide" style="margin-top:14px">
        <div class="log" style="max-height:320px;margin-top:0">
          ${job.events.map(e => `<div><span class="t">${Math.round(e.percent)}%</span>${esc(e.message)}</div>`).join('')}
        </div>
      </div>
    </div>` : ''}

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

  const historyTabHtml = hasHistory ? renderConfigurationHistoryTabContent(job) : '';

  body.innerHTML = `
    <div id="job-tab-findings-content" class="${currentJobDetailTab === 'findings' ? '' : 'hide'}">
      ${findingsTabHtml}
    </div>
    <div id="job-tab-benchmark-content" class="${currentJobDetailTab === 'benchmark' ? '' : 'hide'}">
      ${benchmarkTabHtml}
    </div>
    ${hasHistory ? `
    <div id="job-tab-history-content" class="${currentJobDetailTab === 'history' ? '' : 'hide'}">
      ${historyTabHtml}
    </div>` : ''}`;

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
            ${done ? `<svg class="svg-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;vertical-align:-1px"><polyline points="20 6 9 17 4 12"></polyline></svg>` : (active ? `<svg class="svg-icon" width="9" height="9" viewBox="0 0 24 24" fill="var(--signal)" stroke="none" style="margin-right:4px;vertical-align:-1px"><circle cx="12" cy="12" r="10"></circle></svg>` : `<svg class="svg-icon" width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:4px;vertical-align:-1px"><circle cx="12" cy="12" r="9"></circle></svg>`)} ${label}
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
                      <span class="taint-code-badge"><svg class="svg-icon" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>Code</span>
                    </span>
                  </div>
                  <div class="taint-step-code-box hide">
                    ${embeddedCode ? `<pre class="taint-code-view"><code>${esc(embeddedCode)}</code></pre>` : `<div class="taint-code-loading"><span class="spinner"></span>Loading code...</div>`}
                  </div>
                </div>`;
            }).join('')}
          </div>` : ''}
        ${f.verification && (f.verification.reason || f.verification.error) ? `
          <h4>Verification</h4>
          <div><b>${esc(f.verification.verdict)}</b> — ${esc(f.verification.reason || 'Verification completed')}</div>
          ${f.verification.error ? `<div class="banner warn" style="margin-top:8px;font-size:12.5px;padding:8px 12px"><b>Verification error / API issue:</b> ${esc(f.verification.error)}</div>` : ''}` : ''}
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
    if (badge) badge.classList.add('active');
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
    if (badge) badge.classList.remove('active');
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
          <label class="field" style="font-weight:700">Scan Title</label>
          <div style="margin-bottom:14px">
            <input type="text" id="rename-input" value="${esc(currentLabel)}" placeholder="Enter scan title..." autocomplete="off">
          </div>
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


async function saveRenameFromModal(jobId) {
  const input = document.getElementById('rename-input');
  const saveBtn = document.getElementById('modal-save-btn');
  if (!input) return;

  const newLabel = input.value.trim();
  if (!newLabel) {
    alert('Please enter a valid title.');
    return;
  }

  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = '<span class="spinner"></span>Saving...';
  }

  let saveSuccess = false;
  try {
    await api(`/api/jobs/${jobId}/rename`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: newLabel })
    });
    saveSuccess = true;
  } catch (err1) {
    try {
      await api(`/api/jobs/${jobId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: newLabel })
      });
      saveSuccess = true;
    } catch (err2) {
      alert('Failed to save title: ' + (err2.message || err1.message));
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save Title';
      }
      return;
    }
  }

  if (saveSuccess) {
    closeRenameModal();

    if (currentLoadedJob && currentLoadedJob.id === jobId) {
      currentLoadedJob.label = newLabel;
    }

    const headerTitle = document.getElementById('job-title-header');
    if (headerTitle) {
      headerTitle.textContent = newLabel;
    }

    // Refresh memory cache so all tables and lists update immediately
    cachedBenchmarkAggregations = {};
    await route();
  }
}


async function deleteJob(id, e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const isRunning = currentLoadedJob && currentLoadedJob.id === id && (currentLoadedJob.status === 'running' || currentLoadedJob.status === 'queued');
  const confirmMsg = isRunning
    ? 'This scan is currently running. Stop background execution and delete it immediately?'
    : 'Are you sure you want to delete this scan from the system?';
  if (!confirm(confirmMsg)) return;

  stopFollowing();
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

`;
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

/* ---------------- benchmark evaluation view & center ---------------- */


function renderConfigurationHistoryTabContent(job) {
  const h = job.configuration_history;
  if (!h || !h.runs || !h.runs.length) {
    return `<div class="card muted">No history recorded for this configuration.</div>`;
  }

  const va = h.variance_analysis || {};
  const spread = va.findings_spread || {};
  const consistencyRate = va.consistency_rate_pct || 100.0;
  const hallucinationRate = va.hallucination_rate_pct || 0.0;

  const runsRows = (h.runs || []).map(r => {
    const isCurrent = r.is_current;
    const bm = r.benchmark || {};
    const hasBm = !!r.benchmark;
    return `
      <tr style="${isCurrent ? 'background:rgba(59,130,246,0.08);border-left:3px solid var(--signal);' : ''}">
        <td style="font-weight:700;text-align:center">Run #${r.run_index}</td>
        <td class="wrap-cell">
          <div style="font-weight:700">
            <a href="#/job/${esc(r.id)}" style="color:var(--text);text-decoration:none">${esc(r.label)}</a>
            ${isCurrent ? `<span class="bench-status-badge perfect" style="margin-left:6px;font-size:10px">Active View</span>` : ''}
          </div>
          <div class="muted" style="font-size:11px">${ago(r.finished_at || r.created_at)} · ID: <code>${esc(r.id)}</code></div>
        </td>
        <td style="text-align:center">
          <span class="pill ${r.status === 'done' ? 'LOW' : 'CRITICAL'}" style="font-size:9.5px">${esc(r.status)}</span>
        </td>
        <td style="font-weight:700;text-align:center">${r.findings_count}</td>
        ${hasBm ? `
          <td style="color:var(--low);font-weight:700;text-align:center">${bm.tp}</td>
          <td style="color:${bm.fp > 0 ? 'var(--crit)' : 'var(--text-faint)'};font-weight:700;text-align:center">${bm.fp}</td>
          <td style="color:${bm.fn > 0 ? 'var(--text-dim)' : 'var(--text-faint)'};text-align:center">${bm.fn}</td>
          <td style="font-variant-numeric:tabular-nums;font-weight:700;text-align:center">${(bm.precision * 100).toFixed(1)}%</td>
          <td style="font-variant-numeric:tabular-nums;font-weight:700;text-align:center">${(bm.recall * 100).toFixed(1)}%</td>
          <td style="font-variant-numeric:tabular-nums;font-weight:700;color:var(--signal);text-align:center">${(bm.f1 || 0).toFixed(4)}</td>
        ` : `
          <td colspan="6" class="muted" style="text-align:center;font-size:11px">Ad-hoc Scan (Non-benchmark)</td>
        `}
        <td style="text-align:center">
          <div class="row" style="gap:4px;justify-content:center">
            <a class="btn ghost sm" href="#/job/${esc(r.id)}" style="padding:4px 8px">View</a>
            <button class="btn-edit-label" title="Rename run" onclick="openRenameModal('${esc(r.id)}', '${esc(r.label)}', event)">
              <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
            </button>
            <button class="btn-del" title="Delete this run" onclick="deleteJob('${esc(r.id)}', event)">
              <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>
        </td>
      </tr>`;
  }).join('');

  const stableItems = (va.stable_findings || []).map(f => `
    <li style="margin-bottom:6px">
      <code>${esc(f.file)}:${f.line}</code> — <b>${esc(f.type)}</b> (<code>${esc(f.cwe)}</code>)
      <span class="bench-status-badge perfect" style="font-size:10px;margin-left:6px">100% Stable</span>
    </li>`).join('');

  const intermittentItems = (va.intermittent_findings || []).map(f => `
    <li style="margin-bottom:6px">
      <code>${esc(f.file)}:${f.line}</code> — <b>${esc(f.type)}</b> (<code>${esc(f.cwe)}</code>)
      <span class="bench-status-badge partial" style="font-size:10px;margin-left:6px">Appeared in ${f.runs_count}/${h.total_runs} runs (${f.presence_rate_pct}%)</span>
    </li>`).join('');

  return `
    <div class="bench-header-box">
      <div style="font-size:17px;font-weight:700;color:var(--text);margin-bottom:4px">
        <svg class="svg-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg> Repeat Scan History &amp; Stochastic Model Variance Analysis
      </div>
      <p class="muted" style="margin:0;font-size:13px">
        Target: <b>${esc(h.target_source)}</b> · Mode: <b>${esc(h.mode_display)}</b> · Model: <b>${esc(h.model_display)}</b> (<code>${esc(h.model_id)}</code>) ·
        <b>${h.total_runs}</b> repeat scans executed with identical configuration.
      </p>
    </div>

    <div class="bench-grid">
      <div class="bench-metric-card good">
        <div class="bench-metric-val">${consistencyRate}%</div>
        <div class="bench-metric-label">Model Consistency Rate</div>
        <div class="bench-metric-sub">${va.stable_findings_count || 0} findings reproducible across 100% of runs</div>
      </div>
      <div class="bench-metric-card ${hallucinationRate > 20 ? 'warn' : 'neutral'}">
        <div class="bench-metric-val">${hallucinationRate}%</div>
        <div class="bench-metric-label">Hallucination Variance</div>
        <div class="bench-metric-sub">${va.intermittent_findings_count || 0} fluctuating findings across runs</div>
      </div>
      <div class="bench-metric-card neutral">
        <div class="bench-metric-val">${spread.min || 0} – ${spread.max || 0}</div>
        <div class="bench-metric-label">Findings Spread</div>
        <div class="bench-metric-sub">Average: ${spread.avg || 0} (Delta: &plusmn;${spread.delta || 0})</div>
      </div>
      <div class="bench-metric-card neutral">
        <div class="bench-metric-val">${h.total_runs}</div>
        <div class="bench-metric-label">Total Repeat Runs</div>
        <div class="bench-metric-sub">Recorded in local registry</div>
      </div>
    </div>

    <div class="card" style="margin-bottom:24px">
      <div class="card-title">Comparative Performance Across Repeat Runs</div>
      <div class="bench-table-wrap">
        <table class="bench-table">
          <thead>
            <tr>
              <th style="width:70px;text-align:center">Run</th>
              <th class="wrap-cell">Scan Title &amp; ID</th>
              <th style="text-align:center;width:80px">Status</th>
              <th style="text-align:center;width:80px">Findings</th>
              <th style="color:var(--low);text-align:center">TP</th>
              <th style="color:var(--crit);text-align:center">FP</th>
              <th style="text-align:center">FN</th>
              <th style="text-align:center">Precision</th>
              <th style="text-align:center">Recall</th>
              <th style="text-align:center">F1-Score</th>
              <th style="text-align:center;width:120px">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${runsRows}
          </tbody>
        </table>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-title">Stable Findings (${va.stable_findings_count || 0})</div>
        <p class="muted" style="margin-bottom:12px">Reproducible findings detected in 100% of all repeated runs (highest reliability):</p>
        ${stableItems ? `<ul style="max-height:260px;overflow-y:auto;padding-left:18px;font-size:12.5px">${stableItems}</ul>` : `<div class="muted">No findings appeared in 100% of runs.</div>`}
      </div>
      <div class="card">
        <div class="card-title">Fluctuating / Hallucinated Findings (${va.intermittent_findings_count || 0})</div>
        <p class="muted" style="margin-bottom:12px">Findings that only appeared in a subset of runs (model stochastic variance / độ ảo):</p>
        ${intermittentItems ? `<ul style="max-height:260px;overflow-y:auto;padding-left:18px;font-size:12.5px">${intermittentItems}</ul>` : `<div class="muted" style="color:var(--low)">Zero variance recorded! All findings are 100% reproducible.</div>`}
      </div>
    </div>`;
}


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
        <span style="color:var(--low)"><svg class="svg-icon" width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:-1px;margin-right:4px"><rect width="20" height="20" rx="3"></rect></svg>True Positives: <b>${tp}</b> (${tpPct}%)</span>
        <span style="color:var(--crit)"><svg class="svg-icon" width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:-1px;margin-right:4px"><rect width="20" height="20" rx="3"></rect></svg>False Positives: <b>${fp}</b> (${fpPct}%)</span>
        <span style="color:var(--text-faint)"><svg class="svg-icon" width="9" height="9" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="vertical-align:-1px;margin-right:4px"><rect width="20" height="20" rx="3"></rect></svg>False Negatives (Missed): <b>${fn}</b> (${fnPct}%)</span>
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
let selectedBenchmarkRuns = {}; // { 'benchmark100': Set([id1, id2, ...]) }

function toggleSuiteMatrix(datasetKey) {
  const container = document.getElementById(`matrix-container-${datasetKey}`);
  const btn = document.getElementById(`btn-toggle-matrix-${datasetKey}`);
  if (!container) return;
  const isHidden = container.classList.contains('hide');
  if (isHidden) {
    container.classList.remove('hide');
    if (btn) btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"></polyline></svg> Hide Comparison Table`;
  } else {
    container.classList.add('hide');
    const selectedCount = (selectedBenchmarkRuns[datasetKey] || new Set()).size;
    const totalCount = (cachedBenchmarkAggregations[datasetKey]?.runs || []).length;
    if (btn) btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> Compare Scans (${selectedCount}/${totalCount} selected)`;
  }
}

function onBenchmarkRunToggle(datasetKey, runId, isChecked) {
  if (!selectedBenchmarkRuns[datasetKey]) {
    selectedBenchmarkRuns[datasetKey] = new Set();
  }
  if (isChecked) {
    selectedBenchmarkRuns[datasetKey].add(runId);
  } else {
    selectedBenchmarkRuns[datasetKey].delete(runId);
  }
  updateSuiteComparisonView(datasetKey);
}

function toggleSelectAllSuiteRuns(datasetKey, selectAll) {
  const agg = cachedBenchmarkAggregations[datasetKey];
  if (!agg || !agg.runs) return;
  if (!selectedBenchmarkRuns[datasetKey]) {
    selectedBenchmarkRuns[datasetKey] = new Set();
  }
  if (selectAll) {
    agg.runs.forEach(r => selectedBenchmarkRuns[datasetKey].add(r.id));
  } else {
    selectedBenchmarkRuns[datasetKey].clear();
  }
  updateSuiteComparisonView(datasetKey);
}

function selectPresetRunsFilter(datasetKey, filterType) {
  const agg = cachedBenchmarkAggregations[datasetKey];
  if (!agg || !agg.runs) return;
  selectedBenchmarkRuns[datasetKey] = new Set();
  agg.runs.forEach(r => {
    const l = (r.label || '').toLowerCase();
    if (filterType === 'deep-verify') {
      if (l.includes('deepverify') || l.includes('3tier') || l.includes('deep-verify')) {
        selectedBenchmarkRuns[datasetKey].add(r.id);
      }
    } else if (filterType === 'llm') {
      if (l.includes(' · llm') || l.includes('llm only')) {
        selectedBenchmarkRuns[datasetKey].add(r.id);
      }
    } else if (filterType === 'semgrep') {
      if (l.includes('semgrep')) {
        selectedBenchmarkRuns[datasetKey].add(r.id);
      }
    }
  });
  updateSuiteComparisonView(datasetKey);
}

function updateSuiteComparisonView(datasetKey) {
  const agg = cachedBenchmarkAggregations[datasetKey];
  if (!agg) return;
  const container = document.getElementById(`matrix-container-${datasetKey}`);
  if (!container) return;

  const contentHolder = document.getElementById(`suite-content-${datasetKey}`);
  if (contentHolder) {
    contentHolder.innerHTML = renderSuiteComparisonInner(agg, datasetKey);
  }

  // Update toggle button text if visible
  const btn = document.getElementById(`btn-toggle-matrix-${datasetKey}`);
  if (btn && container.classList.contains('hide')) {
    const selectedCount = (selectedBenchmarkRuns[datasetKey] || new Set()).size;
    btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> Compare Scans (${selectedCount}/${agg.runs.length} selected)`;
  }
}

function renderSuiteComparisonInner(agg, datasetKey) {
  const runs = agg.runs || [];
  const selectedSet = selectedBenchmarkRuns[datasetKey] || new Set();
  const selectedRuns = runs.filter(r => selectedSet.has(r.id));
  const cweMatrix = agg.cwe_matrix || [];

  const allSelected = runs.length > 0 && selectedRuns.length === runs.length;
  const bestSelectedRun = selectedRuns.length > 1
    ? [...selectedRuns].sort((a, b) => ((b.metrics?.f1 || 0) - (a.metrics?.f1 || 0)))[0]
    : null;

  const summaryRows = runs.map(r => {
    const isChecked = selectedSet.has(r.id);
    const m = r.metrics || {};
    const prec = (m.precision * 100).toFixed(1);
    const rec = (m.recall * 100).toFixed(1);
    const f1 = (m.f1 || 0).toFixed(4);
    const isBest = bestSelectedRun && r.id === bestSelectedRun.id;

    return `
      <tr style="${isChecked ? (isBest ? 'background:rgba(78,148,120,0.08);' : '') : 'opacity:0.42;'}">
        <td class="chk-col">
          <input type="checkbox" class="bench-run-check" ${isChecked ? 'checked' : ''} onchange="onBenchmarkRunToggle('${esc(datasetKey)}', '${esc(r.id)}', this.checked)">
        </td>
        <td class="wrap-cell">
          <div style="font-weight:700">
            <a href="#/job/${esc(r.id)}/benchmark" style="color:var(--text);text-decoration:none">${esc(r.label)}</a>
            ${isBest ? `<span class="bench-status-badge perfect" style="margin-left:6px;font-size:10px">Best F1</span>` : ''}
          </div>
          <div class="muted" style="font-size:11px">${ago(r.finished_at || r.created_at)} · ID: <code>${esc(r.id)}</code></div>
        </td>
        <td class="num-col" style="font-weight:700">${r.findings_count}</td>
        <td class="num-col" style="color:var(--low);font-weight:700">${m.tp}</td>
        <td class="num-col" style="color:${m.fp > 0 ? 'var(--crit)' : 'var(--text-faint)'};font-weight:700">${m.fp}</td>
        <td class="num-col" style="color:${m.fn > 0 ? 'var(--text-dim)' : 'var(--text-faint)'}">${m.fn}</td>
        <td class="num-col" style="font-weight:700">${prec}%</td>
        <td class="num-col" style="font-weight:700">${rec}%</td>
        <td class="num-col" style="font-weight:700;color:var(--signal)">${f1}</td>
        <td class="num-col" style="color:${m.fp_on_clean_files > 0 ? 'var(--high)' : 'var(--text-faint)'}">${m.fp_on_clean_files || 0}</td>
        <td class="num-col">
          <a class="btn ghost sm" href="#/job/${esc(r.id)}/benchmark" style="padding:4px 8px">
            View
          </a>
        </td>
      </tr>`;
  }).join('');

  let cweMatrixHtml = '';
  if (selectedRuns.length >= 2 && cweMatrix.length > 0) {
    const cweMatrixRows = cweMatrix.map(row => {
      const scanCells = selectedRuns.map(r => {
        const sc = (row.scans || {})[r.id] || {};
        const tp = sc.tp || 0;
        const rec = ((sc.recall || 0) * 100).toFixed(1);
        const badgeCls = sc.recall >= 1.0 ? 'perfect' : (sc.recall > 0 ? 'partial' : 'zero');
        return `
          <td class="matrix-col">
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

    // Overall recall footer row across selected runs
    const overallCols = selectedRuns.map(r => {
      const tp = r.metrics?.tp || 0;
      const gt = agg.total_ground_truth || 1;
      const pct = ((tp / gt) * 100).toFixed(1);
      return `<td class="matrix-col" style="font-weight:700;color:var(--signal)">${tp}/${gt} (${pct}%)</td>`;
    }).join('');

    cweMatrixHtml = `
      <div style="margin-top:24px">
        <div class="row" style="margin-bottom:8px">
          <div class="card-title" style="margin:0">Head-to-Head Per-CWE Recall Comparison (${selectedRuns.length} runs selected)</div>
          <div class="spacer"></div>
          <span class="muted" style="font-size:11.5px">${cweMatrix.length} CWE categories evaluated</span>
        </div>
        <div class="bench-table-wrap">
          <table class="bench-table">
            <thead>
              <tr>
                <th style="width:90px">CWE ID</th>
                <th class="wrap-cell">Vulnerability Category</th>
                <th style="text-align:center;width:65px">Total</th>
                ${selectedRuns.map(r => `<th class="matrix-col wrap-cell" style="font-weight:700">${esc(r.label.split(' · ')[1] || r.label)}</th>`).join('')}
              </tr>
            </thead>
            <tbody>
              ${cweMatrixRows}
              <tr style="background:var(--raised);font-weight:700">
                <td>OVERALL</td>
                <td class="wrap-cell">OVERALL RECALL RATE</td>
                <td style="text-align:center">${agg.total_ground_truth}</td>
                ${overallCols}
              </tr>
            </tbody>
          </table>
        </div>
      </div>`;
  } else if (selectedRuns.length === 1) {
    cweMatrixHtml = `
      <div class="banner info" style="margin-top:18px">
        Select 1 more scan run above (at least 2 runs) to display the Head-to-Head Per-CWE comparative matrix.
      </div>`;
  } else if (selectedRuns.length === 0) {
    cweMatrixHtml = `
      <div class="banner warn" style="margin-top:18px">
        No scan runs selected. Use the checkboxes above to select runs for head-to-head comparison.
      </div>`;
  }

  return `
    <div class="bench-selection-bar">
      <div class="row" style="gap:8px;align-items:center">
        <span style="font-weight:700;font-size:12.5px;color:var(--text)">
          Comparing <b>${selectedRuns.length}</b> of ${runs.length} runs
        </span>
        <button type="button" class="bench-pill-btn ${allSelected ? 'active' : ''}" onclick="toggleSelectAllSuiteRuns('${esc(datasetKey)}', true)">
          Select All
        </button>
        <button type="button" class="bench-pill-btn" onclick="selectPresetRunsFilter('${esc(datasetKey)}', 'deep-verify')">
          DeepVerify Only
        </button>
        <button type="button" class="bench-pill-btn" onclick="toggleSelectAllSuiteRuns('${esc(datasetKey)}', false)">
          Clear
        </button>
      </div>
      <div class="spacer"></div>
      <div class="row" style="gap:8px">
        <button type="button" class="btn ghost sm" onclick="copySuiteMarkdown('${esc(datasetKey)}')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy Markdown Table
        </button>
        <button type="button" class="btn ghost sm" onclick="exportSuiteCSV('${esc(datasetKey)}')">
          <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg> Export CSV
        </button>
      </div>
    </div>

    <div class="bench-table-wrap">
      <table class="bench-table">
        <thead>
          <tr>
            <th class="chk-col">
              <input type="checkbox" class="bench-run-check" ${allSelected ? 'checked' : ''} onchange="toggleSelectAllSuiteRuns('${esc(datasetKey)}', this.checked)" title="Select/Deselect All">
            </th>
            <th class="wrap-cell">Configuration / Model</th>
            <th class="num-col">Findings</th>
            <th class="num-col" style="color:var(--low)">TP</th>
            <th class="num-col" style="color:var(--crit)">FP</th>
            <th class="num-col">FN</th>
            <th class="num-col">Precision</th>
            <th class="num-col">Recall</th>
            <th class="num-col">F1-Score</th>
            <th class="num-col">Clean FP</th>
            <th class="num-col">Action</th>
          </tr>
        </thead>
        <tbody>
          ${summaryRows}
        </tbody>
      </table>
    </div>

    ${cweMatrixHtml}`;
}

function renderBenchmarkSuiteAggregation(agg, datasetKey) {
  if (!agg || !agg.runs || !agg.runs.length) {
    return `<div class="card muted" style="margin-bottom:24px">No completed runs found for <code>${esc(datasetKey)}</code> yet. Run a scan targeting this benchmark to generate comparative metrics.</div>`;
  }

  const runs = agg.runs;
  if (!selectedBenchmarkRuns[datasetKey]) {
    selectedBenchmarkRuns[datasetKey] = new Set(runs.map(r => r.id));
  }
  const selectedCount = selectedBenchmarkRuns[datasetKey].size;

  return `
    <div class="card" style="margin-bottom:30px">
      <div class="row" style="margin-bottom:14px;align-items:flex-start">
        <div style="min-width:0;flex:1">
          <h2 style="font-size:18px;font-weight:700;margin:0;color:var(--text)">
            ${esc(agg.dataset_name)}
          </h2>
          <p class="muted" style="margin-top:4px;font-size:12px">
            Suite: <code>${esc(datasetKey)}</code> · <b>${agg.total_ground_truth}</b> Ground-Truth Defects · <b>${runs.length}</b> Scan Runs Available
          </p>
        </div>
        <div class="row" style="gap:8px">
          <button type="button" class="btn sm" id="btn-toggle-matrix-${esc(datasetKey)}" onclick="toggleSuiteMatrix('${esc(datasetKey)}')">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span>Compare Scans (${selectedCount}/${runs.length} selected)</span>
          </button>
        </div>
      </div>

      <!-- Collapsible Comparative Matrix Container (Hidden by Default) -->
      <div id="matrix-container-${esc(datasetKey)}" class="hide" style="margin-top:16px;border-top:var(--border) solid var(--edge);padding-top:16px">
        <div id="suite-content-${esc(datasetKey)}">
          ${renderSuiteComparisonInner(agg, datasetKey)}
        </div>
      </div>
    </div>`;
}

async function copySuiteMarkdown(datasetKey) {
  const agg = cachedBenchmarkAggregations[datasetKey];
  if (!agg || !agg.runs || !agg.runs.length) {
    alert('No benchmark aggregation data available for ' + datasetKey);
    return;
  }

  const selectedSet = selectedBenchmarkRuns[datasetKey] || new Set(agg.runs.map(r => r.id));
  const selectedRuns = agg.runs.filter(r => selectedSet.has(r.id));
  if (!selectedRuns.length) {
    alert('Please select at least 1 scan run to copy.');
    return;
  }

  let md = `### Benchmark Comparative Summary: ${agg.dataset_name} (${agg.total_ground_truth} Ground-Truth Defects)\n\n`;
  md += `| Configuration / Scan Run | Findings | TP | FP | FN | Precision | Recall | F1-Score | Clean-File FP |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
  for (const r of selectedRuns) {
    const m = r.metrics || {};
    md += `| **${r.label}** | ${r.findings_count} | ${m.tp} | ${m.fp} | ${m.fn} | ${(m.precision * 100).toFixed(2)}% | ${(m.recall * 100).toFixed(2)}% | **${(m.f1 || 0).toFixed(4)}** | ${m.fp_on_clean_files || 0} |\n`;
  }

  if (agg.cwe_matrix && agg.cwe_matrix.length && selectedRuns.length >= 2) {
    md += `\n#### Head-to-Head Per-CWE Recall Comparison Matrix\n\n`;
    const runHeaders = selectedRuns.map(r => r.label.split(' · ')[1] || r.label).join(' | ');
    md += `| CWE ID | Vulnerability Category | Ground Truth | ${runHeaders} |\n`;
    md += `| :--- | :--- | :---: | ${selectedRuns.map(() => ':---:').join(' | ')} |\n`;
    for (const row of agg.cwe_matrix) {
      const runCols = selectedRuns.map(r => {
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
    alert(`Comparative Markdown table (${selectedRuns.length} runs) copied to clipboard! You can paste it directly into Chapter 4 of your thesis.`);
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
  const selectedSet = selectedBenchmarkRuns[datasetKey] || new Set(agg.runs.map(r => r.id));
  const selectedRuns = agg.runs.filter(r => selectedSet.has(r.id));
  if (!selectedRuns.length) {
    alert('Please select at least 1 scan run to export.');
    return;
  }
  let csv = "Scan_Label,Dataset,Findings,True_Positives,False_Positives,False_Negatives,Precision,Recall,F1_Score,Clean_File_FP\n";
  for (const r of selectedRuns) {
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

function toggleOwaspSpecTable() {
  const container = document.getElementById('owasp-spec-table-body');
  const btn = document.getElementById('btn-toggle-owasp-spec');
  if (!container) return;
  const isHidden = container.classList.contains('hide');
  if (isHidden) {
    container.classList.remove('hide');
    if (btn) btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"></polyline></svg> Hide Specifications Table`;
  } else {
    container.classList.add('hide');
    if (btn) btn.innerHTML = `<svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> View Specifications Table (14 CWEs)`;
  }
}

function renderOwaspOfficialSpecsCard() {
  const specs = [
    { cwe: 'CWE-89', name: 'SQL Injection (SQLi)', b100: 5, b1000: 5, sink: 'sqlite3.execute, cursor.execute (string formatting)' },
    { cwe: 'CWE-78', name: 'Command Injection (OS CmdI)', b100: 5, b1000: 13, sink: 'os.system, subprocess.call, popen' },
    { cwe: 'CWE-79', name: 'Cross-Site Scripting (XSS)', b100: 5, b1000: 31, sink: 'render_template_string, unescaped HTTP response' },
    { cwe: 'CWE-22', name: 'Path Traversal', b100: 5, b1000: 65, sink: 'open(), os.path.join with relative traversal' },
    { cwe: 'CWE-94', name: 'Code Injection', b100: 5, b1000: 20, sink: 'eval(), exec(), dynamic compilation' },
    { cwe: 'CWE-502', name: 'Insecure Deserialization', b100: 5, b1000: 18, sink: 'pickle.loads, yaml.load, marshal.loads' },
    { cwe: 'CWE-643', name: 'XPath Injection', b100: 5, b1000: 51, sink: 'etree.xpath, unparameterized XML queries' },
    { cwe: 'CWE-611', name: 'XML External Entity (XXE)', b100: 3, b1000: 8, sink: 'xml.etree.ElementTree, external DTD loading' },
    { cwe: 'CWE-90', name: 'LDAP Injection', b100: 0, b1000: 16, sink: 'ldap3.Connection.search, unescaped user filter' },
    { cwe: 'CWE-328', name: 'Weak Hashing Algorithm', b100: 5, b1000: 71, sink: 'hashlib.md5, hashlib.sha1' },
    { cwe: 'CWE-330', name: 'Insecure Randomness', b100: 5, b1000: 99, sink: 'random.random, random.randint in security context' },
    { cwe: 'CWE-601', name: 'Open Redirect', b100: 2, b1000: 13, sink: 'flask.redirect to unvalidated destination' },
    { cwe: 'CWE-614', name: 'Insecure Cookie', b100: 0, b1000: 24, sink: 'Set-Cookie missing Secure / HttpOnly flags' },
    { cwe: 'CWE-501', name: 'Trust Boundary Violation', b100: 0, b1000: 18, sink: 'Untrusted user input written into session context' },
    { cwe: 'Control', name: 'Clean Testcases (True Negatives / Controls)', b100: 50, b1000: 778, sink: 'Sanitized/defensive implementations (FP check)' },
  ];

  const rows = specs.map(s => `
    <tr style="${s.cwe === 'Control' ? 'background:rgba(184,194,207,0.06);font-style:italic' : ''}">
      <td style="font-weight:700"><code>${esc(s.cwe)}</code></td>
      <td class="wrap-cell" style="font-weight:600">${esc(s.name)}</td>
      <td style="text-align:center;font-weight:700;color:${s.b100 > 0 ? 'var(--text)' : 'var(--text-faint)'}">${s.b100}</td>
      <td style="text-align:center;font-weight:700;color:${s.b1000 > 0 ? 'var(--text)' : 'var(--text-faint)'}">${s.b1000}</td>
      <td class="wrap-cell muted" style="font-size:12px"><code>${esc(s.sink)}</code></td>
    </tr>`).join('');

  return `
    <div class="card" style="margin-bottom:28px">
      <div class="row" style="margin-bottom:12px;align-items:flex-start">
        <div style="min-width:0;flex:1">
          <div style="font-size:17px;font-weight:700;color:var(--text);margin-bottom:3px">
            Official OWASP Benchmark Ground-Truth Specifications
          </div>
          <p class="muted" style="margin:0;font-size:12.5px">
            Authoritative testcase distribution officially published for the OWASP BenchmarkPython 1000 corpus.
          </p>
        </div>
        <div class="row" style="gap:8px">
          <button type="button" class="btn sm" id="btn-toggle-owasp-spec" onclick="toggleOwaspSpecTable()">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span>View Specifications Table (14 CWEs)</span>
          </button>
          <button type="button" class="btn ghost sm" onclick="copyOwaspSpecMarkdown()">
            <svg class="svg-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy Specification Table
          </button>
        </div>
      </div>

      <div class="bench-grid" style="margin-bottom:18px">
        <div class="bench-metric-card neutral" style="padding:12px 16px">
          <div class="bench-metric-val" style="font-size:22px">100 / 1,230</div>
          <div class="bench-metric-label">Total Testcases</div>
          <div class="bench-metric-sub">Benchmark 100 / Benchmark 1000</div>
        </div>
        <div class="bench-metric-card good" style="padding:12px 16px">
          <div class="bench-metric-val" style="font-size:22px">50 / 452</div>
          <div class="bench-metric-label">True Positives (Vuln)</div>
          <div class="bench-metric-sub">Actual exploitable defects</div>
        </div>
        <div class="bench-metric-card warn" style="padding:12px 16px">
          <div class="bench-metric-val" style="font-size:22px">50 / 778</div>
          <div class="bench-metric-label">True Negatives (Clean)</div>
          <div class="bench-metric-sub">Clean control files for FP test</div>
        </div>
        <div class="bench-metric-card neutral" style="padding:12px 16px">
          <div class="bench-metric-val" style="font-size:22px">11 / 14</div>
          <div class="bench-metric-label">CWE Categories</div>
          <div class="bench-metric-sub">Core injection &amp; logic flaws</div>
        </div>
      </div>

      <!-- Collapsible Specifications Table Body (Hidden by default) -->
      <div id="owasp-spec-table-body" class="hide" style="margin-top:14px;border-top:var(--border) solid var(--edge);padding-top:14px">
        <div class="bench-table-wrap">
          <table class="bench-table">
            <thead>
              <tr>
                <th style="width:100px">CWE ID</th>
                <th class="wrap-cell">OWASP Vulnerability Category</th>
                <th style="text-align:center;width:130px">Benchmark 100 (TP)</th>
                <th style="text-align:center;width:140px">Benchmark 1000 (TP)</th>
                <th class="wrap-cell">Primary Sink &amp; Detection Anchor</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
              <tr style="background:var(--raised);font-weight:700">
                <td>TOTAL</td>
                <td class="wrap-cell">ALL TESTCASES (VULNERABLE + CLEAN)</td>
                <td style="text-align:center;color:var(--signal)">100 Files</td>
                <td style="text-align:center;color:var(--signal)">1,230 Files</td>
                <td class="wrap-cell muted" style="font-size:12px">Official OWASP Benchmark Ground Truth</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>`;
}

async function copyOwaspSpecMarkdown() {
  let md = `### Official OWASP Benchmark Ground-Truth Specifications\n\n`;
  md += `| CWE ID | Vulnerability Category | Benchmark 100 (TP) | Benchmark 1000 (TP) | Primary Sink & Detection Anchor |\n`;
  md += `| :--- | :--- | :---: | :---: | :--- |\n`;
  md += `| **CWE-89** | SQL Injection (SQLi) | 5 | 5 | \`sqlite3.execute\`, raw query string concatenation |\n`;
  md += `| **CWE-78** | Command Injection (OS CmdI) | 5 | 13 | \`os.system\`, \`subprocess.call\`, \`popen\` |\n`;
  md += `| **CWE-79** | Cross-Site Scripting (XSS) | 5 | 31 | \`render_template_string\`, unescaped reflected output |\n`;
  md += `| **CWE-22** | Path Traversal | 5 | 65 | \`open()\`, relative traversal resolution |\n`;
  md += `| **CWE-94** | Code Injection | 5 | 20 | \`eval()\`, \`exec()\`, dynamic compilation |\n`;
  md += `| **CWE-502** | Insecure Deserialization | 5 | 18 | \`pickle.loads\`, \`yaml.load\`, \`marshal.loads\` |\n`;
  md += `| **CWE-643** | XPath Injection | 5 | 51 | \`etree.xpath\`, unparameterized XML queries |\n`;
  md += `| **CWE-611** | XML External Entity (XXE) | 3 | 8 | \`xml.etree.ElementTree\`, external DTD resolution |\n`;
  md += `| **CWE-90** | LDAP Injection | 0 | 16 | \`ldap3.Connection.search\`, unescaped filters |\n`;
  md += `| **CWE-328** | Weak Hashing Algorithm | 5 | 71 | \`hashlib.md5\`, \`hashlib.sha1\` |\n`;
  md += `| **CWE-330** | Insecure Randomness | 5 | 99 | \`random.random\`, \`random.randint\` for secret generation |\n`;
  md += `| **CWE-601** | Open Redirect | 2 | 13 | \`flask.redirect\` to untrusted destinations |\n`;
  md += `| **CWE-614** | Insecure Cookie | 0 | 24 | \`Set-Cookie\` missing \`Secure\` or \`HttpOnly\` flag |\n`;
  md += `| **CWE-501** | Trust Boundary Violation | 0 | 18 | Untrusted input placed into trusted session context |\n`;
  md += `| *Control* | *Clean Testcases (True Negatives)* | *50* | *778* | *Sanitized/defensive implementations (FP evaluation)* |\n`;
  md += `| **TOTAL** | **ALL TESTCASES** | **100 Files** | **1,230 Files** | **Official OWASP BenchmarkPython 1000 Corpus** |\n`;

  try {
    await navigator.clipboard.writeText(md);
    alert('OWASP Benchmark specifications table copied to clipboard! You can paste it directly into Chapter 4.');
  } catch (err) {
    alert('Copy failed: ' + err.message);
  }
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

  const b100Agg = aggregations.benchmark100 || { dataset_key: 'benchmark100', dataset_name: 'OWASP BenchmarkPython 100', total_ground_truth: 50, runs: [] };
  const b1000Agg = aggregations.benchmark1000 || { dataset_key: 'benchmark1000', dataset_name: 'OWASP BenchmarkPython 1000', total_ground_truth: 452, runs: [] };

  view.innerHTML = `
    <div class="page-head">
      <h1><svg class="svg-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg> Benchmark Evaluation Center</h1>
      <p>Automated ground-truth scoring and aggregated comparative matrices for <b>benchmark100</b> and <b>benchmark1000</b>.</p>
    </div>

    ${renderOwaspOfficialSpecsCard()}

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
    const ruleColor = h.rule_engine ? 'var(--low)' : 'var(--crit)';
    const llmColor = h.llm_configured ? 'var(--low)' : 'var(--crit)';
    const cleanModelName = h.model_name || h.model || 'LLM not configured';

    if (el) {
      el.innerHTML = `
        <svg class="svg-icon" width="7" height="7" viewBox="0 0 24 24" fill="${ruleColor}" stroke="none" style="margin-right:7px;flex-shrink:0"><circle cx="12" cy="12" r="10"></circle></svg>
        <span>rule engine ${h.rule_engine ? 'ready' : 'missing'}</span>`;
    }
    if (model) {
      model.innerHTML = `
        <svg class="svg-icon" width="7" height="7" viewBox="0 0 24 24" fill="${llmColor}" stroke="none" style="margin-right:7px;flex-shrink:0"><circle cx="12" cy="12" r="10"></circle></svg>
        <span title="${esc(h.model)}">${esc(cleanModelName)}</span>`;
    }
  } catch (e) {
    if (el) el.innerHTML = '<svg class="svg-icon" width="7" height="7" viewBox="0 0 24 24" fill="var(--crit)" stroke="none" style="margin-right:7px;flex-shrink:0"><circle cx="12" cy="12" r="10"></circle></svg><span>server unreachable</span>';
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


/* ---------------- sidebar toggle ---------------- */

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const isCollapsed = sidebar.classList.toggle('collapsed');
  const btn = document.getElementById('sidebar-toggle-btn');
  if (btn) {
    btn.title = isCollapsed ? 'Expand sidebar' : 'Collapse sidebar';
  }
  try {
    localStorage.setItem('vulnagent-sidebar-collapsed', isCollapsed ? 'true' : 'false');
  } catch (e) {}
}

function initSidebar() {
  try {
    if (localStorage.getItem('vulnagent-sidebar-collapsed') === 'true') {
      const sidebar = document.getElementById('sidebar');
      if (sidebar) sidebar.classList.add('collapsed');
      const btn = document.getElementById('sidebar-toggle-btn');
      if (btn) btn.title = 'Expand sidebar';
    }
  } catch (e) {}
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
initSidebar();
initTheme();
route();
checkHealth();
setInterval(checkHealth, 30000);
