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
function riskGauge(score, max = 100) {
  const pct = Math.max(0, Math.min(1, score / max));
  const R = 62, CX = 78, CY = 78;
  const arc = Math.PI * R;            // half circle
  const band = score >= 60 ? 'var(--crit)' : score >= 30 ? 'var(--high)' : 'var(--low)';
  const level = score >= 60 ? 'ELEVATED' : score >= 30 ? 'MODERATE' : 'LOW';

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
        <div class="gauge-label">Risk score · ${level}</div>
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
        ${riskGauge(Math.round((stats.severity || {}).CRITICAL * 10 + ((stats.severity || {}).HIGH || 0) * 6))}
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
    <a class="job" href="#/job/${esc(job.id)}">
      <span class="job-status ${esc(job.status)}"></span>
      <div style="min-width:0">
        <div class="job-label">${esc(job.label)}</div>
        <div class="job-meta">${esc(job.kind)} · ${esc(job.status)}${
          job.status === 'running' ? ` · ${Math.round(job.percent)}%` : ''} · ${ago(job.created_at)}</div>
      </div>
      <div class="job-right">
        ${badges || `<span class="muted">${job.status === 'done' ? 'clean' : ''}</span>`}
      </div>
    </a>`;
}

/* ---------------- new scan ---------------- */

let pendingFiles = [];

function renderScan() {
  pendingFiles = [];
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
          <option value="deep">Deep — rule engine + LLM</option>
          <option value="fast">Fast — rule engine only</option>
        </select>
        <label class="check"><input type="checkbox" id="verify"> Verification agent</label>
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
  const verify = document.getElementById('verify').checked;

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
      job = await api('/api/jobs/folder', { method: 'POST', body: form });
    } else if (pane === 'snippet') {
      const code = document.getElementById('code').value;
      if (!code.trim()) throw new Error('Paste some code first');
      job = await api('/api/jobs/snippet', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code, filename: document.getElementById('snippet-name').value || 'snippet.py',
          mode, verify
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
          mode, verify
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
    <div class="page-head"><h1>Scans</h1><p>Every scan this server has run.</p></div>
    <div class="card">
      ${jobs.length ? jobs.map(jobRow).join('')
        : emptyState('No scans yet', 'Start one from the New scan tab.')}
    </div>`;
}

/* ---------------- job detail ---------------- */

async function renderJob(id) {
  view.innerHTML = `<div class="empty"><span class="spinner"></span>Loading scan</div>`;
  let job;
  try {
    job = await api(`/api/jobs/${id}`);
  } catch (e) {
    view.innerHTML = `<div class="banner err">${esc(e.message)}</div>
      <a class="btn ghost" href="#/jobs">Back to scans</a>`;
    return;
  }

  paintJob(job);
  if (job.status === 'running' || job.status === 'queued') follow(id);
}

function paintJob(job) {
  const running = job.status === 'running' || job.status === 'queued';
  const result = job.result;

  view.innerHTML = `
    <div class="page-head">
      <div class="row">
        <div style="min-width:0">
          <h1>${esc(job.label)}</h1>
          <p>${esc(job.kind)} · ${esc(job.status)} · started ${ago(job.created_at)}</p>
        </div>
        <div class="spacer"></div>
        <a class="btn ghost sm" href="#/jobs">All scans</a>
      </div>
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

  if (!result) {
    body.innerHTML = emptyState('No result stored', 'This scan finished without a result payload.');
    return;
  }

  const counts = result.counts || {};
  const sources = result.sources || {};
  const stats = result.stats || {};
  const findings = [...(result.findings || [])]
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  body.innerHTML = `
    ${result.degraded ? `<div class="banner warn">
      One analysis tier did not complete, so these results are incomplete.</div>` : ''}

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
        ${riskGauge(Math.round(result.risk_score || 0))}
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
      <div class="card-title">Findings</div>
      ${findings.length ? findings.map(findingCard).join('')
        : emptyState('No vulnerabilities found', (result && (result.status === 'failed' || result.degraded)) ? 'Scan completed with degraded coverage or failed engine.' : 'Scanned scope came back clean.')}
    </div>`;

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
      <div style="margin-top:16px">${sorted.map(findingCard).join('')}</div>
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
            ${done ? '✓' : (active ? '●' : '○')} ${label}
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

function findingCard(f) {
  const verified = f.verification && f.verification.verdict === 'confirmed';
  const assessmentStatus = f.assessment_status || (f.assessment && f.assessment.status);
  const corroborated = f.corroborated || (f.provenance && f.provenance.corroborated);
  return `
    <div class="finding ${esc(f.severity)}">
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
        ${(f.taint_path || []).length ? `<h4>Traced dataflow</h4><div class="taint">
          ${f.taint_path.map(s => `
            <div class="taint-step">
              <span class="taint-kind ${esc(s.kind || '')}">${esc(s.kind || 'step')}</span>
              <span>${esc(s.step || '')}</span>
              <span class="taint-loc">${esc(s.file || '')}:${esc(s.line || '')}</span>
            </div>`).join('')}</div>` : ''}
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
      (page === 'job' && target === 'jobs'));
  });

  try {
    if (page === 'scan') renderScan();
    else if (page === 'jobs') await renderJobs();
    else if (page === 'job' && parts[1]) await renderJob(parts[1]);
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
