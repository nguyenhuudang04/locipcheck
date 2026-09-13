/* ══════════════════════════════════════════════════════════════
   SOC IOC Enrichment — Frontend Logic
   ══════════════════════════════════════════════════════════════ */

'use strict';

// ── State ──
let currentIoc = '';
let currentLookupId = '';
let currentReport = null;
let detectTimer = null;
let _rawJsonStr = '';
let _jsonFilterTimer = null;

const SOURCE_ICONS = {
  'VirusTotal':    { icon: 'VT', color: '#3b82f6' },
  'AbuseIPDB':     { icon: 'AB', color: '#ef4444' },
  'urlscan.io':    { icon: 'US', color: '#06b6d4' },
  'GreyNoise':     { icon: 'GN', color: '#10b981' },
  'ThreatFox':     { icon: 'TF', color: '#f59e0b' },
  'MalwareBazaar': { icon: 'MB', color: '#8b5cf6' },
};
const TYPE_COLOURS = {
  ipv4: '#3b82f6', ipv6: '#06b6d4', domain: '#10b981',
  url: '#8b5cf6', md5: '#f59e0b', sha1: '#f97316', sha256: '#ef4444',
};
const LEVEL_ARC_COLOUR = { LOW: '#10b981', MEDIUM: '#f59e0b', HIGH: '#ef4444', CRITICAL: '#ff6b6b', UNDETERMINED: '#64748b' };

// ════════════════════════════════════
// DETECTION & SEARCH
// ════════════════════════════════════
function onInputChange(val) {
  clearTimeout(detectTimer);
  const badge = document.getElementById('iocTypeBadge');
  if (!val.trim()) { badge.style.display = 'none'; return; }
  detectTimer = setTimeout(() => detectType(val.trim()), 300);
}

async function detectType(ioc) {
  try {
    const r = await fetch('/api/detect', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc })
    });
    const d = await r.json();
    const badge = document.getElementById('iocTypeBadge');
    if (d.ioc_type && d.ioc_type !== 'unknown') {
      badge.textContent = d.ioc_type.toUpperCase();
      badge.style.display = 'inline-flex';
      badge.style.background = hexToRgba(TYPE_COLOURS[d.ioc_type] || '#3b82f6', .15);
      badge.style.color = TYPE_COLOURS[d.ioc_type] || '#60a5fa';
    } else {
      badge.style.display = 'none';
    }
  } catch {}
}

const EXAMPLES = {
  ip:     '185.220.101.5',
  domain: 'malware.example.com',
  url:    'https://phishing.example.com/login',
  hash:   '094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d',
};
function setExample(type) {
  document.querySelectorAll('.qtab').forEach(b => b.classList.remove('active'));
  event.currentTarget.classList.add('active');
  const input = document.getElementById('iocInput');
  input.value = EXAMPLES[type];
  onInputChange(EXAMPLES[type]);
  input.focus();
}

function submitSearch() {
  const ioc = document.getElementById('iocInput').value.trim();
  if (!ioc) return;
  const iocs = ioc.split(/[\s,]+/).filter(x => x);
  if (iocs.length > 1) {
    doBulkEnrich(iocs);
  } else {
    doEnrich(iocs[0]);
  }
}
function submitNavSearch() {
  const ioc = document.getElementById('navSearchInput').value.trim();
  if (!ioc) return;
  document.getElementById('iocInput').value = ioc;
  const iocs = ioc.split(/[\s,]+/).filter(x => x);
  if (iocs.length > 1) {
    doBulkEnrich(iocs);
  } else {
    doEnrich(iocs[0]);
  }
}

async function doBulkEnrich(iocs) {
  document.getElementById('loadingOverlay').style.display = 'flex';
  document.getElementById('resultsSection').style.display = 'none';
  document.getElementById('heroSection').style.display = 'flex';
  document.getElementById('searchBtn').disabled = true;

  let lastData = null;
  for (let i = 0; i < iocs.length; i++) {
    document.getElementById('loadingIOC').textContent = `Enriching ${i + 1} of ${iocs.length}: ${iocs[i]}`;
    const lookupId = 'id-' + Math.random().toString(36).substr(2, 16) + '-' + Date.now();
    const body = { ioc: iocs[i], lookup_id: lookupId, alert_context: getAlertContext() };
    try {
      const res = await fetch('/api/enrich', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (res.ok && !data.error) {
        lastData = data;
      }
    } catch (e) {
      console.error('Error enriching', iocs[i], e);
    }
  }

  document.getElementById('loadingOverlay').style.display = 'none';
  document.getElementById('searchBtn').disabled = false;
  
  if (lastData) {
    currentIoc = lastData.ioc;
    currentLookupId = lastData.lookup_id;
    currentReport = lastData;
    renderResults(lastData);
  } else {
    alert('Finished bulk enrichment, but no results were successfully loaded.');
  }
}

// ════════════════════════════════════
// ALERT CONTEXT
// ════════════════════════════════════
function toggleAlertCtx() {
  const body = document.getElementById('alertCtxBody');
  const chev = document.getElementById('ctxChevron');
  if (body.style.display === 'none') {
    body.style.display = 'block';
    chev.style.transform = 'rotate(180deg)';
  } else {
    body.style.display = 'none';
    chev.style.transform = '';
  }
}

function getAlertContext() {
  return {
    event_time: document.getElementById('ctx_event_time').value.trim() || null,
    hostname: document.getElementById('ctx_hostname').value.trim() || null,
    username: document.getElementById('ctx_username').value.trim() || null,
    source_ip: document.getElementById('ctx_source_ip').value.trim() || null,
    destination: document.getElementById('ctx_destination').value.trim() || null,
    action: document.getElementById('ctx_action').value || null,
    event_count: document.getElementById('ctx_event_count').value || null,
    log_source: document.getElementById('ctx_log_source').value.trim() || null,
    process_name: document.getElementById('ctx_process_name').value.trim() || null,
    command_line: document.getElementById('ctx_command_line').value.trim() || null,
    file_hash: document.getElementById('ctx_file_hash').value.trim() || null,
    email_sender: document.getElementById('ctx_email_sender').value.trim() || null,
    email_recipient: document.getElementById('ctx_email_recipient').value.trim() || null,
  };
}

function clearAlertContext() {
  ['ctx_action'].forEach(id => document.getElementById(id).value = '');
  ['ctx_event_time', 'ctx_hostname', 'ctx_username', 'ctx_source_ip', 'ctx_destination', 'ctx_event_count', 'ctx_log_source', 'ctx_process_name', 'ctx_command_line', 'ctx_file_hash', 'ctx_email_sender', 'ctx_email_recipient'].forEach(id => document.getElementById(id).value = '');
}

function applyAlertContext() {
  if (currentIoc) doEnrich(currentIoc);
}

// ════════════════════════════════════
// ENRICH
// ════════════════════════════════════
async function doEnrich(ioc) {
  currentIoc = ioc;
  currentLookupId = 'id-' + Math.random().toString(36).substr(2, 16) + '-' + Date.now();
  currentReport = null;
  _rawJsonStr = '';
  document.getElementById('loadingIOC').textContent = ioc;
  document.getElementById('loadingOverlay').style.display = 'flex';
  document.getElementById('resultsSection').style.display = 'none';
  
  // Clear UI state
  document.getElementById('sourcesPanel').innerHTML = '';
  document.getElementById('analystSummaryBody').innerHTML = '';
  document.getElementById('jsonCode').innerHTML = '';
  document.getElementById('breakdownList').innerHTML = '';
  document.getElementById('coverageGrid').innerHTML = '';
  document.getElementById('iocRiskNum').textContent = '0';
  document.getElementById('incidentSevLevel').textContent = 'UNDETERMINED';
  document.getElementById('incidentSevNote').textContent = '';
  document.getElementById('heroSection').style.display = 'flex';
  document.getElementById('searchBtn').disabled = true;

  document.querySelectorAll('.src-chip').forEach((c, i) => {
    c.style.opacity = '0.3';
    setTimeout(() => { setInterval(() => { c.style.opacity = c.style.opacity === '1' ? '0.3' : '1'; }, 600 + i * 100); }, i * 150);
  });

  const body = { ioc, lookup_id: currentLookupId, alert_context: getAlertContext() };
  try {
    const res = await fetch('/api/enrich', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);
    
    // Result mismatch validation
    if (data.lookup_id !== currentLookupId || data.ioc !== currentIoc) {
        console.error(`Result mismatch: got data for ${data.ioc} (${data.lookup_id}), expected ${currentIoc} (${currentLookupId})`);
        // If we throw here, the loading overlay won't disappear if this was an old request, but we also shouldn't hide it because a NEW request is running.
        // Actually, just return without hiding the loading overlay because another request is in flight.
        return;
    }
    
    currentReport = data;
    renderResults(data);
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    if (body.lookup_id === currentLookupId) {
        document.getElementById('loadingOverlay').style.display = 'none';
        document.getElementById('searchBtn').disabled = false;
    }
  }
}

// ════════════════════════════════════
// RENDER RESULTS
// ════════════════════════════════════
function renderResults(data) {
  document.getElementById('heroSection').style.display = 'none';
  document.getElementById('resultsSection').style.display = 'block';
  document.getElementById('navSearchWrap').style.display = 'block';
  document.getElementById('navSearchInput').value = data.ioc;

  // Header
  const pill = document.getElementById('iocTypePill');
  pill.textContent = (data.ioc_type || '').toUpperCase();
  pill.style.background = hexToRgba(TYPE_COLOURS[data.ioc_type] || '#3b82f6', .12);
  pill.style.color = TYPE_COLOURS[data.ioc_type] || '#60a5fa';
  document.getElementById('iocValue').textContent = data.ioc;
  document.getElementById('iocTs').textContent = 'Analysed: ' + (data.timestamp || '');

  document.getElementById('dlJsonBtn').dataset.file = data._json_file || '';
  document.getElementById('dlMdBtn').dataset.file = data._md_file || '';

  const risk = data.risk || {};
  const summary = data.analyst_summary || {};

  // Alert Context Badge
  const ctxEmpty = Object.values(data.alert_context || {}).every(x => x === null || x === '');
  document.getElementById('ctxStatusBadge').textContent = ctxEmpty ? 'Optional — adds Incident Severity' : 'Context Applied';
  document.getElementById('ctxStatusBadge').style.color = ctxEmpty ? 'var(--text-d)' : 'var(--green-l)';
  document.getElementById('ctxStatusBadge').style.borderColor = ctxEmpty ? 'var(--border)' : 'var(--green)';

  // IOC Reputation Risk
  const score = risk.score ?? 0;
  const level = risk.level || 'LOW';
  document.getElementById('iocRiskNum').textContent = score;
  document.getElementById('iocRiskNum').style.color = LEVEL_ARC_COLOUR[level];
  const lb = document.getElementById('iocRiskLevel');
  lb.textContent = level; lb.className = `ds-level-badge level-${level}`;
  
  const arc = document.getElementById('gaugeArc1');
  const circumference = 289.0;
  const offset = circumference - (score / 100) * circumference;
  arc.style.stroke = LEVEL_ARC_COLOUR[level];
  if(level === 'CRITICAL') arc.style.filter = `drop-shadow(0 0 8px ${LEVEL_ARC_COLOUR[level]}88)`;
  else arc.style.filter = '';
  arc.style.strokeDashoffset = circumference;
  setTimeout(() => { arc.style.strokeDashoffset = offset; }, 50);

  // Incident Severity
  const sevLevel = summary.incident_severity || 'UNDETERMINED';
  const sevWrap = document.getElementById('incidentSevWrap');
  const sevL = document.getElementById('incidentSevLevel');
  const sevN = document.getElementById('incidentSevNote');
  const sevI = document.getElementById('sevIcon');
  
  sevL.textContent = sevLevel;
  sevN.textContent = summary.incident_severity_note || '';
  
  if (sevLevel === 'UNDETERMINED') {
    sevL.style.color = 'var(--text-m)';
    sevI.innerHTML = `<svg viewBox="0 0 48 48" fill="none" width="52" height="52"><circle cx="24" cy="24" r="22" stroke="#334155" stroke-width="2"/><path d="M24 14v12M24 32h.01" stroke="#64748b" stroke-width="3" stroke-linecap="round"/></svg>`;
    sevI.style.background = 'var(--bg3)';
  } else {
    sevL.style.color = LEVEL_ARC_COLOUR[sevLevel];
    sevI.innerHTML = `<svg viewBox="0 0 48 48" fill="none" width="52" height="52"><circle cx="24" cy="24" r="22" stroke="${LEVEL_ARC_COLOUR[sevLevel]}" stroke-width="2"/><path d="M16 24l6 6 10-10" stroke="${LEVEL_ARC_COLOUR[sevLevel]}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    sevI.style.background = hexToRgba(LEVEL_ARC_COLOUR[sevLevel], 0.1);
  }

  // Coverage Stats
  document.getElementById('coverageGrid').innerHTML = `
    <div class="stat-box"><div class="stat-box-val">${risk.sources_consulted || 0}</div><div class="stat-box-lbl">Consulted</div></div>
    <div class="stat-box"><div class="stat-box-val">${risk.sources_matched || 0}</div><div class="stat-box-lbl">Matched</div></div>
    <div class="stat-box"><div class="stat-box-val">${risk.sources_no_match || 0}</div><div class="stat-box-lbl">No Match</div></div>
    <div class="stat-box"><div class="stat-box-val" style="color:var(--orange-l)">${summary.skipped_sources?.length || 0}</div><div class="stat-box-lbl">Skipped</div></div>
  `;

  renderBreakdown(risk.factors || []);
  renderAnalystSummary(summary);
  renderSources(data.results || []);
  loadHistory();
  renderJsonViewer(data);

  setTimeout(() => document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' }), 50);
}

function renderBreakdown(factors) {
  const container = document.getElementById('breakdownList');
  if (!factors.length) { container.innerHTML = '<p class="empty-msg" style="color:var(--text-d);font-size:13px">No scoring factors</p>'; return; }
  const maxAbs = Math.max(...factors.map(f => Math.abs(f.points)), 1);
  container.innerHTML = factors.map(f => {
    const isPos = f.points > 0;
    const ptsStr = (isPos ? '+' : '') + Math.round(f.points);
    return `
      <div class="breakdown-item">
        <div class="bf-top">
          <span class="bf-name">${escHtml(f.factor)}</span>
          <span class="bf-pts ${isPos?'pos':'neg'}">${ptsStr}</span>
        </div>
        <div class="bf-reason">${escHtml(f.reason)}</div>
      </div>`;
  }).join('');
}

function renderAnalystSummary(s) {
  const c = document.getElementById('analystSummaryBody');
  let html = '';

  // Executive Assessment
  if (s.executive_assessment) {
    html += `<div class="as-section"><div class="as-title">Executive Assessment</div>
             <p style="margin:4px 0 0;font-size:13px;color:var(--text-m);line-height:1.5;">${escHtml(s.executive_assessment)}</p></div>`;
  }

  // Why this IOC is risky
  if (s.why_this_ioc_is_risky && s.why_this_ioc_is_risky.length) {
    html += `<div class="as-section"><div class="as-title">Why this IOC is risky</div><ul class="as-list">`;
    s.why_this_ioc_is_risky.forEach(n => html += `<li>${escHtml(n)}</li>`);
    html += `</ul></div>`;
  }

  // Threat Intelligence
  if (s.threat_intelligence && s.threat_intelligence.length) {
    html += `<div class="as-section"><div class="as-title">Threat Intelligence</div><ul class="as-list">`;
    s.threat_intelligence.forEach(n => html += `<li>${escHtml(n)}</li>`);
    html += `</ul></div>`;
  }

  // Infrastructure
  if (s.infrastructure && s.infrastructure.length) {
    html += `<div class="as-section"><div class="as-title">Infrastructure</div><ul class="as-list">`;
    s.infrastructure.forEach(n => html += `<li>${escHtml(n)}</li>`);
    html += `</ul></div>`;
  }

  // Recommended Telemetry Checks
  if (s.recommended_telemetry && s.recommended_telemetry.length) {
    html += `<div class="as-section"><div class="as-title">Recommended Telemetry Checks</div><ul class="as-list">`;
    s.recommended_telemetry.forEach(l => html += `<li>${escHtml(l)}</li>`);
    html += `</ul></div>`;
  }

  // Recommended Containment
  if (s.recommended_containment && s.recommended_containment.length) {
    html += `<div class="as-section"><div class="as-title">Recommended Containment</div><ul class="as-list">`;
    s.recommended_containment.forEach(l => html += `<li>${escHtml(l)}</li>`);
    html += `</ul></div>`;
  }

  // Escalation Conditions
  if (s.escalation_conditions && s.escalation_conditions.length) {
    html += `<div class="as-section"><div class="as-title">Escalation Conditions</div><ul class="as-list">`;
    s.escalation_conditions.forEach(l => html += `<li>${escHtml(l)}</li>`);
    html += `</ul></div>`;
  }

  c.innerHTML = html;
}

function renderSources(results) {
  const panel = document.getElementById('sourcesPanel');
  if (!results.length) { panel.innerHTML = '<p class="empty-msg" style="color:var(--text-d);font-size:13px;padding:20px">No source data available</p>'; return; }
  panel.innerHTML = results.map((r, idx) => renderSourceCard(r, idx)).join('');
  const first = panel.querySelector('.source-card.has-data');
  if (first) toggleSource(first.querySelector('.source-header'));
}

function renderSourceCard(r, idx) {
  const src = SOURCE_ICONS[r.source] || { icon: r.source.substring(0,2).toUpperCase(), color: '#3b82f6' };
  const pStatus = r.status || 'UNKNOWN';
  const data = r.data || {};
  
  let pStatusClass = 'status-ERROR';
  if (pStatus === 'MATCHED') pStatusClass = 'status-MATCHED';
  else if (pStatus === 'NO_MATCH') pStatusClass = 'status-NO_MATCH';
  else if (pStatus === 'SKIPPED') pStatusClass = 'status-SKIPPED';
  else if (pStatus === 'RATE_LIMITED') pStatusClass = 'status-RATE_LIMITED';
  else if (pStatus === 'UNAUTHORIZED') pStatusClass = 'status-UNAUTHORIZED';

  const verdict = data.verdict || 'unknown';
  let verdictClass = 'verdict-unknown';
  if (verdict === 'malicious') verdictClass = 'verdict-malicious';
  else if (verdict === 'suspicious') verdictClass = 'verdict-suspicious';
  else if (verdict === 'benign') verdictClass = 'verdict-benign';

  const hasData = pStatus === 'MATCHED' || pStatus === 'NO_MATCH';

  let bodyHtml = '';
  
  // Error message
  if (data.error) {
    bodyHtml += `<div class="source-error">
      <svg viewBox="0 0 18 18" fill="none" width="14" height="14"><circle cx="9" cy="9" r="7" stroke="#64748b" stroke-width="1.4"/><path d="M9 6v3M9 12h.01" stroke="#64748b" stroke-width="1.5" stroke-linecap="round"/></svg>
      ${escHtml(data.error)}
    </div>`;
  }

  // Tags
  if (data.tags && data.tags.length) {
    bodyHtml += `<div class="tags-wrap">` + data.tags.map(t => {
      const isRed = ['tor','botnet','ransomware','c2','stealer','trojan','exploit','malware','cobalt_strike'].some(x => t.toLowerCase().includes(x));
      return `<span class="tag ${isRed ? 'red' : ''}">${escHtml(t)}</span>`;
    }).join('') + `</div>`;
  }

  if (r.source === 'VirusTotal') {
    bodyHtml = renderVirusTotalTabs(r, data, verdictClass);
  } else {
    // Normal provider rendering
    if (data.analysis_stats && data.analysis_stats.total > 0) {
      const s = data.analysis_stats;
      const t = s.total;
      bodyHtml += `
        <div class="analysis-bar-wrap">
          <div class="ab-header"><span>Engine Detections</span><span>${s.malicious} / ${t} malicious</span></div>
          <div class="ab-track">
            <div class="ab-mal" style="width:${(s.malicious/t)*100}%"></div>
            <div class="ab-sus" style="width:${(s.suspicious/t)*100}%"></div>
            <div class="ab-cln" style="width:${(s.harmless/t)*100}%"></div>
            <div class="ab-und" style="width:${((s.undetected+s.timeout)/t)*100}%"></div>
          </div>
        </div>`;
    }

    const stats = [];
    if (data.confidence != null) stats.push({ label: 'Confidence', value: data.confidence + '%' });
    if (data.reputation != null) stats.push({ label: 'Reputation', value: data.reputation });
    if (data.malicious_count != null && !data.analysis_stats) stats.push({ label: 'Malicious Hits', value: data.malicious_count, bold: true });
    if (data.country) stats.push({ label: 'Country', value: data.country });
    if (data.asn) stats.push({ label: 'ASN', value: data.asn });
    if (data.isp) stats.push({ label: 'ISP', value: data.isp });
    if (data.organization) stats.push({ label: 'Organization', value: data.organization });
    if (data.domain) stats.push({ label: 'Domain', value: data.domain });
    if (data.network) stats.push({ label: 'Network', value: data.network });
    if (data.usage_type) stats.push({ label: 'Usage', value: data.usage_type });
    if (data.classification) stats.push({ label: 'GN Class', value: data.classification });
    if (data.name) stats.push({ label: 'Actor Name', value: data.name });
    if (data.threat_type) stats.push({ label: 'Threat Type', value: data.threat_type });
    if (data.malware_printable) stats.push({ label: 'Malware', value: data.malware_printable, bold: true });
    if (data.malware_family) stats.push({ label: 'Malware Family', value: data.malware_family, bold: true });
    if (data.message) stats.push({ label: 'Message', value: data.message });
    if (data.first_observed) stats.push({ label: 'First Seen', value: data.first_observed });
    if (data.last_observed) stats.push({ label: 'Last Seen', value: data.last_observed });
    if (data.last_analyzed) stats.push({ label: 'Last Analyzed', value: data.last_analyzed });
    if (data.enrichment_queried_at) stats.push({ label: 'Query Time', value: data.enrichment_queried_at });
    if (data.http_status) stats.push({ label: 'HTTP Status', value: data.http_status });
    
    if (stats.length) {
      bodyHtml += `<div class="source-stats">` + stats.map(s => 
        `<div class="stat-item"><span class="stat-label">${s.label}</span><span class="stat-value mono ${s.bold?'bold':''}">${escHtml(String(s.value))}</span></div>`
      ).join('') + `</div>`;
    }

    if (data.raw_link) {
      bodyHtml += `<a class="source-link-btn" href="${escHtml(data.raw_link)}" target="_blank" rel="noopener noreferrer">
        <svg viewBox="0 0 16 16" fill="none" width="13" height="13"><path d="M6 4H3a1 1 0 00-1 1v8a1 1 0 001 1h8a1 1 0 001-1v-3M9 2h5v5M9 7l5-5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
        View raw on ${escHtml(r.source)}
      </a>`;
    }
  }

  return `
    <div class="source-card ${verdictClass} ${hasData ? 'has-data' : ''}">
      <div class="source-header" onclick="toggleSource(this)">
        <div class="source-icon" style="color:${src.color};border-color:${hexToRgba(src.color,.3)};background:${hexToRgba(src.color,.08)}">${src.icon}</div>
        <div class="source-name-wrap">
          <div class="source-name">${escHtml(r.source)}</div>
          <div class="source-name-sub">Verdict: ${escHtml(verdict.toUpperCase())}</div>
        </div>
        <span class="source-status-badge ${pStatusClass}">${escHtml(pStatus)}</span>
        <svg class="source-chevron" viewBox="0 0 16 16" fill="none" width="16" height="16"><path d="M6 4l4 4-4 4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </div>
      <div class="source-body">${bodyHtml}</div>
    </div>`;
}

function toggleSource(h) { h.closest('.source-card').classList.toggle('open'); }

// ════════════════════════════════════
// VIRUSTOTAL TABS
// ════════════════════════════════════
function renderVirusTotalTabs(r, data, verdictClass) {
  let html = `<div class="vt-tabs">
    <div class="vt-tab active" onclick="switchVtTab(this, 'vt-overview')">Overview</div>
    <div class="vt-tab" onclick="switchVtTab(this, 'vt-vendor')">Vendor Detections</div>
    <div class="vt-tab" onclick="switchVtTab(this, 'vt-whois')">WHOIS</div>
    <div class="vt-tab" onclick="loadVtRelationship(this, 'resolutions', 'vt-resolutions')">Resolutions</div>
    <div class="vt-tab" onclick="loadVtRelationship(this, 'communicating_files', 'vt-related')">Related Files</div>
    <div class="vt-tab" onclick="loadVtRelationship(this, 'comments', 'vt-community')">Community</div>
  </div>
  <div class="vt-tab-content active" id="vt-overview">
    ${renderVtOverview(r, data)}
  </div>
  <div class="vt-tab-content" id="vt-vendor">
    ${renderVtVendorDetections(data.vendor_detections)}
  </div>
  <div class="vt-tab-content" id="vt-whois">
    ${renderVtWhois(data)}
  </div>
  <div class="vt-tab-content" id="vt-resolutions">
    <div class="loading-text">Click tab to load...</div>
  </div>
  <div class="vt-tab-content" id="vt-related">
    <div class="loading-text">Click tab to load...</div>
  </div>
  <div class="vt-tab-content" id="vt-community">
    <div class="loading-text">Click tab to load...</div>
  </div>`;
  return html;
}

function switchVtTab(el, targetId) {
  const card = el.closest('.source-body');
  card.querySelectorAll('.vt-tab').forEach(t => t.classList.remove('active'));
  card.querySelectorAll('.vt-tab-content').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  card.querySelector('#' + targetId).classList.add('active');
}

function renderVtOverview(r, data) {
  let html = '';
  if (data.analysis_stats && data.analysis_stats.total > 0) {
    const s = data.analysis_stats;
    const t = s.total;
    html += `
      <div class="analysis-bar-wrap">
        <div class="ab-header"><span>Engine Detections</span><span>${s.malicious} / ${t} malicious</span></div>
        <div class="ab-track">
          <div class="ab-mal" style="width:${(s.malicious/t)*100}%"></div>
          <div class="ab-sus" style="width:${(s.suspicious/t)*100}%"></div>
          <div class="ab-cln" style="width:${(s.harmless/t)*100}%"></div>
          <div class="ab-und" style="width:${((s.undetected+s.timeout)/t)*100}%"></div>
        </div>
      </div>`;
  }
  const stats = [];
  if (data.reputation != null) stats.push({ label: 'Reputation', value: data.reputation });
  if (data.network) stats.push({ label: 'Network', value: data.network });
  if (data.asn) stats.push({ label: 'ASN', value: data.asn });
  if (data.organization) stats.push({ label: 'Organization', value: data.organization });
  if (data.country) stats.push({ label: 'Country', value: data.country });
  if (data.last_analyzed) stats.push({ label: 'Last Analyzed', value: data.last_analyzed });
  
  if (stats.length) {
    html += `<div class="source-stats">` + stats.map(s => 
      `<div class="stat-item"><span class="stat-label">${s.label}</span><span class="stat-value mono">${escHtml(String(s.value))}</span></div>`
    ).join('') + `</div>`;
  }
  return html;
}

function renderVtVendorDetections(vd) {
  if (!vd) return '<p class="empty-msg">No vendor detections available</p>';
  let html = '<div class="vd-table-wrap"><table class="vd-table"><tr><th>Engine</th><th>Category</th><th>Result</th></tr>';
  ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout'].forEach(cat => {
    if (vd[cat] && vd[cat].length) {
      vd[cat].forEach(e => {
        let catClass = 'vd-' + cat;
        html += `<tr><td>${escHtml(e.engine_name)}</td><td><span class="tag ${catClass}">${escHtml(e.category)}</span></td><td>${escHtml(e.result || '')}</td></tr>`;
      });
    }
  });
  html += '</table></div>';
  return html;
}

function renderVtWhois(data) {
  const stats = [];
  if (data.organization) stats.push({ label: 'Network Owner', value: data.organization });
  if (data.asn) stats.push({ label: 'ASN', value: data.asn });
  if (data.network) stats.push({ label: 'Network Range', value: data.network });
  if (data.regional_internet_registry) stats.push({ label: 'RIR', value: data.regional_internet_registry });
  if (data.country) stats.push({ label: 'Country', value: data.country });
  if (data.continent) stats.push({ label: 'Continent', value: data.continent });
  if (data.whois_date) stats.push({ label: 'WHOIS Updated', value: data.whois_date });

  let html = '';
  if (stats.length) {
    html += `<div class="source-stats" style="margin-bottom:16px">` + stats.map(s => 
      `<div class="stat-item"><span class="stat-label">${s.label}</span><span class="stat-value mono">${escHtml(String(s.value))}</span></div>`
    ).join('') + `</div>`;
  }
  if (data.whois) {
    html += `<details class="whois-details"><summary>Raw WHOIS Record</summary><pre>${escHtml(data.whois)}</pre></details>`;
  } else {
    html += '<p class="empty-msg">No WHOIS data available</p>';
  }
  return html;
}

async function loadVtRelationship(el, rel, targetId) {
  switchVtTab(el, targetId);
  const container = el.closest('.source-body').querySelector('#' + targetId);
  if (container.dataset.loaded) return;
  
  container.innerHTML = '<div class="spinner-ring" style="width:24px;height:24px;margin:10px auto"><div></div><div></div><div></div><div></div></div>';
  try {
    const res = await fetch(`/api/vt_relationship?ioc=${encodeURIComponent(currentIoc)}&relationship=${rel}&limit=10`);
    const data = await res.json();
    container.dataset.loaded = "true";
    
    if (data.status === 'PREMIUM_REQUIRED') {
      container.innerHTML = `<div class="premium-msg"><svg viewBox="0 0 24 24" fill="none" width="24" height="24" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg><h3>Premium Features Required</h3><p>VirusTotal API plan does not allow this endpoint or quota exceeded.</p></div>`;
      return;
    }
    if (data.status === 'RATE_LIMITED') {
      container.innerHTML = '<div class="source-error">Rate limited by VirusTotal API. Try again later.</div>';
      return;
    }
    if (data.status === 'ERROR') {
      container.innerHTML = `<div class="source-error">Error: ${escHtml(data.data.error || 'Unknown error')}</div>`;
      return;
    }
    
    let html = '';
    if (data.data && data.data.length > 0) {
       html += `<div class="vt-rel-list">` + data.data.map(item => {
          let text = '';
          if (rel === 'resolutions') text = `${item.attributes.host_name || item.attributes.ip_address} (Seen: ${_ts(item.attributes.date)})`;
          else if (rel === 'comments') text = item.attributes.text;
          else if (rel.includes('files')) text = `${item.attributes.meaningful_name || item.id} (Malicious: ${item.attributes.last_analysis_stats?.malicious || 0})`;
          else text = JSON.stringify(item.attributes);
          return `<div class="vt-rel-item">${escHtml(text)}</div>`;
       }).join('') + `</div>`;
    } else {
       html = '<p class="empty-msg">No data found</p>';
    }
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div class="source-error">Failed to load: ${err.message}</div>`;
  }
}
function _ts(unix_ts) {
    if (!unix_ts) return 'Unknown';
    const d = new Date(unix_ts * 1000);
    return d.toISOString().split('T')[0];
}

// ════════════════════════════════════
// HISTORY
// ════════════════════════════════════
async function loadHistory() {
  try {
    const r = await fetch('/api/history');
    const items = await r.json();
    const c = document.getElementById('historyList');
    if (!items.length) { c.innerHTML = '<p class="empty-msg" style="color:var(--text-d);font-size:13px">No history yet</p>'; return; }
    const BG = { LOW: '#10b98120', MEDIUM: '#f59e0b20', HIGH: '#ef444420', CRITICAL: '#ef444430' };
    const FG = { LOW: '#6ee7b7', MEDIUM: '#fcd34d', HIGH: '#fca5a5', CRITICAL: '#ff6b6b' };
    c.innerHTML = items.map(i => `
      <div class="history-item" onclick="document.getElementById('iocInput').value='${escHtml(i.ioc)}'; submitSearch();">
        <div class="hi-score" style="background:${BG[i.level]||'#1e2a42'};color:${FG[i.level]||'#94a3b8'}">${i.score ?? '?'}</div>
        <div class="hi-info">
          <div class="hi-ioc" title="${escHtml(i.ioc)}">${escHtml(i.ioc)}</div>
          <div class="hi-meta">${(i.ioc_type||'').toUpperCase()} &middot; Lookups: ${i.lookup_count} &middot; ${i.timestamp ? i.timestamp.slice(0,10) : ''}</div>
        </div>
      </div>`).join('');
  } catch {}
}

// ════════════════════════════════════
// JSON VIEWER
// ════════════════════════════════════
function renderJsonViewer(data) {
  const d = Object.fromEntries(Object.entries(data).filter(([k]) => !k.startsWith('_')));
  _rawJsonStr = JSON.stringify(d, null, 2);
  document.getElementById('jsonSearchInput').value = '';
  document.getElementById('jsonMatchCount').textContent = '';
  document.getElementById('jsonCode').innerHTML = syntaxHighlight(_rawJsonStr);
  document.getElementById('jsonLineCount').textContent = `${_rawJsonStr.split('\n').length} lines`;
  document.getElementById('jsonViewerBody').classList.remove('collapsed');
  document.getElementById('toggleJsonIcon').style.transform = '';
}
function syntaxHighlight(json) {
  return json.split('\n').map((l, i) => {
    let hl = l
      .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")\s*:/g, m => `<span class="jk">${m}</span>`)
      .replace(/:\s*("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")/g, (m, s) => m.replace(s, `<span class="js">${s}</span>`))
      .replace(/^\s*("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*")\s*[,\]]?$/, m => m.replace(/(".*?")/g, s => `<span class="js">${s}</span>`))
      .replace(/:\s*(-?\d+(\.\d+)?([eE][+-]?\d+)?)/g, (m, n) => m.replace(n, `<span class="jn">${n}</span>`))
      .replace(/:\s*(true|false)\b/g, (m, b) => m.replace(b, `<span class="jb">${b}</span>`))
      .replace(/:\s*(null)\b/g, (m, n) => m.replace(n, `<span class="jnl">${n}</span>`));
    return `<span class="jl">${i + 1}</span>` + hl;
  }).join('\n');
}
function filterJson(q) {
  clearTimeout(_jsonFilterTimer);
  _jsonFilterTimer = setTimeout(() => {
    const c = document.getElementById('jsonCode');
    if (!q.trim()) { c.innerHTML = syntaxHighlight(_rawJsonStr); document.getElementById('jsonMatchCount').textContent = ''; return; }
    const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    const rawMatches = (_rawJsonStr.match(re) || []).length;
    let html = syntaxHighlight(_rawJsonStr.replace(re, m => `\x00MATCH\x00${m}\x00END\x00`));
    c.innerHTML = html.replace(/\x00MATCH\x00/g, '<mark class="json-match">').replace(/\x00END\x00/g, '</mark>');
    document.getElementById('jsonMatchCount').textContent = rawMatches ? `${rawMatches} match${rawMatches>1?'es':''}` : 'no match';
  }, 200);
}
function toggleJsonViewer() {
  const b = document.getElementById('jsonViewerBody');
  b.classList.toggle('collapsed');
  document.getElementById('toggleJsonIcon').style.transform = b.classList.contains('collapsed') ? 'rotate(-90deg)' : '';
}
async function copyJson() {
  if (!_rawJsonStr) return;
  try { await navigator.clipboard.writeText(_rawJsonStr); } catch {
    const t = document.createElement('textarea'); t.value = _rawJsonStr;
    t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t);
    t.select(); document.execCommand('copy'); document.body.removeChild(t);
  }
  const btn = document.getElementById('copyJsonBtn'), lbl = document.getElementById('copyLabel');
  btn.classList.add('copied'); lbl.textContent = 'Copied!';
  setTimeout(() => { btn.classList.remove('copied'); lbl.textContent = 'Copy'; }, 2000);
}
function downloadFile(t) {
  const f = document.getElementById(t==='json'?'dlJsonBtn':'dlMdBtn').dataset.file;
  if(f) window.open(`/api/download/${encodeURIComponent(f)}`, '_blank');
}

// ════════════════════════════════════
// UTIL / INIT
// ════════════════════════════════════
function goBack() {
  document.getElementById('heroSection').style.display = 'flex';
  document.getElementById('resultsSection').style.display = 'none';
  document.getElementById('navSearchWrap').style.display = 'none';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function hexToRgba(h, a) { const r = parseInt(h.slice(1,3),16), g = parseInt(h.slice(3,5),16), b = parseInt(h.slice(5,7),16); return `rgba(${r},${g},${b},${a})`; }

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('iocInput').focus();
});
