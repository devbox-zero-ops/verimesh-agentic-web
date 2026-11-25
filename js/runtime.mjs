import {
  auditAgenticSite,
  buildAuditChain,
  evaluateFmeaRpn,
  verifyAuditChain,
} from './conformance-engine.mjs';

const COGNIZANT_REF_BASE =
  'https://raw.githubusercontent.com/cognizant-ai-labs/agentic-web/main/examples/guesthouse_agentified/';

const auditForm = document.getElementById('audit-form');
const siteUrlInput = document.getElementById('site-url-input');
const auditStatus = document.getElementById('audit-status');
const auditChecksEl = document.getElementById('audit-checks');
const auditBadge = document.getElementById('audit-badge');
const chatLog = document.getElementById('chat-log');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const graphCards = document.getElementById('graph-cards');
const routerModePill = document.getElementById('router-mode-pill');

const consentDialog = document.getElementById('peer-consent-dialog');
const consentDetails = document.getElementById('consent-details');
const byokDialog = document.getElementById('byok-dialog');
const byokForm = document.getElementById('byok-form');
const byokBaseUrl = document.getElementById('byok-base-url');
const byokModel = document.getElementById('byok-model');
const byokApiKey = document.getElementById('byok-api-key');

function selfBaseUrl() {
  const u = new URL('./', window.location.href);
  return u.href;
}

function getByokConfig() {
  return {
    baseUrl: sessionStorage.getItem('verimesh_byok_url') || 'https://api.otari.ai/api/v1',
    model: sessionStorage.getItem('verimesh_byok_model') || 'alibaba/qwen3.8-flash',
    apiKey: sessionStorage.getItem('verimesh_byok_key') || '',
  };
}

function updateRouterPill() {
  const cfg = getByokConfig();
  routerModePill.textContent = cfg.apiKey
    ? `Mode: BYOK (${cfg.model})`
    : 'Mode: Zero-Key Deterministic';
}

function appendMsg(role, summary, detailObj = null, isUser = false) {
  const div = document.createElement('div');
  div.className = isUser ? 'msg user' : 'msg';
  const r = document.createElement('div');
  r.className = 'msg-role';
  r.textContent = role;
  const p = document.createElement('div');
  p.textContent = summary;
  div.append(r, p);
  if (detailObj !== null) {
    const pre = document.createElement('pre');
    pre.textContent = typeof detailObj === 'string' ? detailObj : JSON.stringify(detailObj, null, 2);
    div.append(pre);
  }
  chatLog.append(div);
  chatLog.scrollTop = chatLog.scrollHeight;
}

async function fetchJsonSafe(url) {
  const r = await fetch(url, { mode: 'cors' });
  if (!r.ok) throw new Error(`HTTP ${r.status} fetching ${url}`);
  return r.json();
}

async function runSiteAudit(rawBase) {
  const base = rawBase.endsWith('/') ? rawBase : `${rawBase}/`;
  auditStatus.textContent = `Fetching agent-manifest.json from ${base}...`;
  auditChecksEl.innerHTML = '';
  auditBadge.textContent = '…';
  auditBadge.className = 'score-badge';

  try {
    const manifest = await fetchJsonSafe(new URL('agent-manifest.json', base).href);
    const firstNet = Array.isArray(manifest.networks) ? manifest.networks[0] : null;
    let network = null;
    if (firstNet && firstNet.hocon) {
      network = await fetchJsonSafe(new URL(firstNet.hocon, base).href);
    }
    let nsdeploy = null;
    try {
      nsdeploy = await fetchJsonSafe(new URL('.well-known/nsdeploy.json', base).href);
    } catch {
      nsdeploy = null;
    }

    const report = auditAgenticSite({ baseUrl: base, manifest, network, nsdeploy });
    auditBadge.textContent = `${report.score}/100 (${report.grade})`;
    auditBadge.className = `score-badge ${report.score >= 85 ? 'pass' : 'warn'}`;
    auditStatus.textContent = `Audited ${base} — ${report.passedCount}/${report.totalChecks} checks passed.`;

    for (const c of report.checks) {
      const li = document.createElement('li');
      li.className = 'check-item';
      const left = document.createElement('div');
      const strong = document.createElement('strong');
      strong.textContent = c.label;
      const det = document.createElement('div');
      det.className = 'check-detail';
      det.textContent = c.detail;
      left.append(strong, det);
      const badge = document.createElement('span');
      badge.className = c.passed ? 'tag-pass' : 'tag-fail';
      badge.textContent = c.passed ? `PASS (+${c.weight})` : `FAIL (0/${c.weight})`;
      li.append(left, badge);
      auditChecksEl.append(li);
    }
    return report;
  } catch (err) {
    auditBadge.textContent = 'FAIL';
    auditBadge.className = 'score-badge warn';
    auditStatus.textContent = `Fail-closed CORS/fetch error: ${err.message}`;
    return { error: err.message };
  }
}

function requestPeerConsent({ peerUrl, peerLabel, actionName, payload }) {
  return new Promise((resolve) => {
    consentDetails.innerHTML = '';
    const rows = [
      ['Peer Network', `${peerLabel} (${peerUrl})`],
      ['Requested Action', actionName],
      ['Private sly_data Shared', 'NONE (deny-by-default enforced)'],
      ['BYOK Credentials Shared', 'NEVER (origin-isolated)'],
      ['Payload Preview', JSON.stringify(payload)],
    ];
    for (const [k, v] of rows) {
      const dt = document.createElement('dt');
      dt.textContent = k;
      const dd = document.createElement('dd');
      dd.textContent = v;
      consentDetails.append(dt, dd);
    }
    const onClose = () => {
      consentDialog.removeEventListener('close', onClose);
      resolve(consentDialog.returnValue === 'approve');
    };
    consentDialog.addEventListener('close', onClose);
    consentDialog.showModal();
  });
}

async function fetchLivePrimarySources() {
  const out = {};
  const tasks = [
    fetch('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_day.geojson')
      .then((r) => r.json())
      .then((d) => {
        const top = (d.features || []).slice(0, 3).map((f) => ({
          mag: f.properties?.mag,
          place: f.properties?.place,
          timeUtc: f.properties?.time ? new Date(f.properties.time).toISOString() : null,
        }));
        out.usgs_m45_24h = { count: d.metadata?.count, latest: top };
      })
      .catch((e) => {
        out.usgs_m45_24h = { error: e.message };
      }),
    Promise.all([
      fetch('https://api.coinbase.com/v2/prices/BTC-USD/spot').then((r) => r.json()),
      fetch('https://api.coinbase.com/v2/prices/ETH-USD/spot').then((r) => r.json()),
    ])
      .then(([btc, eth]) => {
        out.coinbase_spot_usd = {
          BTC: btc?.data?.amount || null,
          ETH: eth?.data?.amount || null,
        };
      })
      .catch((e) => {
        out.coinbase_spot_usd = { error: e.message };
      }),
  ];
  await Promise.all(tasks);
  return out;
}

async function runCoordinator(query) {
  appendMsg('Visitor', query, null, true);
  const q = query.toLowerCase();

  if (q.includes('audit') || q.includes('manifest') || q.includes('http')) {
    const urlMatch = query.match(/https?:\/\/[^\s]+/i);
    const target = urlMatch ? urlMatch[0] : selfBaseUrl();
    appendMsg('verimesh_coordinator -> manifest_conformance_auditor', `Auditing ${target} against MVP Profile 0.3...`);
    const rep = await runSiteAudit(target);
    appendMsg('manifest_conformance_auditor', `Conformance result: ${rep.score ?? 'ERR'}/100 (${rep.grade ?? 'FAIL'})`, rep.graphSummary || rep);
    return;
  }

  if (q.includes('usgs') || q.includes('earthquake') || q.includes('coinbase') || q.includes('btc') || q.includes('price')) {
    appendMsg('verimesh_coordinator -> primary_source_verifier', 'Querying live zero-key CORS endpoints (USGS + Coinbase)...');
    const data = await fetchLivePrimarySources();
    appendMsg('primary_source_verifier', 'Live primary-source readings retrieved directly in browser:', data);
    return;
  }

  if (q.includes('fmea') || q.includes('rpn') || q.includes('fda') || q.includes('iso') || q.includes('as9100')) {
    const std = q.includes('iso') ? 'ISO_13485' : q.includes('as9100') ? 'AS9100D' : 'FDA_21CFR11';
    const payload = { standard: std, severity: 8, occurrence: 4, detectability: 3 };
    const approved = await requestPeerConsent({
      peerUrl: './compliance_fmea_peer.network.json',
      peerLabel: 'ChangeProof Compliance Peer Network',
      actionName: 'site_action_score_fmea_rpn',
      payload,
    });
    if (!approved) {
      appendMsg('peer_policy_guardian', 'Peer delegation cancelled by visitor. Zero data sent.');
      return;
    }
    const res = evaluateFmeaRpn(payload);
    appendMsg('compliance_fmea_peer (approved)', `Computed ${res.standardName} RPN=${res.rpn} (${res.tier}):`, res);
    return;
  }

  if (q.includes('sha') || q.includes('chain') || q.includes('tamper') || q.includes('ledger')) {
    const payload = { entries: 2, simulateTamper: true };
    const approved = await requestPeerConsent({
      peerUrl: './compliance_fmea_peer.network.json',
      peerLabel: 'ChangeProof Compliance Peer Network',
      actionName: 'site_action_verify_sha256_chain',
      payload,
    });
    if (!approved) {
      appendMsg('peer_policy_guardian', 'Peer delegation cancelled by visitor.');
      return;
    }
    const chain = await buildAuditChain([
      { issueKey: 'QMS-42', actor: 'acct-eng-01', role: 'PROPOSER', rationale: 'Calibrate sterile fill sensor.' },
      { issueKey: 'QMS-42', actor: 'acct-qa-09', role: 'QA_APPROVER', rationale: 'Independent QA verified IQ/OQ.' },
    ]);
    const intact = await verifyAuditChain(chain);
    const mutated = structuredClone(chain);
    mutated[1].rationale += '!';
    const tampered = await verifyAuditChain(mutated);
    appendMsg('compliance_fmea_peer (approved)', 'Web Crypto SHA-256 chain verification & 1-byte tamper test:', {
      intact_verification: intact,
      after_1_byte_mutation: tampered,
    });
    return;
  }

  // Optional BYOK OpenAI-compatible / Mozilla Otari call if user supplied a key
  const byok = getByokConfig();
  if (byok.apiKey) {
    appendMsg('verimesh_coordinator (BYOK)', `Calling ${byok.baseUrl} with model ${byok.model}...`);
    try {
      const resp = await fetch(`${byok.baseUrl.replace(/\/$/, '')}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${byok.apiKey}`,
        },
        body: JSON.stringify({
          model: byok.model,
          messages: [
            { role: 'system', content: 'You are verimesh_coordinator, an Open Agentic Web MVP Profile 0.3 specialist.' },
            { role: 'user', content: query },
          ],
        }),
      });
      const json = await resp.json();
      const text = json?.choices?.[0]?.message?.content || JSON.stringify(json);
      appendMsg('verimesh_coordinator (BYOK)', text);
      return;
    } catch (e) {
      appendMsg('verimesh_coordinator (BYOK Error)', `Router call failed (fail-closed): ${e.message}`);
      return;
    }
  }

  appendMsg(
    'verimesh_coordinator',
    'Try one of the sample prompts above (Self-Audit Manifest, Live USGS + Coinbase, Peer Delegate FDA FMEA, or SHA-256 Chain), or configure a BYOK router key for open-ended LLM chat.'
  );
}

async function renderPublishedGraph() {
  try {
    const net = await fetchJsonSafe('./verimesh_trust_auditor.network.json');
    graphCards.innerHTML = '';
    for (const tool of net.tools || []) {
      const card = document.createElement('article');
      card.className = 'agent-node';
      const h3 = document.createElement('h3');
      h3.textContent = tool.name;
      const p = document.createElement('p');
      p.textContent = tool.function?.description || '';
      const meta = document.createElement('div');
      meta.innerHTML = `<strong>Tools:</strong> ${(tool.tools || []).map((t) => `<code>${t}</code>`).join(' ')}`;
      card.append(h3, p, meta);
      graphCards.append(card);
    }
  } catch (e) {
    graphCards.textContent = `Could not load local network graph: ${e.message}`;
  }
}

auditForm.addEventListener('submit', (e) => {
  e.preventDefault();
  if (siteUrlInput.value.trim()) runSiteAudit(siteUrlInput.value.trim());
});

document.querySelectorAll('[data-preset]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const url = btn.dataset.preset === 'self' ? selfBaseUrl() : COGNIZANT_REF_BASE;
    siteUrlInput.value = url;
    runSiteAudit(url);
  });
});

document.querySelectorAll('[data-query]').forEach((btn) => {
  btn.addEventListener('click', () => {
    runCoordinator(btn.dataset.query);
  });
});

chatForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const q = chatInput.value.trim();
  if (!q) return;
  chatInput.value = '';
  runCoordinator(q);
});

document.getElementById('open-byok-btn').addEventListener('click', () => {
  const cfg = getByokConfig();
  byokBaseUrl.value = cfg.baseUrl;
  byokModel.value = cfg.model;
  byokApiKey.value = cfg.apiKey;
  byokDialog.showModal();
});

document.getElementById('byok-clear-btn').addEventListener('click', () => {
  sessionStorage.removeItem('verimesh_byok_key');
  byokApiKey.value = '';
  updateRouterPill();
  byokDialog.close();
});

byokForm.addEventListener('submit', () => {
  sessionStorage.setItem('verimesh_byok_url', byokBaseUrl.value.trim() || 'https://api.otari.ai/api/v1');
  sessionStorage.setItem('verimesh_byok_model', byokModel.value.trim() || 'alibaba/qwen3.8-flash');
  if (byokApiKey.value.trim()) {
    sessionStorage.setItem('verimesh_byok_key', byokApiKey.value.trim());
  } else {
    sessionStorage.removeItem('verimesh_byok_key');
  }
  updateRouterPill();
});

// Boot
siteUrlInput.value = selfBaseUrl();
updateRouterPill();
renderPublishedGraph();
runSiteAudit(selfBaseUrl());
appendMsg(
  'verimesh_coordinator',
  'Ready in Zero-Key Deterministic Mode. Click any sample action to audit an Open Agentic Website, query live public APIs, or test consent-gated peer delegation.'
);
