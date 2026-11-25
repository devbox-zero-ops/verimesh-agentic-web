/**
 * VeriMesh Conformance & Cryptographic Compliance Engine (Isomorphic ES Module)
 * Zero external dependencies — runs identically in modern browsers and Node.js 18+.
 */

export const STANDARDS = {
  FDA_21CFR11: { code: 'FDA_21CFR11', name: 'FDA 21 CFR Part 11', highRpn: 60, criticalRpn: 120, sopDays: 365 },
  ISO_13485: { code: 'ISO_13485', name: 'ISO 13485:2016', highRpn: 48, criticalRpn: 100, sopDays: 365 },
  AS9100D: { code: 'AS9100D', name: 'AS9100D Aerospace', highRpn: 45, criticalRpn: 90, sopDays: 180 },
};

/**
 * Audit an Open Agentic Website against Worldwide Agentic Web MVP Profile 0.3.
 */
export function auditAgenticSite({ baseUrl, manifest, network, nsdeploy }) {
  const checks = [];
  const add = (id, label, weight, passed, detail) => {
    checks.push({ id, label, weight, passed: Boolean(passed), detail });
  };

  // 1. Manifest presence & brand
  add(
    'manifest_root',
    'Valid agent-manifest.json with brand & networks[]',
    15,
    Boolean(manifest && typeof manifest === 'object' && Array.isArray(manifest.networks) && manifest.networks.length > 0),
    manifest && Array.isArray(manifest.networks)
      ? `Found ${manifest.networks.length} published network(s) under brand "${manifest.brand || 'Unnamed'}".`
      : 'Missing or invalid agent-manifest.json or empty networks array.'
  );

  const primaryNet = manifest && Array.isArray(manifest.networks) ? manifest.networks[0] : null;

  // 2. Network metadata & front_man declaration
  add(
    'network_identity',
    'Primary network declares name, front_man & hocon/json path',
    10,
    Boolean(primaryNet && primaryNet.name && primaryNet.front_man && primaryNet.hocon),
    primaryNet
      ? `name="${primaryNet.name}", front_man="${primaryNet.front_man}", hocon="${primaryNet.hocon}"`
      : 'Primary network entry is missing required identity fields.'
  );

  // 3. Resolved network definition (Neuro SAN data-only JSON)
  const tools = network && Array.isArray(network.tools) ? network.tools : [];
  add(
    'resolved_network',
    'Resolved data-only network JSON with tools[] graph',
    15,
    Boolean(network && network.metadata && tools.length > 0),
    tools.length > 0
      ? `Resolved ${tools.length} agent/tool definition(s) in portable JSON.`
      : 'Network JSON missing metadata or non-empty tools[] array.'
  );

  // 4. Front agent exists in tools[] & has instructions + function.description
  const frontAgent = primaryNet ? tools.find((t) => t && t.name === primaryNet.front_man) : null;
  const frontValid = Boolean(
    frontAgent &&
      frontAgent.function &&
      typeof frontAgent.function.description === 'string' &&
      frontAgent.function.description.trim().length >= 10 &&
      typeof frontAgent.instructions === 'string' &&
      frontAgent.instructions.trim().length >= 10
  );
  add(
    'front_agent_valid',
    'Front agent reachable in tools[] with description & instructions',
    15,
    frontValid,
    frontValid
      ? `Front agent "${frontAgent.name}" exposes function schema and grounded instructions.`
      : `Front agent "${primaryNet?.front_man || '?'}" missing or incomplete in network tools[].`
  );

  // 5. Internal agent references resolve cleanly (no dangling local names)
  const toolNames = new Set(tools.map((t) => t && t.name).filter(Boolean));
  const dangling = [];
  for (const agent of tools) {
    for (const ref of Array.isArray(agent.tools) ? agent.tools : []) {
      if (typeof ref === 'string') {
        const isExternalOrAction =
          ref.startsWith('http://') ||
          ref.startsWith('https://') ||
          ref.startsWith('./') ||
          ref.startsWith('/') ||
          ref.startsWith('site_action_') ||
          ref.startsWith('website_');
        if (!isExternalOrAction && !toolNames.has(ref)) {
          dangling.push(`${agent.name} -> ${ref}`);
        }
      }
    }
  }
  add(
    'graph_integrity',
    'All internal sub-agent references resolve without dangling links',
    10,
    tools.length > 0 && dangling.length === 0,
    dangling.length === 0
      ? `All ${toolNames.size} internal agent node(s) resolve cleanly.`
      : `Dangling references: ${dangling.join(', ')}`
  );

  // 6. Pluggable inference / BYOK router declaration
  const hasRouter = Boolean(
    manifest && manifest.llm_router && (manifest.llm_router.base_url || manifest.llm_router.byok_router)
  );
  add(
    'pluggable_inference',
    'Declares pluggable LLM router / BYOK endpoint',
    10,
    hasRouter,
    hasRouter
      ? `Router: ${manifest.llm_router.byok_router || manifest.llm_router.base_url}`
      : 'No llm_router metadata declared in agent-manifest.json.'
  );

  // 7. Peer policy & trust boundary
  const pp = manifest && manifest.peer_policy ? manifest.peer_policy : null;
  const safePeerPolicy = Boolean(pp && (pp.mode === 'closed' || pp.mode === 'allowlist' || Array.isArray(manifest.allowed_peers)));
  add(
    'peer_policy',
    'Explicit peer_policy trust boundary (closed/allowlist)',
    10,
    safePeerPolicy,
    pp
      ? `mode="${pp.mode || 'unspecified'}", allowed_peers=${Array.isArray(manifest.allowed_peers) ? manifest.allowed_peers.length : 0}`
      : 'Missing peer_policy metadata.'
  );

  // 8. Private context (sly_data) deny-by-default hygiene (no secrets in public JSON)
  const serialized = JSON.stringify({ manifest, network }).toLowerCase();
  const hasLeakedSecret = /(sk-[a-z0-9]{20,}|ghp_[a-z0-9]{20,}|atatt3x|bearer\s+[a-z0-9._-]{20,})/i.test(serialized);
  add(
    'secret_hygiene',
    'Zero leaked credentials or private keys in public manifest/network',
    10,
    !hasLeakedSecret,
    hasLeakedSecret
      ? 'CRITICAL: Potential API key or bearer token pattern detected in public JSON!'
      : 'Public JSON artifacts are clean of credential/token patterns.'
  );

  // 9. Well-known nsdeploy-link/v1 discovery endpoint
  const hasNsdeploy = Boolean(nsdeploy && nsdeploy.protocol === 'nsdeploy-link/v1' && Array.isArray(nsdeploy.exports));
  add(
    'well_known_discovery',
    'Publishes .well-known/nsdeploy.json (nsdeploy-link/v1)',
    5,
    hasNsdeploy,
    hasNsdeploy
      ? `Exports ${nsdeploy.exports.length} discoverable network(s) via nsdeploy-link/v1.`
      : 'Optional .well-known/nsdeploy.json not found or non-conforming.'
  );

  const totalWeight = checks.reduce((s, c) => s + c.weight, 0);
  const earned = checks.reduce((s, c) => s + (c.passed ? c.weight : 0), 0);
  const score = Math.round((earned / totalWeight) * 100);
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'F';

  return {
    baseUrl,
    score,
    grade,
    passedCount: checks.filter((c) => c.passed).length,
    totalChecks: checks.length,
    checks,
    graphSummary: {
      networkName: primaryNet?.name || null,
      frontAgent: primaryNet?.front_man || null,
      agentCount: tools.length,
      peerLinks: Object.keys(network?.link_labels || {}),
    },
  };
}

/**
 * Deterministic FMEA Risk Priority Number (RPN) scorer for regulated change control.
 */
export function evaluateFmeaRpn({ standard = 'FDA_21CFR11', severity, occurrence, detectability }) {
  const profile = STANDARDS[standard] || STANDARDS.FDA_21CFR11;
  const s = Math.max(1, Math.min(10, Math.round(Number(severity) || 1)));
  const o = Math.max(1, Math.min(10, Math.round(Number(occurrence) || 1)));
  const d = Math.max(1, Math.min(10, Math.round(Number(detectability) || 1)));
  const rpn = s * o * d;
  const tier = rpn >= profile.criticalRpn ? 'CRITICAL' : rpn >= profile.highRpn ? 'HIGH' : rpn >= 24 ? 'MEDIUM' : 'LOW';
  const requiredSigners =
    tier === 'CRITICAL' || tier === 'HIGH'
      ? ['PROPOSER', 'QA_APPROVER', 'RELEASE_AUTHORITY']
      : ['PROPOSER', 'QA_APPROVER'];
  return {
    standard: profile.code,
    standardName: profile.name,
    severity: s,
    occurrence: o,
    detectability: d,
    rpn,
    tier,
    requiredSigners,
    separationOfDutiesRequired: true,
  };
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    const buf = await subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function canonicalPayload(entry) {
  return JSON.stringify({
    seq: entry.seq,
    issueKey: entry.issueKey,
    actor: entry.actor,
    role: entry.role,
    rationale: entry.rationale,
    timestamp: entry.timestamp,
  });
}

export async function buildAuditChain(rawEntries) {
  let prevHash = '0'.repeat(64);
  const out = [];
  for (let i = 0; i < rawEntries.length; i++) {
    const base = {
      seq: i + 1,
      issueKey: rawEntries[i].issueKey,
      actor: rawEntries[i].actor,
      role: rawEntries[i].role,
      rationale: rawEntries[i].rationale,
      timestamp: rawEntries[i].timestamp || '2026-11-25T00:00:00Z',
    };
    const payloadHash = await sha256Hex(canonicalPayload(base));
    const entryHash = await sha256Hex(`${prevHash}:${payloadHash}`);
    out.push({ ...base, prevHash, payloadHash, entryHash });
    prevHash = entryHash;
  }
  return out;
}

export async function verifyAuditChain(entries) {
  let expectedPrev = '0'.repeat(64);
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.prevHash !== expectedPrev) {
      return { valid: false, status: 'TAMPERED', brokenAt: i + 1, reason: 'prevHash_mismatch' };
    }
    const recomputedPayload = await sha256Hex(canonicalPayload(e));
    if (recomputedPayload !== e.payloadHash) {
      return { valid: false, status: 'TAMPERED', brokenAt: i + 1, reason: 'payloadHash_mismatch' };
    }
    const recomputedEntry = await sha256Hex(`${e.prevHash}:${recomputedPayload}`);
    if (recomputedEntry !== e.entryHash) {
      return { valid: false, status: 'TAMPERED', brokenAt: i + 1, reason: 'entryHash_mismatch' };
    }
    expectedPrev = recomputedEntry;
  }
  return {
    valid: true,
    status: 'VERIFIED',
    entries: entries.length,
    headHash: expectedPrev,
  };
}
