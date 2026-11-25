import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  auditAgenticSite,
  buildAuditChain,
  evaluateFmeaRpn,
  verifyAuditChain,
} from '../js/conformance-engine.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const loadJson = (rel) => JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));

test('VeriMesh own manifest, primary network, peer network & .well-known pass 100/100 MVP Profile 0.3', () => {
  const manifest = loadJson('agent-manifest.json');
  const network = loadJson('verimesh_trust_auditor.network.json');
  const nsdeploy = loadJson('.well-known/nsdeploy.json');

  const res = auditAgenticSite({
    baseUrl: 'https://devbox-zero-ops.github.io/verimesh-agentic-web/',
    manifest,
    network,
    nsdeploy,
  });

  assert.equal(res.score, 100);
  assert.equal(res.grade, 'A+');
  assert.equal(res.passedCount, res.totalChecks);
  assert.equal(res.graphSummary.frontAgent, 'verimesh_coordinator');
  assert.equal(res.graphSummary.agentCount, 4);

  // Also verify peer network conforms when audited directly
  const peerManifest = { ...manifest, networks: [manifest.networks[1]] };
  const peerNetwork = loadJson('compliance_fmea_peer.network.json');
  const peerRes = auditAgenticSite({
    baseUrl: 'https://devbox-zero-ops.github.io/verimesh-agentic-web/',
    manifest: peerManifest,
    network: peerNetwork,
    nsdeploy,
  });
  assert.equal(peerRes.score, 100);
});

test('Conformance engine catches dangling sub-agents and leaked API keys', () => {
  const badManifest = {
    brand: 'Broken Site',
    networks: [{ name: 'net1', front_man: 'coord', hocon: './net1.json' }],
    peer_policy: { mode: 'closed' },
  };
  const badNetwork = {
    metadata: { description: 'Broken network with leaked key sk-1234567890abcdefghijklmno' },
    tools: [
      {
        name: 'coord',
        function: { description: 'Coordinator agent for testing' },
        instructions: 'Delegate to missing_agent.',
        tools: ['missing_agent'],
      },
    ],
  };
  const res = auditAgenticSite({ baseUrl: 'https://example.test/', manifest: badManifest, network: badNetwork, nsdeploy: null });
  assert.ok(res.score < 70);
  const byId = Object.fromEntries(res.checks.map((c) => [c.id, c.passed]));
  assert.equal(byId.graph_integrity, false);
  assert.equal(byId.secret_hygiene, false);
  assert.equal(byId.well_known_discovery, false);
});

test('Peer FMEA RPN thresholds & SHA-256 tamper detection work deterministically', async () => {
  const fda = evaluateFmeaRpn({ standard: 'FDA_21CFR11', severity: 8, occurrence: 4, detectability: 3 });
  assert.equal(fda.rpn, 96);
  assert.equal(fda.tier, 'HIGH');
  assert.equal(fda.requiredSigners.length, 3);

  const chain = await buildAuditChain([
    { issueKey: 'QMS-42', actor: 'acct-eng-01', role: 'PROPOSER', rationale: 'Calibrate sterile fill sensor.' },
    { issueKey: 'QMS-42', actor: 'acct-qa-09', role: 'QA_APPROVER', rationale: 'Verified IQ/OQ report.' },
  ]);
  const okRes = await verifyAuditChain(chain);
  assert.equal(okRes.valid, true);
  assert.equal(okRes.status, 'VERIFIED');

  // Mutate 1 byte
  const tampered = structuredClone(chain);
  tampered[1].rationale += '!';
  const badRes = await verifyAuditChain(tampered);
  assert.equal(badRes.valid, false);
  assert.equal(badRes.status, 'TAMPERED');
  assert.equal(badRes.brokenAt, 2);
});
