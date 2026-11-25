# VeriMesh — Open Agentic Web Trust, Primary-Source & Peer Discovery Hub

**VeriMesh** is an open-source, zero-dependency reference site and reusable trust-infrastructure tool conforming to the **[Worldwide Agentic Web Minimum Viable Specification (MVP Profile 0.3)](https://github.com/cognizant-ai-labs/agentic-web/blob/main/docs/worldwide_agentic_web_mvp_spec.md)**.

- **Live Open Agentic Website (GitHub Pages):** https://devbox-zero-ops.github.io/verimesh-agentic-web/
- **Published Site Manifest:** [`agent-manifest.json`](agent-manifest.json)
- **Primary Agent Network (Neuro SAN JSON):** [`verimesh_trust_auditor.network.json`](verimesh_trust_auditor.network.json)
- **Linked Peer Agent Network:** [`compliance_fmea_peer.network.json`](compliance_fmea_peer.network.json)
- **Discovery Metadata:** [`.well-known/nsdeploy.json`](.well-known/nsdeploy.json) · [`.well-known/nsdeploy-agent.json`](.well-known/nsdeploy-agent.json)

## What It Builds for the Open Agentic Web

1. **Live MVP Profile 0.3 Conformance Auditor (`js/conformance-engine.mjs`)**:
   - Inspects any Open Agentic Website URL directly in the browser over CORS fail-closed `fetch()`.
   - Validates `agent-manifest.json`, resolved `.network.json`, front-agent schema/instructions reachability, internal sub-agent graph integrity (zero dangling refs), pluggable `llm_router` / BYOK metadata, `peer_policy` boundaries, zero leaked secrets, and `.well-known/nsdeploy.json` (`nsdeploy-link/v1`).
   - Ships as an isomorphic ES module (`js/conformance-engine.mjs`) usable both in browsers and CI (`node --test`).
2. **Consent-Gated Peer Delegation & `sly_data` Isolation**:
   - Demonstrates live cross-network delegation from `verimesh_trust_auditor` to `compliance_fmea_peer` behind an explicit native `<dialog>` consent gate (`Approve Peer Call` / `Decline`), stripping private `sly_data` and isolating BYOK credentials strictly in `sessionStorage`.
3. **Zero-Key Deterministic Mode + Pluggable BYOK Router (Mozilla Otari / OpenAI-Compatible)**:
   - Works immediately with zero API keys (live browser queries to USGS Earthquakes & Coinbase Spot, plus deterministic FDA 21 CFR Part 11 / ISO 13485 / AS9100D FMEA RPN and Web Crypto SHA-256 tamper-evident audit chains), while supporting visitor-supplied BYOK keys via `https://api.otari.ai/api/v1` or any OpenAI-compatible router.

## Local Verification

```bash
node --test tests/conformance.test.mjs
```

## License

MIT — see [LICENSE](LICENSE).
