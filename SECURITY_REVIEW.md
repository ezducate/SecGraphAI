# Security review checklist

The release candidate is ready for an independent review of:

- [ ] target URL parsing, DNS resolution, redirects, and scope budgets
- [ ] secret storage and recursive report redaction
- [ ] plugin manifests, subprocess containment, and container-mode design
- [ ] attack-pack trust and Ed25519 signature verification
- [ ] policy matching, default deny, approvals, and shadow-mode explanations
- [ ] dashboard authentication, headers, CORS assumptions, request limits, and WebSockets
- [ ] replay archive validation and evidence hashes
- [ ] CVE/NVD data parsing and affected-version decisions
- [ ] vulnerable/hardened benchmark detection and utility preservation

No unchecked item should be represented as independently reviewed. Findings should be
reported using the process in `SECURITY.md` and resolved or explicitly accepted before a
final 1.0 release.

## Engineering readiness evidence

The independent sign-off above remains intentionally separate from repository-owned
verification. As of the 1.0 release candidate, the codebase itself exercises:

- URL allowlists, private/special network blocking, DNS revalidation, disabled redirects,
  request/rate/time/cost budgets, response-size limits, and nested-document limits;
- recursive secret/cookie/session redaction, optional PII masking, encrypted SQLite records,
  and automatic evidence-retention pruning;
- permission-gated process plugins, digest-pinned hardened container commands, bounded JSON
  input/output, schema checks, and hostile native-result normalization;
- Ed25519 verification for the bundled official data-only attack pack;
- default-deny policy matching, approvals, shadow decisions, explanations, and historical
  simulation;
- authenticated dashboard routes and WebSockets, browser security headers, request limits,
  local-by-default binding, and explicit remote/TLS warnings;
- replay member allowlists, duplicate/path/size/compression-ratio checks, manifest hashes,
  and per-evidence/report/regression SHA-256 manifests;
- bounded NVD parsing, conditional and modified-date delta synchronization, affected-version
  decisions, SBOM correlation, and vulnerable/hardened benchmark assertions.

CI separately runs Python-version tests, branch coverage, Ruff, mypy, Bandit, dependency
auditing, builds, wheel smoke tests, secret scanning, CodeQL, Semgrep, mutation testing,
fuzzing, dynamic benchmark tests, and self-dogfooding. These controls provide review inputs;
they do not substitute for the independent manual review required before final 1.0.
