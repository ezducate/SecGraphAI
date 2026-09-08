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
