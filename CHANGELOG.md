# Changelog

All notable changes to SecGraphAI are documented here. The project follows Semantic
Versioning and the format is based on Keep a Changelog.

## [Unreleased]

## [1.0.0rc3] - 2026-09-08

- Added a dedicated BYOK and AI model guide covering the exact HTTP contract, PowerShell,
  Bash, CI secrets, local Ollama, hosted OpenAI-compatible endpoints, and troubleshooting.
- Documented when each target, attack, judge, and remediation model role is invoked and how
  to isolate their endpoints and credentials.
- Added mocked provider tests for bearer-header construction, environment-based key rotation,
  missing-key behavior, direct-key precedence, and credential-safe representations.

## [1.0.0rc2] - 2026-09-07

- Reworked the PyPI project page into a scenario-driven guide for real application threats.
- Expanded annotation guidance for permission, approval, policy, context, and instrumentation boundaries.
- Added a complete CLI reference covering every command, argument, option, default, and security gate.
- Added practical workflows for unauthorized refunds, poisoned RAG, cross-tenant API access,
  MCP capability drift, excessive agent behavior, model scanning, and CI regression replay.

- Enforced PASSIVE, SAFE, LAB, and CUSTOM request modes and recorded finding reproduction inputs.
- Added executable replay verification, persisted dashboard scan jobs, and authenticated live events.
- Added four independent model roles, boundary-progress adaptive search, and a package-driven
  six-behavior vulnerable/hardened benchmark.
- Added incremental CVE cache metadata/freshness and digest-pinned container plugin isolation.
- Added resumable, rate-aware NVD paging and all PRD-documented installation extras.
- Added MCP and OpenTelemetry architecture discovery with graph relationships and public APIs.
- Added a detailed user guide with callback, model, API, RAG, MCP, agent, CI, and dashboard scenarios.
- Expanded security and integration coverage to more than 450 tests.
- Completed principal/tool/condition/control invariant evaluation and full resource accounting.
- Expanded RAG, MCP, API, and agent checks and normalized every declared external-engine format.
- Added live FastAPI route discovery, declared graph relationships, and environment-name-only metadata.
- Added conditional/delta NVD synchronization, encrypted/retained storage, optional PII masking,
  broader credential redaction, DNS rebinding detection, and replay compression-ratio limits.
- Added baseline-aware `secgraph test`, historical policy simulation, and dedicated dashboard views.

## [1.0.0rc1] - 2026-09-07

- Connected attack planning, validators, target execution, policy enforcement, and evidence.
- Added complete CLI workflow groups, dashboard API/frontend, CVE/CycloneDX/SPDX intelligence,
  instrumentation, security modules, adapters, signed packs, and benchmark applications.
- Added release-candidate security, property, integration, and packaging verification.

## [0.9.0] - 2026-09-07

- Added validators, judge ensembles, API/identity, RAG, MCP, provenance, and policy primitives.
- Added adaptive planning, memory, novelty/evolution, and signed attack packs.
- Added baselines, replay bundles, pytest generation, SARIF, and JUnit.
- Added OWASP coverage, SBOM/CVE intelligence, security gates, plugin isolation, and dashboard API.
- Expanded the suite with over 300 parameterized unit and security cases.

## [0.1.0] - 2026-09-07

### Added

- Initial package, CLI, OpenAI-compatible model adapter, and callback scanner.
- Typed security graph, invariants, findings, evidence, and verdicts.
- Runtime authorization and approval interception.
- Deterministic canaries, scope controls, secret redaction, configuration doctor,
  secure HTML/JSON reporting, and SQLite report storage.
