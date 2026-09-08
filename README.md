# SecGraphAI

**Security testing for systems that think and act.**

SecGraphAI is a local-first Python toolkit for describing an AI application's security
graph, declaring security invariants, collecting deterministic evidence, protecting
Python tools at runtime, and producing actionable scan reports. Version 1.0.0rc1 connects
the product-requirements architecture into testable end-to-end workflows while the
independent pre-1.0 security review remains open.

It includes OpenAPI/identity, RAG, MCP, provenance and policy testing; independent target,
attack, judge, and remediation model roles; adaptive attack selection and signed packs;
baselines, safe replay bundles, pytest regression generation, SARIF/JUnit output; OWASP
profiles, CycloneDX/SPDX and offline CVE intelligence; plugin process/container isolation;
an authenticated, local-only dashboard; utility/cost comparisons; research draft import;
model supply-chain inspection; and bounded multimodal artifact handling.

## Install

```bash
pip install secgraphai
```

Python 3.11 or newer is required.

## Quick start

```python
from secgraphai import SecGraph, invariant, secgraph

@secgraph.tool(permission="crm.read")
def lookup_customer(customer_id: str) -> dict[str, str]:
    return {"id": customer_id}

security = SecGraph(invariants=[
    invariant("NO_SECRET_EXFIL", source={"sensitivity": "secret"},
              destination={"trust": "external"}, expected="deny")
])
report = security.scan_callback(lambda prompt: "I cannot disclose protected data")
print(report.summary())
```

Create a safe starter configuration and inspect it:

```bash
secgraph init
secgraph doctor
secgraph discover ./src
secgraph scan --callback module:function --format json
secgraph replay scan.secgraph --callback module:function --fail-on-violation
secgraph cve status --cache cve-cache.json
```

Remote targets must be explicitly allow-listed. API keys are referenced through
environment variables and are never serialized into reports.

## Documentation

The [detailed user guide](docs/USER_GUIDE.md) covers installation extras, safety modes,
scope configuration, callback and OpenAI-compatible scans, local/OpenTelemetry/MCP
discovery, API identity matrices, RAG isolation, agent analysis, invariants, reports,
replay and baselines, OWASP CI gates, SBOM/CVE workflows, plugins, and the dashboard API.

Common starting points:

| Goal | Start with |
| --- | --- |
| Inventory an application without importing it | `secgraph discover ./src` |
| Test an application callback | `secgraph scan --callback module:function` |
| Test a model API | `secgraph scan --target https://host/v1 --model name` |
| Add a security regression gate | `secgraph replay scan.secgraph --callback module:function --fail-on-violation` |
| Explore saved results locally | `pip install "secgraphai[dashboard]"` and `secgraph serve` |

## Release-candidate capabilities

- OpenAI-compatible async model client, bounded attack planner, prompt-injection families,
  deterministic validators, judge ensembles, cost/request/time budgets, and sanitized traces
- callback, OpenAPI/API identity, RAG, MCP, agent, model-artifact, and multimodal targets
- typed/versioned findings, evidence, interactions, manifests, verdicts, and attack packs
- security/attack graphs, declarative invariants, runtime provenance and firewall policies
- FastAPI/httpx/OpenAI/MCP/LangChain/LangGraph instrumentation and OpenTelemetry events
- baselines, differential utility/security measurement, tamper-checked replay bundles,
  generated pytest/YAML/CI regressions, and SQLite storage
- JSON, JSONL, HTML, Markdown, CSV, SARIF, JUnit, and optional PDF reports
- authenticated local dashboard/API with security headers, limits, and live events
- CycloneDX/SPDX generation and ingestion, NVD/CVSS/CWE/KEV parsing, affected-version and reachability gates
- permission-gated subprocess adapters, Ed25519 pack verification, doctor, and self-audit

See [`SecGraphAI_PRD_v3.1_CVE_OWASP.md`](SecGraphAI_PRD_v3.1_CVE_OWASP.md) for the
product roadmap. Only test systems you are authorized to assess.

## Development

```bash
python -m pip install -e '.[test,api,security]'
python -m coverage run --branch -m pytest
python -m coverage report --include='src/secgraphai/*' --fail-under=90
python -m ruff check src tests demo
python -m mypy src
python -m bandit -q -r src
python -m build
```

The benchmark in `demo/` provides vulnerable and hardened modes for six seeded behaviors:
object authorization, approval gates, indirect prompt injection and RAG isolation, external
data flow, and runaway agent recursion. `demo.assessment.assess_demo` drives both variants
through SecGraphAI's public API, RAG, and agent modules; the test suite requires every seeded
behavior to be detected in the vulnerable app and absent from the hardened app. The release
workflow generates a CycloneDX SBOM and uses trusted publishing plus build-provenance
attestation.

## Security

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability.
