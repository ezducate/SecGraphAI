# SecGraphAI user guide

SecGraphAI is a local-first security testing toolkit for AI applications, agents,
retrieval systems, MCP servers, APIs, and OpenAI-compatible model endpoints. It helps you
describe security boundaries, run bounded tests, capture deterministic evidence, enforce
runtime controls, and turn findings into repeatable regressions.

Use SecGraphAI only against systems you own or are authorized to assess. Start in
`PASSIVE` or `SAFE` mode, use synthetic data, set explicit host and request limits, and
reserve `LAB` mode for isolated test environments.

## Installation

Python 3.11 or newer is required.

```bash
pip install secgraphai
```

Install only the optional capabilities you need:

```bash
pip install "secgraphai[dashboard]"     # local dashboard and HTTP API
pip install "secgraphai[mcp]"           # MCP support (no additional dependency today)
pip install "secgraphai[rag]"           # RAG support (bring your own retriever client)
pip install "secgraphai[pii]"           # PII adapter entry point (bring your own engine)
pip install "secgraphai[otel]"          # OpenTelemetry event emission
pip install "secgraphai[evolution]"     # bounded evolutionary planner (included in core)
pip install "secgraphai[integrations]"  # Schemathesis and OpenTelemetry APIs
pip install "secgraphai[security]"      # signing, dependency audit, secret scanning
pip install "secgraphai[pdf]"           # PDF report output
pip install "secgraphai[research]"      # PDF research import
pip install "secgraphai[all]"           # all optional features and development tools
```

Confirm the installation and create a safe starter configuration:

```bash
secgraph --help
secgraph init
secgraph doctor
secgraph self-audit
```

`secgraph init` will not overwrite an existing configuration unless `--force` is used.
Configuration validation rejects unknown fields and expects secret *references*, such as
environment-variable names, rather than secret values.

## A first callback scan

A callback is the quickest way to test an application boundary. It accepts a prompt and
returns text, synchronously or asynchronously.

```python
# myapp.py
def answer(prompt: str) -> str:
    if "protected test token" in prompt.lower():
        return "I cannot disclose protected data."
    return "Request handled safely."
```

Run the safe profile and store a machine-readable report:

```bash
secgraph scan \
  --callback myapp:answer \
  --profile safe \
  --mode SAFE \
  --max-requests 25 \
  --max-duration 60 \
  --output report.json \
  --format json
```

The equivalent Python workflow is:

```python
import asyncio

from secgraphai import SecGraph
from secgraphai.scanner import ScanBudget


async def main() -> None:
    scanner = SecGraph(
        mode="SAFE",
        budget=ScanBudget(max_requests=25, max_duration_seconds=60),
    )
    report = await scanner.scan(
        lambda prompt: "I cannot disclose protected data.",
        modules=["prompt-injection", "agent"],
        strategy="adaptive",
        attack_budget=25,
    )
    report.save("report.json")
    print(report.summary())


asyncio.run(main())
```

Each report includes typed findings, sanitized interactions, resource totals, a scan
manifest, errors, limitations, and a graph snapshot. A scan can finish with zero findings
while still recording test errors, so check both `report.summary()` and `report.errors`.

## Safety modes and scope

The execution mode and network scope are separate controls:

| Mode | Intended use | Behavior |
| --- | --- | --- |
| `PASSIVE` | Production inventory | Metadata discovery only; active scanner probes are rejected. |
| `SAFE` | Normal authorized testing | Allows bounded reads and safe probes; blocks active and destructive writes. |
| `LAB` | Isolated test systems | Permits active test actions, still subject to explicit scope and budgets. |
| `CUSTOM` | Reviewed special cases | Permits only actions explicitly named in `allowed_actions`. |

Network clients use `ScopeGuard` to enforce the exact hostname, port, blocked network
ranges, total requests, request rate, duration, and prohibited action classes before a
request is sent.

```python
from secgraphai.security import Scope, ScopeGuard

scope = Scope(
    allowed_hosts=frozenset({"staging.example.test"}),
    allowed_ports=frozenset({443}),
    max_total_requests=50,
    max_requests_per_second=2,
    max_duration_seconds=120,
    prohibit=frozenset({"destructive_write", "account_deletion"}),
    require_stable_dns=True,
)
guard = ScopeGuard(scope)
```

Private, loopback, link-local, carrier-grade NAT, benchmark, and special-purpose networks
are blocked by default. DNS is resolved at authorization time and again immediately before
connection; a changed address set is rejected when `require_stable_dns` is enabled. The
CLI's `--allow-private` switch is meant for a local lab that you control; it is not a
general bypass for production scope review. Redirects are not followed.

## Scenario: discover an application architecture

Local discovery parses Python syntax and small JSON/YAML manifests without importing or
executing application code. It recognizes decorated agents, tools, retrievers, common API
routes, annotated parameters, OpenAPI and GraphQL operations, declared components, HTTP
traces, and selected OpenTelemetry attributes.

```bash
secgraph discover ./src
secgraph discover ./architecture.yaml --format json > inventory.json
```

A manifest can combine declared architecture and observed telemetry:

```yaml
agents:
  - id: support-agent
tools:
  - id: refund-tool
    privileged: true
    sends_to: [payments-api]
external_services:
  - id: payments-api
vector_stores:
  - id: customer-index
trust_boundaries:
  - id: public-network
otel_spans:
  - name: chat
    attributes:
      gen_ai.request.model: assistant-v2
      tool.name: refund-tool
  - name: customer-read
    attributes:
      http.request.method: GET
      http.route: /customers/{customer_id}
environment:
  - DATABASE_URL
  - MODEL_TOKEN
```

Relationship keys `calls`, `reads`, `writes`, `sends_to`, and `retrieves_from` become
typed graph edges when their target is unambiguous. Environment discovery records names
only and marks values as redacted; it never persists values from the manifest.

Use the public discovery API when you need to combine inventory with custom analysis:

```python
from secgraphai import discover_path

inventory = discover_path("src")
graph = inventory.to_graph()
print(inventory.counts())
print(graph.risk_paths())
```

For a live FastAPI or Starlette-style application object, route inventory is also available
without starting the server or executing handlers:

```python
from secgraphai import discover_fastapi
from myapp import app

inventory = discover_fastapi(app, source="staging-app")
```

Remote discovery fetches only the exact, explicitly supplied OpenAPI URL and enforces a
single-request scope:

```bash
secgraph discover https://staging.example.test/openapi.json --format json
```

For a controlled service on loopback, add `--allow-private` deliberately.

## Scenario: scan an OpenAI-compatible model endpoint

Set credentials in the environment and point the target at the API base that precedes
`/chat/completions`:

```bash
export STAGING_MODEL_TOKEN="..."
secgraph scan \
  --target https://models.example.test/v1 \
  --model assistant-v2 \
  --api-key-env STAGING_MODEL_TOKEN \
  --profile owasp-llm-2026 \
  --budget-usd 2.00 \
  --max-requests 40 \
  --output model-report.json \
  --format json
```

On PowerShell, set the variable with
`$env:STAGING_MODEL_TOKEN = "..."`. The variable name is recorded for reproducibility;
the credential value is not serialized into the report.

Programmatic model clients should receive a scope guard:

```python
from secgraphai import Model

target_model = Model(
    base_url="https://models.example.test/v1",
    model="assistant-v2",
    api_key_env="STAGING_MODEL_TOKEN",
    scope_guard=guard,
)
```

## Scenario: separate target, attack, judge, and remediation models

Keeping model roles explicit makes results easier to explain and allows independent
providers or configurations. A model may fill more than one role, but the assignment is
still represented in the scan manifest.

```python
from secgraphai import Model, ModelRoles, SecGraph

roles = ModelRoles(
    target=Model(
        base_url="https://target.example.test/v1",
        model="target-v2",
        api_key_env="TARGET_TOKEN",
    ),
    attack=Model(
        base_url="https://attack.example.test/v1",
        model="attack-v1",
        api_key_env="ATTACK_TOKEN",
    ),
    judges=(
        Model(
            base_url="https://judge.example.test/v1",
            model="judge-v3",
            api_key_env="JUDGE_TOKEN",
        ),
    ),
    remediation=Model(
        base_url="https://review.example.test/v1",
        model="remediator-v1",
        api_key_env="REMEDIATION_TOKEN",
    ),
)

scanner = SecGraph(roles=roles, mode="SAFE")
```

Attach an explicit `ScopeGuard` to every networked `Model` in real usage. Judge output is
treated as untrusted structured data and is not a substitute for deterministic evidence.

## Scenario: audit an OpenAPI document without sending requests

Schema inspection is side-effect-free and can flag missing authentication declarations,
unbounded pagination, and URL-handling operations that require SSRF review.

```python
import asyncio
import yaml

from secgraphai.security import Scope, ScopeGuard
from secgraphai.security_modules import APISecurityModule
from secgraphai.targets import APITarget

schema = yaml.safe_load(open("openapi.yaml", encoding="utf-8"))
target = APITarget(
    "https://api.example.test",
    scope_guard=ScopeGuard(
        Scope(
            allowed_hosts=frozenset({"api.example.test"}),
            allowed_ports=frozenset({443}),
        )
    ),
    mode="PASSIVE",
)
findings = APISecurityModule(target).audit_openapi(schema)
print([finding.title for finding in findings])
```

The target is supplied so the same module can later run authorized checks, but
`audit_openapi` itself does not use it.

## Scenario: verify API authorization with identities

Use synthetic or staging identities whose tokens are referenced by environment variable.
GET operations fit `SAFE` mode; write operations require a reviewed `LAB` scope or an
explicitly classified safe test action.

```python
import asyncio

from secgraphai.security import Scope, ScopeGuard
from secgraphai.security_modules import APISecurityModule
from secgraphai.targets import APITarget, Endpoint, Identity, IdentityCase


async def main() -> None:
    target = APITarget(
        "https://api.example.test",
        scope_guard=ScopeGuard(
            Scope(
                allowed_hosts=frozenset({"api.example.test"}),
                allowed_ports=frozenset({443}),
                max_total_requests=10,
            )
        ),
        mode="SAFE",
    )
    endpoint = Endpoint("GET", "/tenants/acme/invoices", security=("bearer",))
    cases = [
        IdentityCase(
            Identity("acme-reader", tenant="acme", token_env="ACME_READER_TOKEN"),
            endpoint,
            frozenset({200}),
        ),
        IdentityCase(
            Identity("other-reader", tenant="other", token_env="OTHER_READER_TOKEN"),
            endpoint,
            frozenset({403}),
        ),
    ]
    findings = await APISecurityModule(target).test_identity_matrix(cases)
    print([finding.model_dump(mode="json") for finding in findings])


asyncio.run(main())
```

To test a known non-destructive POST in a dedicated staging API, call `test_operation`
with `action="non_destructive_probe"`. Do not relabel an operation merely to bypass the
safety mode; the action must truly have no durable or external side effect.

## Scenario: test RAG tenant isolation and content controls

Wrap your retriever so it returns `RAGDocument` values. SecGraphAI can check cross-tenant
retrieval, instruction-bearing text or metadata, missing provenance, result flooding, and
declared configuration controls.

```python
import asyncio

from secgraphai.security_modules import RAGSecurityModule
from secgraphai.targets import RAGDocument, RAGTarget


async def retrieve(query: str, tenant: str) -> list[RAGDocument]:
    # Replace with your staging retriever. Enforce tenant filtering before retrieval.
    return [
        RAGDocument(
            id="policy-1",
            tenant=tenant,
            text="Approved support policy",
            metadata={"source": "policy-repository"},
        )
    ]


async def main() -> None:
    target = RAGTarget(
        retrieve,
        configuration={
            "namespace_isolation": True,
            "authorization_before_retrieval": True,
            "provenance": True,
            "metadata_filtering": True,
            "max_results": 10,
        },
    )
    module = RAGSecurityModule(target)
    findings = await module.test_isolation(["acme", "other"])
    findings += await module.test_retrieval_controls("support policy", "acme", max_results=10)
    findings += module.audit_configuration()
    print([finding.title for finding in findings])


asyncio.run(main())
```

`test_canary_lifecycle` inserts and deletes a synthetic document and therefore requires a
controlled store plus both `writer` and `deleter` callbacks. Use it only when those writes
are authorized and cleanup has been reviewed.

## Scenario: inventory and audit an MCP server

`MCPClient` is transport-independent. Its discovery flow calls only `initialize`,
`tools/list`, `resources/list`, and `prompts/list`; it does not execute tools.

```python
import asyncio

from secgraphai import discover_mcp
from secgraphai.security_modules import MCPSecurityModule
from secgraphai.targets import MCPClient


async def transport(method: str, params: dict[str, object]) -> dict[str, object]:
    # Adapt these metadata calls to your authorized MCP transport.
    responses = {
        "initialize": {"serverInfo": {"name": "support"}},
        "tools/list": {
            "tools": [
                {
                    "name": "lookup_ticket",
                    "description": "Read one support ticket",
                    "inputSchema": {"type": "object", "additionalProperties": False},
                    "permissions": ["tickets.read"],
                }
            ]
        },
        "resources/list": {"resources": [{"uri": "tickets://schema"}]},
        "prompts/list": {"prompts": []},
    }
    return responses[method]


async def main() -> None:
    client = MCPClient(transport)
    inventory = await discover_mcp(client, source="staging-support")
    findings = await MCPSecurityModule(client).audit(max_tools=25)
    print(inventory.counts())
    print([finding.title for finding in findings])


asyncio.run(main())
```

Persist `MCPInventory.fingerprint()` as an approved baseline and pass it as
`baseline_fingerprint` on a later audit to detect capability drift.

## Scenario: analyze agent behavior

Agent analysis consumes normalized events, so it works with custom agent frameworks as
well as instrumented code. It detects excessive tool use, unapproved high-risk calls,
delegation loops, untrusted memory writes, and external actions outside declared intent.

```python
from secgraphai.security_modules import AgentSecurityModule

events = [
    {
        "kind": "tool",
        "function": "send_email",
        "risk": "high",
        "external": True,
        "allowed": True,
        "in_intent": False,
    },
    {"kind": "memory_write", "provenance": "rag"},
]

findings = AgentSecurityModule().analyze(events, max_tool_calls=10, approved=False)
print([finding.title for finding in findings])
```

Instrumented functions can enforce permissions and approvals at runtime:

```python
from secgraphai import secgraph


@secgraph.tool(permission="billing.refund", approval=True, risk="high")
def refund(invoice_id: str) -> dict[str, str]:
    return {"invoice_id": invoice_id, "status": "queued"}
```

Set a `SecurityContext` with the required permissions and approval state around actual
execution. Missing permission or approval raises `PolicyDenied` before the function runs.

## Scenario: declare and verify a data-flow invariant

```python
from secgraphai import SecGraph, invariant
from secgraphai.scanner import TargetResult

no_secret_exfiltration = invariant(
    "NO_SECRET_EXFIL",
    description="Secret data must not reach an external destination",
    source={"sensitivity": "secret"},
    destination={"trust": "external"},
    expected="deny",
)


def application(prompt: str) -> TargetResult:
    return TargetResult(
        "Request completed",
        metadata={
            "flow": {
                "source": {"sensitivity": "secret"},
                "destination": {"trust": "external"},
            }
        },
    )


scanner = SecGraph(invariants=[no_secret_exfiltration])
```

The scanner evaluates matching flows deterministically and attaches flow evidence to the
finding. An LLM judge can add semantic coverage, but it should not replace an observable
boundary signal such as an authorization response, tool event, tenant marker, or canary.
Invariant matching also supports `principal` equality against `$resource.<field>`, an exact
`tool`, conditional `_gt`, `_gte`, `_lt`, `_lte`, and `_eq` suffixes under `when`, and
required observed controls. Pass `principal`, `tool`, `context`, and `controls` inside the
flow metadata to exercise those clauses.

## Reports, baselines, and regression replay

Reports can be rendered as JSON, JSONL, Markdown, HTML, CSV, SARIF, JUnit, and—when the
PDF extra is installed—PDF. The output extension selects the renderer unless `--format`
is supplied.

```bash
secgraph report render report.json report.md
secgraph report render report.json report.sarif --format sarif
secgraph report render report.json report.junit.xml --format junit
```

Create and compare named baselines:

```bash
secgraph baseline create staging-main report.json
secgraph baseline compare staging-main candidate-report.json
```

Run the deterministic callback suite against that baseline and fail only for newly
introduced findings:

```bash
secgraph test --callback myapp:answer \
  --baseline staging-main \
  --fail-on-regression \
  --output candidate-report.json
```

Create a tamper-checked replay archive and validate it without contacting a target:

```bash
secgraph bundle create report.json scan.secgraph
secgraph replay scan.secgraph
```

Re-run its data-only cases through a callback and fail CI when a verified violation is
reproduced:

```bash
secgraph replay scan.secgraph \
  --callback myapp:answer \
  --fail-on-violation
```

Generate a focused pytest regression for one finding:

```bash
secgraph generate-test report.json FINDING_ID --output test_security_regression.py
```

Replay archives contain JSON data and hashes, never executable serialized objects. Review
the prompts and target callback before executing a replay in another environment.

## OWASP coverage and CI gates

The CLI provides versioned Web, API, LLM, and agentic coverage profiles. Coverage records
what was tested and with what verdict; it does not by itself certify the application.

```bash
secgraph owasp coverage report.json --profile llm-2026
secgraph owasp gate report.json --profile llm-2026 --minimum-percent 90
```

A practical CI sequence is:

```bash
secgraph scan --callback myapp:answer --output report.json --format json
secgraph replay approved.secgraph --callback myapp:answer --fail-on-violation
secgraph baseline compare production report.json
secgraph owasp gate report.json --profile llm-2026 --minimum-percent 90
```

Treat `TEST_ERROR` as a failed security test, not a pass. Pin the SecGraphAI version and
attack-pack versions used by CI so changes are intentional.

## SBOM and offline vulnerability intelligence

Generate CycloneDX or SPDX inventories from the current Python environment:

```bash
secgraph sbom generate --output bom.json --format cyclonedx
secgraph sbom generate --output bom.spdx.json --format spdx
```

Synchronize a bounded NVD query into a local cache, inspect its freshness, and use it
offline:

```bash
secgraph cve sync --query Python --cache cve-cache.json
secgraph cve status --cache cve-cache.json
secgraph cve search urllib3 --cache cve-cache.json
secgraph cve affected urllib3 2.2.1 --cache cve-cache.json
secgraph sbom scan bom.json --cache cve-cache.json
```

Repeated syncs merge records, preserve source metadata, and resume from the next NVD page
when a bounded query has more results. Once paging completes, later runs send ETag and
Last-Modified validators and request an NVD last-modified date window, so unchanged data can
return without reparsing a full feed. A numeric `Retry-After` response is honored with a
bounded retry. Review `age_seconds` and source validators before relying on an offline result.
Package-name and version matching may be
inconclusive; reachability and known-exploited signals are prioritization inputs, not proof
that a vulnerability is exploitable in your application.

## Signed attack packs and external plugins

Official attack packs are bundled and integrity checked:

```bash
secgraph packs official prompt_injection_core
secgraph packs verify custom-pack.yaml --public-key reviewer.pub
```

Unverified packs are disabled by default. `--allow-unverified` is appropriate only for a
reviewed local draft.

Audit plugin manifests before execution:

```bash
secgraph plugins audit plugin.json
```

Subprocess plugins are permission-gated, receive a reduced environment, and have resource
limits. Container plugins must use an immutable image digest and are started with hardened
Docker or Podman flags. SecGraphAI does not make third-party code trusted; review the
adapter and run it with the minimum permissions.

Native JSON normalization is included for PyRIT, garak, Promptfoo, DeepTeam, Schemathesis,
LLM Guard, Presidio, Semgrep, CodeQL/SARIF, ZAP, Nuclei, detect-secrets, pip-audit, OSV, and
ModelScan. Engines still execute through an explicitly permissioned plugin manifest; listing
an engine does not install it or grant it target access.

## Evidence privacy, retention, and encrypted storage

Redaction covers authorization, proxy authorization, API keys, tokens, passwords, secrets,
cookies, Set-Cookie, and session fields. Optional PII masking replaces common email and phone
values in reports:

```bash
secgraph scan --callback myapp:answer --format json --mask-pii
secgraph report render report.json report.html --mask-pii
```

SQLite can encrypt every stored report, finding, evidence item, interaction, graph element,
and dashboard document with a Fernet key held only in an environment variable. It can also
prune expired evidence at startup:

```powershell
pip install "secgraphai[dashboard,security]"
$env:SECGRAPH_STORAGE_KEY = "<url-safe Fernet key>"
secgraph serve --database secgraph.db `
  --encryption-key-env SECGRAPH_STORAGE_KEY `
  --retention-days 30 `
  --mask-pii
```

The key is never written to SQLite. Back it up separately: opening encrypted records without
the same key fails closed. The Python API exposes the same controls through
`Storage(..., encryption_key_env=..., retention_days=..., mask_pii=True)`.

## Local dashboard and API

Install the dashboard extra, choose a strong token of at least 16 characters, and bind to
loopback:

```bash
pip install "secgraphai[dashboard]"
export SECGRAPH_DASHBOARD_TOKEN="replace-with-a-long-random-value"
secgraph serve --host 127.0.0.1 --port 8777 --database secgraph.db
```

Open `http://127.0.0.1:8777/`. Every data API requires
`Authorization: Bearer <token>`. The server disables interactive API docs, applies body
and request-rate limits, and adds defensive browser headers. Loopback is the default. An
explicit non-loopback `--host` is accepted only with the required strong bearer token and
prints a TLS-termination warning; put it behind a trusted TLS proxy before exposing it.

Every frontend area has a dedicated shaped endpoint under `/api/v1/views/{name}`, including
overview, architecture, attack paths, prompt injection, agents, RAG, MCP, API security,
identities, runtime events, regression artifacts, models, vulnerabilities, OWASP coverage,
settings, and self-security. This prevents security-specific pages from silently showing an
unfiltered copy of the general findings feed.

Register an OpenAI-compatible target and queue an adaptive scan:

```bash
curl -X POST http://127.0.0.1:8777/api/v1/targets \
  -H "Authorization: Bearer $SECGRAPH_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"staging-model","type":"openai-compatible","configuration":{"base_url":"https://models.example.test/v1","model":"assistant-v2","api_key_env":"STAGING_MODEL_TOKEN","scope":{"allowed_hosts":["models.example.test"],"allowed_ports":[443]}}}'

curl -X POST http://127.0.0.1:8777/api/v1/scan-jobs \
  -H "Authorization: Bearer $SECGRAPH_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_id":"staging-model","mode":"SAFE","modules":["prompt-injection","agent"],"attack_budget":20}'
```

Read the returned job with `GET /api/v1/scan-jobs/{job_id}`. Jobs and completed reports
are persisted in SQLite. Live events are available from `ws://127.0.0.1:8777/api/v1/events`
using either an `Authorization` header or WebSocket subprotocols
`["secgraphai", "<token>"]`.

## Demo benchmark

The `demo` package contains vulnerable and hardened applications with six seeded
behaviors: object authorization, approval gates, indirect prompt injection, RAG isolation,
external data flow, and runaway agent recursion.

```bash
python -m pytest tests/test_prd_benchmark.py -q
```

`demo.assessment.assess_demo` runs both variants through the public API, RAG, and agent
modules. It is a useful reference for integrating a real application and for checking that
a remediation removes a finding without breaking the test harness.

## Troubleshooting

- **`PASSIVE mode does not permit active security probes`**: use discovery or schema audit,
  or move an authorized bounded test to `SAFE`.
- **`target is not in the explicit scan scope`**: verify the exact hostname and effective
  port. Do not broaden scope beyond the authorization you have.
- **`target resolves to a blocked network`**: local services require an intentional local
  lab configuration or the CLI's `--allow-private` flag.
- **`request budget exhausted`**: raise the bound only after confirming the target can
  tolerate the load; do not disable it.
- **`callback must use module:function syntax`**: run from a directory where the module is
  importable, for example `secgraph scan --callback package.module:answer`.
- **dashboard token errors**: set the environment variable in the same shell that launches
  `secgraph serve`; the value must contain at least 16 characters.
- **missing PDF, API, or integration dependency**: install the corresponding optional
  extra shown in the installation section.
- **unexpected `TEST_ERROR`**: inspect `report.errors` and the matching interaction. A test
  that could not execute has not verified the control.

## Current release-candidate boundaries

SecGraphAI 1.0.0rc1 provides the executable core described in the PRD, but some activities
remain release or integration responsibilities:

- framework-specific live inventory beyond built-in FastAPI-style route, static Python,
  OpenAPI, manifest, OpenTelemetry, and supplied MCP transport discovery needs an adapter;
- external scanners use the normalized plugin/adapter contract and still require their own
  installation, configuration, licenses, and trust review;
- NVD synchronization supports paging, conditional requests, and modified-date deltas;
  operators remain responsible for scheduling queries and deciding cache-freshness policy;
- probabilistic model judgments require human review for consequential decisions;
- an independent pre-1.0 security review, release signing, and publishing are maintainer
  actions rather than package runtime features.

For the complete requirements and threat assumptions, read
[`SecGraphAI_PRD_v3.1_CVE_OWASP.md`](../SecGraphAI_PRD_v3.1_CVE_OWASP.md),
[`THREAT_MODEL.md`](../THREAT_MODEL.md), [`SECURITY.md`](../SECURITY.md), and
[`SECURITY_REVIEW.md`](../SECURITY_REVIEW.md).
