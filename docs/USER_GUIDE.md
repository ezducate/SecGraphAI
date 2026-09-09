# SecGraphAI user guide

SecGraphAI is a local-first security testing toolkit for AI applications, agents,
retrieval systems, MCP servers, APIs, and OpenAI-compatible model endpoints. It helps you
describe security boundaries, run bounded tests, capture deterministic evidence, enforce
runtime controls, and turn findings into repeatable regressions.

Use SecGraphAI only against systems you own or are authorized to assess. Start in
`PASSIVE` or `SAFE` mode, use synthetic data, set explicit host and request limits, and
reserve `LAB` mode for isolated test environments.

Choose a workflow based on an observable application risk, not a generic prompt list:

| What happened or could happen | Boundary to test | Start here |
| --- | --- | --- |
| An agent attempted a refund, deployment, message, or deletion without approval | Runtime tool authorization | `@secgraph.tool`, `SecurityContext`, and policy simulation |
| Search or RAG returned another customer's data | Retriever tenant filter | `RAGSecurityModule.test_isolation` |
| A document or tool description contained instructions for the model | Untrusted-content boundary | RAG/MCP audits plus a callback scan |
| A user changed an object ID and accessed another tenant's resource | API authorization | API identity matrix with synthetic tokens |
| A new model or guardrail leaked a canary that the old version blocked | Model boundary | Bounded scan, baseline comparison, and replay |
| An MCP upgrade exposed a new privileged tool | Capability boundary | MCP inventory fingerprint and metadata audit |
| An agent performed an external action outside the user's stated request | Intent-to-action boundary | Normalized agent event analysis |
| A dependency alert needs prioritization | Deployment supply chain | SBOM, offline CVE cache, affected-version, and reachability checks |

## Installation

Python 3.11 or newer is required.

```bash
python -m pip install --pre secgraphai
```

The current public line is the `1.0.0rc3` release candidate. `--pre` allows pip to select
it before a stable release exists. For a reproducible installation, pin it explicitly:

```bash
python -m pip install "secgraphai==1.0.0rc3"
python -c "from importlib.metadata import version; print(version('secgraphai'))"
```

Use a virtual environment for applications and CI so SecGraphAI's dependencies remain
isolated. To upgrade to a newer prerelease, run
`python -m pip install --upgrade --pre secgraphai`. Once a stable release is available,
omit `--pre` to stay on the stable channel.

Install only the optional capabilities you need:

```bash
python -m pip install --pre "secgraphai[dashboard]"     # local dashboard and HTTP API
python -m pip install --pre "secgraphai[mcp]"           # MCP support (no extra dependency today)
python -m pip install --pre "secgraphai[rag]"           # RAG support (bring your own retriever client)
python -m pip install --pre "secgraphai[pii]"           # PII adapter entry point (bring your own engine)
python -m pip install --pre "secgraphai[otel]"          # OpenTelemetry event emission
python -m pip install --pre "secgraphai[evolution]"     # bounded evolutionary planner (included in core)
python -m pip install --pre "secgraphai[integrations]"  # Schemathesis and OpenTelemetry APIs
python -m pip install --pre "secgraphai[security]"      # signing, dependency audit, secret scanning
python -m pip install --pre "secgraphai[pdf]"           # PDF report output
python -m pip install --pre "secgraphai[research]"      # PDF research import
python -m pip install --pre "secgraphai[all]"           # all optional features and development tools
```

Confirm the installation and create a safe starter configuration:

```bash
secgraph --help
secgraph init
secgraph doctor
secgraph self-audit
```

The [complete CLI reference](CLI_REFERENCE.md) documents every command, argument, option,
default, exit behavior, and practical invocation. The scenarios below explain when to use
those controls and what evidence to expect.

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

## Annotations and runtime enforcement

Annotations connect application intent to enforcement and evidence. Apply them at the
smallest function that performs the sensitive action—not only at a top-level agent—so a
prompt-injection or confused-deputy path cannot bypass the check by calling the tool through
another route.

| Annotation | Practical boundary | Enforced behavior |
| --- | --- | --- |
| `@secgraph.tool(permission="crm.read")` | CRM, payment, messaging, deployment, file, or admin operation | Rejects a context without the exact permission before the function runs |
| `@secgraph.tool(approval=True, risk="high")` | Refund, wire, delete, publish, send, or other consequential action | Rejects a context without explicit approval; `risk` remains available to policy and analysis |
| `@secgraph.agent(...)` | Agent or delegated worker entry point | Records agent metadata and applies supplied permission/approval metadata |
| `@secgraph.retriever(...)` | Vector search, document search, or memory retrieval | Marks the retrieval boundary in discovery and runtime events |
| `@secgraph.approval(when="...")` | Function that always requires an approval checkpoint | Requires the current context's approval flag |
| `secgraph.instrument(callable)` | Existing framework or third-party callable | Records trace, duration, outcome, and safe metadata but does not itself authorize the call |

### Secure a customer-support refund path

Assume a support agent can look up invoices and propose refunds. The lookup requires a
read permission. Issuing the refund requires a separate permission and human approval:

```python
from secgraphai import secgraph
from secgraphai.runtime import PolicyDenied, SecurityContext, current_context


@secgraph.tool(permission="billing.invoice.read", risk="customer-data")
def get_invoice(invoice_id: str) -> dict[str, object]:
    return billing_api.get_invoice(invoice_id)


@secgraph.tool(permission="billing.refund", approval=True, risk="high")
def issue_refund(invoice_id: str, amount_usd: int) -> dict[str, object]:
    return billing_api.refund(invoice_id, amount_usd)


def handle_refund_request(invoice_id: str, amount_usd: int) -> dict[str, object]:
    context = SecurityContext(
        user="support-operator-42",
        tenant="synthetic-acme",
        permissions=frozenset({"billing.invoice.read", "billing.refund"}),
        approved=False,
        trace_id="support-ticket-1842",
    )
    token = current_context.set(context)
    try:
        invoice = get_invoice(invoice_id)
        try:
            refund = issue_refund(invoice_id, amount_usd)
        except PolicyDenied:
            refund = {"status": "awaiting-human-approval"}
        return {"invoice": invoice, "refund": refund, "security_events": context.events}
    finally:
        current_context.reset(token)
```

Set and reset the context at every request, message, or job boundary. Never reuse a context
between tenants. Map permissions from an authenticated server-side identity; do not accept
permission or approval flags from model output, retrieved text, tool arguments, or an
untrusted client payload.

`risk` and arbitrary metadata support discovery, policies, and analysis. The built-in
`tool` decorator directly enforces `permission` and `approval`. If you need deny, redact,
transform, sandbox, or rate-limit decisions, attach a `PolicyEngine` once at startup:

```yaml
# policy.yaml
mode: shadow
default: deny
rules:
  - id: allow-customer-read
    effect: allow
    priority: 100
    match:
      kind: tool
      permission: billing.invoice.read
  - id: require-refund-approval
    effect: require_approval
    priority: 200
    match:
      kind: tool
      permission: billing.refund
```

```python
from secgraphai import PolicyEngine, secgraph

secgraph.use_policy(PolicyEngine.from_yaml("policy.yaml"))
```

Start in `shadow` mode and run `secgraph policy simulate` against representative or stored
events. Change to `enforce` only after reviewing false positives and default-deny behavior.
Because `secgraph` is process-global, configure its policy once during application startup.

### Instrument when you cannot annotate

Use adapters at framework boundaries and annotations on privileged business functions:

```python
import httpx
from fastapi import FastAPI

from secgraphai import secgraph

app = FastAPI()
fastapi_recorder = secgraph.instrument_fastapi(app)
http = httpx.AsyncClient(event_hooks=secgraph.instrument_httpx())
openai_client = secgraph.instrument_openai(openai_client)
mcp_call = secgraph.instrument_mcp(mcp_call)
chain_call = secgraph.instrument_langchain(chain_call)
graph_call = secgraph.instrument_langgraph(graph_call)
```

Instrumentation provides traces and timing; it is not a replacement for authorization.
Correlate its trace IDs with application audit logs while avoiding raw prompts, tokens, and
customer data in telemetry.

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

SecGraphAI supports bring your own key (BYOK). Set credentials in the environment and point
the target at the API base that precedes `/chat/completions`. The request goes directly from
the machine running SecGraphAI to that endpoint; SecGraphAI does not operate a credential or
model proxy:

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

For provider endpoint patterns, PowerShell and Bash instructions, local Ollama usage,
separate credentials for all four model roles, CI secret handling, and compatibility
troubleshooting, read the dedicated [`BYOK_AND_MODELS.md`](BYOK_AND_MODELS.md) guide.

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

The target is the system under test. The attack model is called only to mutate bounded
probes during adaptive evolution. Judges are called only when deterministic checks did not
already create a finding for an interaction. The remediation model is called only when a
finding does not already include remediation. Supplying a target key alone does not silently
enable the other three roles.

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
python -m pip install --pre "secgraphai[dashboard,security]"
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
python -m pip install --pre "secgraphai[dashboard]"
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

SecGraphAI 1.0.0rc3 provides the executable core described in the PRD, but some activities
remain release or integration responsibilities:

- framework-specific live inventory beyond built-in FastAPI-style route, static Python,
  OpenAPI, manifest, OpenTelemetry, and supplied MCP transport discovery needs an adapter;
- external scanners use the normalized plugin/adapter contract and still require their own
  installation, configuration, licenses, and trust review;
- NVD synchronization supports paging, conditional requests, and modified-date deltas;
  operators remain responsible for scheduling queries and deciding cache-freshness policy;
- probabilistic model judgments require human review for consequential decisions;
- the release candidate is published with PyPI trusted publishing and GitHub build
  provenance; independent security review and the final 1.0 release remain maintainer
  responsibilities rather than package runtime features.

For the complete requirements and threat assumptions, read
[`SecGraphAI_PRD_v3.1_CVE_OWASP.md`](../SecGraphAI_PRD_v3.1_CVE_OWASP.md),
[`THREAT_MODEL.md`](../THREAT_MODEL.md), [`SECURITY.md`](../SECURITY.md), and
[`SECURITY_REVIEW.md`](../SECURITY_REVIEW.md).
