# SecGraphAI

**Security testing and runtime guardrails for systems that think, retrieve, and act.**

SecGraphAI is a local-first Python toolkit for testing AI applications, agents, retrieval
systems, MCP servers, APIs, and OpenAI-compatible model endpoints. It maps trust boundaries,
runs bounded adversarial checks, enforces permissions and approvals on Python tools, captures
sanitized evidence, and turns findings into repeatable CI regressions.

Version `1.0.0rc3` is a release candidate. Use SecGraphAI only on systems you own or are
explicitly authorized to assess.

## What you can use it for

| Real threat or operational question | SecGraphAI workflow | Evidence or outcome |
| --- | --- | --- |
| A support agent tries to issue a refund without the operator's permission | Annotate the refund function with `@secgraph.tool` | The call is blocked before side effects and an event records why |
| A retrieved document tells the model to ignore policy and disclose secrets | Run RAG isolation/content checks and a prompt-injection scan | Poisoned content, provenance gaps, canary leakage, and resulting calls are recorded |
| One tenant's token can read another tenant's invoice | Execute an API identity matrix | Expected versus observed status codes produce a deterministic authorization finding |
| An MCP server silently adds a privileged tool | Discover capabilities and compare the inventory fingerprint | Capability drift and risky tool metadata become reviewable findings |
| An agent sends email, writes memory, or calls tools outside the user's intent | Analyze normalized agent events | Excessive agency, unapproved external actions, loops, and untrusted memory writes are flagged |
| A model or guardrail update reintroduces a known issue | Save a baseline or replay bundle and gate CI | Only new or reproduced violations fail the build |
| A deployed Python environment contains a known vulnerable component | Generate an SBOM and scan it against a local CVE cache | Affected-version, reachability, CVSS, CWE, and KEV signals feed a security gate |
| A team needs to understand what an AI service can reach | Discover source, manifests, OpenAPI, MCP, and telemetry | A typed security graph exposes privileged, cross-tenant, external, and cyclic paths |

## Install

Python 3.11 or newer is required. The current release is a prerelease:

```bash
python -m pip install --pre secgraphai
```

For a reproducible installation:

```bash
python -m pip install "secgraphai==1.0.0rc3"
python -c "from importlib.metadata import version; print(version('secgraphai'))"
```

Common optional capabilities:

```bash
python -m pip install --pre "secgraphai[dashboard]"     # local dashboard and HTTP API
python -m pip install --pre "secgraphai[integrations]"  # Schemathesis and OpenTelemetry APIs
python -m pip install --pre "secgraphai[security]"      # signing, audit, and secret-scanning tools
python -m pip install --pre "secgraphai[pdf]"           # PDF reports
python -m pip install --pre "secgraphai[all]"           # every optional feature
```

Create and validate a safe starter configuration:

```bash
secgraph init
secgraph doctor
secgraph self-audit
```

## Start with a real application callback

Expose a staging-safe function that accepts a test prompt and returns the application's
actual response. This keeps the scanner at the same boundary used by your application.

```python
# security_target.py
from myapp.support_agent import answer_support_question


def answer(prompt: str) -> str:
    return answer_support_question(
        prompt,
        tenant="synthetic-acme",
        user="security-test-user",
        allow_external_actions=False,
    )
```

Run a bounded scan and keep the report:

```bash
secgraph scan \
  --callback security_target:answer \
  --profile owasp-full \
  --mode SAFE \
  --max-requests 40 \
  --max-duration 120 \
  --output report.json \
  --format json \
  --mask-pii
```

Review both findings and `report.errors`. A test that could not run is a `TEST_ERROR`, not
a pass. Start with synthetic accounts and data; do not point active checks at production by
default.

## Annotations are executable security boundaries

The `secgraph` decorators are not descriptive labels only. They attach machine-readable
metadata for discovery and enforce selected controls before the wrapped function executes.

| Annotation | Use it on | What it does at runtime |
| --- | --- | --- |
| `@secgraph.tool(permission="...")` | Functions that read, write, send, charge, delete, or invoke another system | Requires the named permission |
| `@secgraph.tool(approval=True, risk="high")` | High-impact tools such as refunds, deployments, email, or account changes | Requires explicit approval and records risk metadata |
| `@secgraph.agent(...)` | Agent entry points or delegated workers | Records agent metadata and applies any supplied permission/approval fields |
| `@secgraph.retriever(...)` | Vector, search, or document retrieval functions | Marks a retrieval boundary for discovery and events |
| `@secgraph.approval(when="...")` | A function that must always cross an approval boundary | Rejects execution unless the current context is approved |
| `secgraph.instrument(...)` | Existing callables you cannot decorate | Adds timing, success, trace, and OpenTelemetry-compatible events |

### Practical example: stop an unauthorized refund

```python
from secgraphai import secgraph
from secgraphai.runtime import PolicyDenied, SecurityContext, current_context


@secgraph.tool(permission="billing.refund", approval=True, risk="high")
def issue_refund(invoice_id: str, amount_usd: int) -> dict[str, object]:
    # This code is reached only after both checks pass.
    return {"invoice_id": invoice_id, "amount_usd": amount_usd, "status": "queued"}


context = SecurityContext(
    user="operator-42",
    tenant="acme",
    permissions=frozenset({"billing.refund"}),
    approved=False,
    trace_id="ticket-1842",
)
token = current_context.set(context)
try:
    issue_refund("inv-1007", 850)
except PolicyDenied as exc:
    print(f"blocked: {exc}")  # explicit approval required
finally:
    current_context.reset(token)

print(context.events[-1])
```

The business function never runs when authorization or approval fails. Set and reset the
`SecurityContext` at the request or job boundary so identity, tenant, permissions, approval,
and trace ID do not leak between requests. Treat `risk` as metadata for policy and analysis;
the enforced checks in this decorator are `permission` and `approval`.

For centralized rules, load a policy once during application startup:

```yaml
# policy.yaml
default: deny
mode: enforce
rules:
  - id: allow-low-risk-customer-read
    effect: allow
    priority: 100
    match:
      kind: tool
      permission: crm.read
  - id: redact-tool-output
    effect: redact
    match:
      kind: tool
      risk: sensitive-output
```

```python
from secgraphai import PolicyEngine, secgraph

secgraph.use_policy(PolicyEngine.from_yaml("policy.yaml"))
```

Use policy shadow mode before enforcement when introducing rules to an existing system.

## Scenario: detect poisoned RAG content

An attacker may place instructions in a ticket, wiki page, PDF, or vector-store record and
wait for an agent to retrieve them. Test tenant separation, provenance, instruction-bearing
content, metadata filtering, and result limits at the retriever boundary:

```python
import asyncio

from secgraphai.security_modules import RAGSecurityModule
from secgraphai.targets import RAGDocument, RAGTarget


async def retrieve(query: str, tenant: str) -> list[RAGDocument]:
    rows = await staging_vector_search(query=query, tenant_filter=tenant)
    return [
        RAGDocument(
            id=row.id,
            tenant=row.tenant,
            text=row.text,
            metadata={"source": row.source, "ingested_by": row.ingested_by},
        )
        for row in rows
    ]


async def check() -> None:
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
    findings = await module.test_isolation(["synthetic-acme", "synthetic-other"])
    findings += await module.test_retrieval_controls(
        "reset an employee password", "synthetic-acme", max_results=10
    )
    findings += module.audit_configuration()
    for finding in findings:
        print(finding.verdict, finding.title)


asyncio.run(check())
```

Do not insert canaries into a production store unless writes and cleanup are explicitly
authorized. `test_canary_lifecycle` is for a controlled store with reviewed writer and
deleter callbacks.

## Scenario: catch cross-tenant API access

Use non-production identities whose tokens are stored in environment variables. This
example verifies that an Acme reader succeeds while another tenant is denied:

```python
import asyncio

from secgraphai.security import Scope, ScopeGuard
from secgraphai.security_modules import APISecurityModule
from secgraphai.targets import APITarget, Endpoint, Identity, IdentityCase


async def check() -> None:
    target = APITarget(
        "https://staging-api.example.test",
        scope_guard=ScopeGuard(
            Scope(
                allowed_hosts=frozenset({"staging-api.example.test"}),
                allowed_ports=frozenset({443}),
                max_total_requests=10,
            )
        ),
        mode="SAFE",
    )
    endpoint = Endpoint("GET", "/tenants/acme/invoices", security=("bearer",))
    cases = [
        IdentityCase(Identity("acme", tenant="acme", token_env="ACME_TEST_TOKEN"), endpoint, frozenset({200})),
        IdentityCase(Identity("other", tenant="other", token_env="OTHER_TEST_TOKEN"), endpoint, frozenset({403})),
    ]
    findings = await APISecurityModule(target).test_identity_matrix(cases)
    print([finding.title for finding in findings])


asyncio.run(check())
```

Keep write operations out of `SAFE` mode. A staging-only, non-destructive POST can be tested
in `LAB` only after its side effects and cleanup are reviewed.

## Scenario: detect excessive agent behavior

Normalize framework events and look for tool-call floods, unapproved high-risk actions,
delegation loops, untrusted memory writes, and external actions outside the user's intent:

```python
from secgraphai.security_modules import AgentSecurityModule

events = [
    {"kind": "tool", "function": "lookup_order", "allowed": True, "in_intent": True},
    {
        "kind": "tool",
        "function": "send_email",
        "risk": "high",
        "external": True,
        "allowed": True,
        "in_intent": False,
    },
    {"kind": "memory_write", "provenance": "untrusted-rag"},
]

findings = AgentSecurityModule().analyze(events, max_tool_calls=10, approved=False)
for finding in findings:
    print(finding.severity, finding.title)
```

Feed the same normalized events into a security report or dashboard so reviewers can follow
the user request, retrieved content, tool decision, and external side effect as one trace.

## Scenario: detect MCP capability drift

Inventory first; metadata discovery does not execute tools:

```python
import asyncio

from secgraphai import discover_mcp
from secgraphai.security_modules import MCPSecurityModule
from secgraphai.targets import MCPClient


async def transport(method: str, params: dict[str, object]) -> dict[str, object]:
    return await authorized_mcp_metadata_call(method, params)


async def check() -> None:
    client = MCPClient(transport)
    inventory = await discover_mcp(client, source="staging-support")
    print("approve this fingerprint:", inventory.fingerprint())
    findings = await MCPSecurityModule(client).audit(
        baseline_fingerprint="previously-approved-fingerprint",
        max_tools=50,
    )
    print([finding.title for finding in findings])


asyncio.run(check())
```

Review newly exposed tools, changed schemas, permission metadata, and external side effects
before updating the approved fingerprint.

## Instrument an existing stack

Instrumentation records timing, success, trace identifiers, and safe metadata without
requiring decorators everywhere:

```python
import httpx
from fastapi import FastAPI

from secgraphai import secgraph

app = FastAPI()
fastapi_events = secgraph.instrument_fastapi(app)
http = httpx.AsyncClient(event_hooks=secgraph.instrument_httpx())
```

```python
client = secgraph.instrument_openai(existing_openai_client)
mcp_call = secgraph.instrument_mcp(existing_mcp_call)
chain = secgraph.instrument_langchain(existing_chain_callable)
graph = secgraph.instrument_langgraph(existing_graph_callable)
```

OpenTelemetry emission is optional through `secgraphai[otel]`. Instrumentation observes a
boundary; decorators and policies enforce it. Use both for privileged actions.

## Discover attack paths before scanning

Static discovery does not import local Python files:

```bash
secgraph discover ./src
secgraph discover ./architecture.yaml --format json > inventory.json
secgraph openapi ./openapi.yaml > operations.json
```

It recognizes decorated agents/tools/retrievers, routes, annotated parameters, OpenAPI and
GraphQL operations, manifests, selected OpenTelemetry attributes, and MCP metadata. The
resulting graph highlights untrusted-to-privileged paths, cross-tenant edges, external data
flows, and execution cycles.

## Scan a model endpoint with explicit limits

SecGraphAI supports bring your own key (BYOK): the key stays in your environment and is
sent directly from the machine running the scan to the exact model endpoint you configure.
There is no SecGraphAI credential proxy or required model vendor.

```bash
export STAGING_MODEL_TOKEN="..."
secgraph scan \
  --target https://models.example.test/v1 \
  --model assistant-v2 \
  --api-key-env STAGING_MODEL_TOKEN \
  --profile owasp-llm-2026 \
  --budget-usd 2.00 \
  --max-requests 40 \
  --max-duration 120 \
  --output model-report.json \
  --format json
```

Remote targets are allow-listed to the exact supplied host and port. Private and special
networks are blocked by default, redirects are not followed, API keys are read from named
environment variables, and credential values are not serialized into reports.

The Python API can assign independent target, attack, judge, and remediation models, each
with its own endpoint and key. See the dedicated
[BYOK and AI model guide](https://github.com/ezducate/SecGraphAI/blob/main/docs/BYOK_AND_MODELS.md)
for PowerShell and Bash setup, model-role behavior, OpenAI/OpenRouter/Groq/Ollama endpoint
patterns, local-model usage, CI secrets, compatibility limits, and troubleshooting.

Available profiles are `safe`, `owasp-web-2025`, `owasp-api-2023`, `owasp-llm-2026`,
`owasp-agentic-2026`, and `owasp-full`. Modes are `PASSIVE`, `SAFE`, `LAB`, and `CUSTOM`;
active scans are rejected in `PASSIVE`.

## Turn a finding into a regression gate

```bash
secgraph baseline create staging-main report.json
secgraph baseline compare staging-main candidate-report.json
secgraph bundle create report.json approved.secgraph
secgraph replay approved.secgraph --callback security_target:answer --fail-on-violation
secgraph generate-test report.json FINDING_ID --output test_security_regression.py
secgraph owasp gate report.json --profile llm-2026 --minimum-percent 90
```

Replay bundles contain data and hashes, not executable serialized objects. Review prompts
and the callback before replaying a bundle in a different environment.

A minimal CI job can pin the tested engine and fail on new or reproduced behavior:

```yaml
- run: python -m pip install "secgraphai==1.0.0rc3"
- run: secgraph test --callback security_target:answer --baseline production --fail-on-regression --output report.json
- run: secgraph replay approved.secgraph --callback security_target:answer --fail-on-violation
- run: secgraph owasp gate report.json --profile llm-2026 --minimum-percent 90
```

## Reports, dashboard, SBOM, and CVE workflows

```bash
secgraph report render report.json report.html
secgraph report render report.json report.sarif --format sarif
secgraph report render report.json report.junit.xml --format junit

secgraph sbom generate --output bom.json --format cyclonedx
secgraph cve sync --query Python --cache cve-cache.json
secgraph cve status --cache cve-cache.json
secgraph sbom scan bom.json --cache cve-cache.json
```

For local review:

```bash
python -m pip install --pre "secgraphai[dashboard,security]"
export SECGRAPH_DASHBOARD_TOKEN="replace-with-a-long-random-value"
secgraph serve --host 127.0.0.1 --port 8777 --database secgraph.db --mask-pii
```

The dashboard is authenticated and loopback-only by default. JSON, JSONL, Markdown, HTML,
CSV, SARIF, JUnit, and optional PDF outputs are supported.

## Command map

| Area | Commands |
| --- | --- |
| Setup and inspection | `init`, `doctor`, `self-audit`, `schemas`, `engines` |
| Discovery and scanning | `discover`, `openapi`, `scan`, `test`, `compare`, `diff` |
| Reproduction | `bundle create`, `bundle replay`, `replay`, `generate-test` |
| Runtime policy | `policy test`, `policy simulate` |
| Reports and review | `report render`, `serve`, `dev`, `baseline create`, `baseline compare` |
| Supply chain | `sbom generate`, `sbom scan`, `cve sync/search/show/affected/reachable/status` |
| Extensibility | `packs official`, `packs verify`, `plugins audit`, `research import` |
| Artifacts and standards | `model inspect`, `media`, `owasp coverage`, `owasp gate` |

See the complete [CLI reference](https://github.com/ezducate/SecGraphAI/blob/main/docs/CLI_REFERENCE.md)
for every argument, option, default, exit behavior, and practical invocation.

## Safety model

- Begin with discovery or `PASSIVE`; use `SAFE` for bounded reads and safe probes.
- Reserve `LAB` for isolated systems where active actions and cleanup are authorized.
- Use synthetic tenants, identities, canaries, payments, inboxes, and documents.
- Keep exact host, port, request, rate, time, and cost limits.
- Store secret references such as `STAGING_MODEL_TOKEN`, never secret values, in configuration.
- Treat `TEST_ERROR` and inconclusive results as unresolved, not secure.
- Require human review for consequential decisions and probabilistic judge output.

## Documentation

- [Detailed user guide](https://github.com/ezducate/SecGraphAI/blob/main/docs/USER_GUIDE.md)
- [BYOK and AI model guide](https://github.com/ezducate/SecGraphAI/blob/main/docs/BYOK_AND_MODELS.md)
- [Complete CLI reference](https://github.com/ezducate/SecGraphAI/blob/main/docs/CLI_REFERENCE.md)
- [Threat model](https://github.com/ezducate/SecGraphAI/blob/main/THREAT_MODEL.md)
- [Security policy](https://github.com/ezducate/SecGraphAI/blob/main/SECURITY.md)
- [Security review](https://github.com/ezducate/SecGraphAI/blob/main/SECURITY_REVIEW.md)
- [Product requirements and roadmap](https://github.com/ezducate/SecGraphAI/blob/main/SecGraphAI_PRD_v3.1_CVE_OWASP.md)
- [Release runbook](https://github.com/ezducate/SecGraphAI/blob/main/docs/RELEASING.md)
- [Changelog](https://github.com/ezducate/SecGraphAI/blob/main/CHANGELOG.md)

## Development and release integrity

The repository test suite covers the public workflows plus vulnerable/hardened benchmark
applications. Releases run tests with branch coverage, dependency audit, CycloneDX SBOM
generation, package builds, GitHub build-provenance attestations, and PyPI OIDC trusted
publishing. No long-lived PyPI upload token is stored in GitHub.

Apache-2.0 licensed. Security reports should follow
[SECURITY.md](https://github.com/ezducate/SecGraphAI/blob/main/SECURITY.md).
