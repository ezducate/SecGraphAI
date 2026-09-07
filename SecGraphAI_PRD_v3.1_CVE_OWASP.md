# SecGraphAI
## Product Requirements Document — Autonomous AI Application Security, Red Teaming, Runtime Control & Verification

**Version:** 3.1  
**Status:** Proposed architecture / implementation PRD — expanded CVE + OWASP security intelligence  
**Date:** 2026-09-07  
**Working package name:** `secgraphai`  
**CLI:** `secgraph`  
**Python import:** `secgraphai`  
**Primary delivery:** Open-source Python package + CLI + optional local HTTP dashboard/API  
**Recommended license:** Apache-2.0  
**Primary language:** Python 3.11+  

> **Product thesis:** SecGraphAI should not merely decide whether an LLM can be jailbroken. It should discover the security-relevant architecture of an AI application, identify trust boundaries, generate and execute authorized tests, verify actual security effects, enforce runtime controls, and convert validated findings into permanent regression tests.

---

# 1. Executive Summary

SecGraphAI is an AI-native application security framework for systems built around:

- Large language models
- AI agents
- Tool/function calling
- MCP clients and servers
- Retrieval-Augmented Generation (RAG)
- Vector databases
- Agent memory
- REST and GraphQL APIs
- OpenAI-compatible model endpoints
- External services
- Multimodal inputs
- Model gateways
- FastAPI and other Python applications

SecGraphAI should operate as a combination of:

- AI security scanner
- AI red-team framework
- application security orchestrator
- security graph engine
- policy-as-code framework
- runtime security middleware
- regression-test generator
- security evidence/reporting platform

The key architectural distinction is:

```text
MODEL COMPROMISE
      ≠
APPLICATION COMPROMISE
      ≠
VERIFIED SECURITY BOUNDARY VIOLATION
```

A model agreeing to an unsafe request is not automatically a security breach. SecGraphAI should determine whether an unauthorized action actually executed, protected data actually crossed a boundary, another tenant's information was actually exposed, or a declared security invariant was actually violated.

Whenever possible, verification should be deterministic.

---

# 2. Competitive Context

SecGraphAI enters a mature and fast-moving market. It must therefore avoid becoming "another prompt injection scanner."

## 2.1 Existing capabilities in the market

### Promptfoo

Promptfoo provides broad AI red-team coverage, including prompt attacks, privacy, unauthorized data access, tool/function discovery, SSRF-oriented risks, continuous protection and many application-level red-team plugins.

**Implication:** SecGraphAI cannot differentiate merely by having many prompt attack templates.

### Microsoft PyRIT

PyRIT provides automated and human-led AI red teaming, single-turn and multi-turn attack strategies, scenario-based testing, extensibility and a graphical human-red-team interface.

**Implication:** multi-turn attack generation alone is not sufficient differentiation.

### NVIDIA garak

garak provides broad generative-model vulnerability probing across prompt injection, leakage, jailbreaks, toxicity, misinformation and other failure modes, with static, dynamic and adaptive probes.

**Implication:** SecGraphAI should integrate with garak rather than compete solely on model probes.

### DeepTeam

DeepTeam provides a Python red-team framework with many vulnerability classes, single- and multi-turn attack strategies, guardrails, framework mappings and local/hosted reporting workflows.

**Implication:** number of vulnerabilities and LLM-as-judge evaluations are not enough to distinguish SecGraphAI.

### Giskard

Giskard offers dynamic, multi-turn red teaming, context-aware testing, evaluation datasets and regression/evaluation workflows.

**Implication:** SecGraphAI must offer something beyond adaptive conversational red teaming.

### Check Point / Lakera AI Security

Check Point's AI security offering includes prompt attack defenses, data leakage protection, agent discovery/risk assessment and runtime controls for tool behavior.

**Implication:** runtime prompt defense and agent monitoring are already commercial capabilities.

### OWASP 2026 guidance

The OWASP GenAI ecosystem now includes:

- LLM Top 10 2026
- Agentic Applications Top 10 2026
- Agent Control Standard (ACS)

The Agent Control Standard emphasizes inspectability, middleware hooks, runtime policies and portable agent controls.

**Implication:** SecGraphAI should align its instrumentation and runtime-control architecture with this direction where practical.

---

# 3. SecGraphAI's Primary Differentiators

SecGraphAI should win through the combination of the following capabilities.

## 3.1 AI Application Security Graph

SecGraphAI understands the application as a graph of:

- identities
- agents
- models
- prompts
- memory
- RAG sources
- vector stores
- tools
- MCP resources
- APIs
- databases
- secrets
- external services
- trust boundaries
- privileges
- information flows

This graph drives testing.

## 3.2 Security Invariants

Developers define properties that must never be violated.

Examples:

```text
Tenant A data must never become visible to Tenant B.

Untrusted retrieved content must never independently authorize a privileged tool.

Secrets must never flow to an external destination.

Refunds greater than $500 require explicit approval.

Anonymous users may never invoke admin functions.
```

The same invariant can drive:

1. threat modeling
2. red-team selection
3. runtime enforcement
4. CI regression testing

## 3.3 Deterministic Outcome Verification

SecGraphAI should prefer evidence such as:

- canary secret observed
- unauthorized record retrieved
- tool invocation executed
- database row changed
- protected endpoint returned data
- expected authorization denial did not occur
- external controlled callback received
- policy engine recorded a violation

An LLM judge may assist when deterministic validation is impossible, but must not be the sole authority when real effects can be measured.

## 3.4 Cross-Layer Attack Paths

SecGraphAI should correlate attacks across layers.

Example:

```text
Indirect prompt injection
        ↓
RAG
        ↓
Agent
        ↓
MCP tool
        ↓
REST API
        ↓
Authorization failure
        ↓
Cross-tenant record
```

Traditional LLM scanners may find only the injection. Traditional API scanners may find only the API flaw. SecGraphAI should explain the complete attack path.

## 3.5 Finding-to-Regression Pipeline

Every validated finding can become:

- a replayable test
- a pytest test
- a policy
- a CI security gate
- a before/after benchmark

This makes AI red teaming part of software engineering rather than a one-time assessment.

## 3.6 Runtime Protection

The same graph/invariant framework can enforce:

- allow
- deny
- redact
- require approval
- rate limit
- sandbox
- log
- transform

## 3.7 Security of the Security Product

SecGraphAI itself must be designed as a high-assurance security-sensitive project.

It should continuously audit:

- its dependencies
- package provenance
- plugin integrity
- dashboard/API exposure
- secret handling
- unsafe parsing
- report rendering
- attack-pack execution
- subprocess usage
- configuration loading
- archive/file handling

A security product that introduces a vulnerability would undermine trust in the project.

---

# 4. Product Principles

1. **Evidence over opinion**
2. **Security effect over prompt behavior**
3. **Safe by default**
4. **Local-first and privacy-first**
5. **No external telemetry by default**
6. **Test error is never treated as secure**
7. **Least privilege**
8. **Explicit target scope**
9. **Plugins are untrusted until proven otherwise**
10. **Fast default install**
11. **Heavy engines remain optional**
12. **Interoperate instead of reinventing mature scanners**
13. **Reproducibility is a first-class feature**
14. **Utility must be measured alongside security**
15. **No automatic exploitation outside authorized scope**
16. **No raw secret logging**
17. **Security controls must be testable**
18. **All automated remediation must remain reviewable**

---

# 5. Target Users

## 5.1 AI Engineer

Needs to test an LLM/agent before deployment.

## 5.2 Application Security Engineer

Needs to understand how AI capabilities interact with authorization, APIs and sensitive data.

## 5.3 Red Team

Needs reproducible, adaptive tests for an authorized application.

## 5.4 MLOps / Platform Engineer

Needs model-version security comparisons, policy enforcement and CI integration.

## 5.5 AI Security Researcher

Needs pluggable strategies, attack search, benchmark datasets and repeatability.

## 5.6 Security-conscious Developer

Needs:

```bash
pip install secgraphai
secgraph scan
```

without becoming an AI-red-team specialist.

---

# 6. Installation Model

## 6.1 Minimal

```bash
pip install secgraphai
```

## 6.2 Extras

```bash
pip install "secgraphai[test]"
pip install "secgraphai[api]"
pip install "secgraphai[mcp]"
pip install "secgraphai[rag]"
pip install "secgraphai[dashboard]"
pip install "secgraphai[pii]"
pip install "secgraphai[otel]"
pip install "secgraphai[evolution]"
pip install "secgraphai[all]"
```

## 6.3 Base dependency goals

Keep base dependencies small:

- `pydantic`
- `httpx`
- `typer`
- `rich`
- `PyYAML`
- `orjson`
- `tenacity`
- `networkx`
- `jsonschema`
- `platformdirs`
- `cryptography`

Avoid mandatory:

- PyTorch
- TensorFlow
- Transformers
- LangChain
- vector databases
- PyRIT
- garak
- browsers

---

# 7. OpenAI-Compatible Model Abstraction

SecGraphAI must support any compatible endpoint using:

```python
from secgraphai import Model

model = Model(
    base_url="http://localhost:8000/v1",
    api_key="...",
    model="my-model",
)
```

Core should use `httpx` directly so the package does not require a provider SDK.

Support optional provider adapters when needed.

---

# 8. Four LLM Roles

SecGraphAI should separate:

## 8.1 Target Model

The system being tested.

## 8.2 Attack Model

Generates/adapts test cases.

## 8.3 Judge Model

Assists semantic evaluation when deterministic verification is unavailable.

## 8.4 Remediation Model

Explains root causes and proposes remediation.

They may be the same model but should remain logically independent.

---

# 9. Target Types

Initial:

- OpenAI-compatible LLM
- Python callback
- FastAPI application
- REST API
- OpenAPI application
- Python agent
- tool/function-calling agent
- RAG application
- MCP client/server

Later:

- GraphQL
- browser/computer-use agents
- multimodal applications
- multi-agent systems
- voice systems
- model gateways
- managed cloud agents

---

# 10. Discovery Engine

Command:

```bash
secgraph discover ./application
```

or:

```bash
secgraph discover http://127.0.0.1:8000
```

Discovery sources:

- Python introspection
- decorators
- `typing.Annotated`
- OpenAPI
- GraphQL metadata
- MCP capability discovery
- function/tool schemas
- FastAPI routes
- supplied manifests
- HTTP traces
- OpenTelemetry spans
- framework adapters
- RAG configuration
- environment-safe configuration metadata

Output:

```text
Models                 2
Agents                 3
Tools                  17
MCP servers             2
APIs                   31
RAG stores              2
Identities              4
Trust boundaries       26
External destinations   7
Privileged actions      9
```

---

# 11. Security Graph

## 11.1 Node Types

- User
- Principal
- Identity
- Session
- Agent
- Model
- Prompt
- Memory
- Retriever
- Document
- Embedding
- VectorStore
- Tool
- MCPServer
- MCPResource
- APIEndpoint
- Database
- File
- Secret
- DataAsset
- Browser
- ExternalService
- NetworkBoundary

## 11.2 Edge Types

- `CAN_READ`
- `CAN_WRITE`
- `CAN_CALL`
- `AUTHENTICATES_AS`
- `CAN_INFLUENCE`
- `RETRIEVES_FROM`
- `SENDS_TO`
- `RECEIVES_FROM`
- `EXECUTES`
- `CONTAINS`
- `BELONGS_TO_TENANT`
- `REQUIRES_PERMISSION`
- `CROSSES_BOUNDARY`

## 11.3 Automatic Risk Paths

Detect:

```text
UNTRUSTED → PRIVILEGED_ACTION
SENSITIVE → EXTERNAL
TENANT_A → TENANT_B
ANONYMOUS → PROTECTED_RESOURCE
LOW_PRIVILEGE → HIGH_PRIVILEGE
TOOL_OUTPUT → CONTROL_PLANE
RAG_CONTENT → PRIVILEGED_TOOL
```

---

# 12. Security Invariant Engine

Example configuration:

```yaml
invariants:

  - id: NO_SECRET_EXFIL
    description: Secrets must not reach an external destination.
    source:
      sensitivity: secret
    destination:
      trust: external
    expected: deny

  - id: TENANT_ISOLATION
    principal:
      tenant: "$resource.tenant"
    expected: equal

  - id: HIGH_VALUE_REFUND_APPROVAL
    tool: issue_refund
    when:
      amount_gt: 500
    requires:
      - authenticated
      - explicit_confirmation
```

Supported outcomes:

- PASS
- VERIFIED_VIOLATION
- LIKELY_VIOLATION
- BLOCKED_BY_CONTROL
- INCONCLUSIVE
- TEST_ERROR
- OUT_OF_SCOPE

`TEST_ERROR` must never become PASS.

---

# 13. Prompt Injection Module

Prompt injection should be a headline capability.

## 13.1 Sources

Test injections from:

- direct user input
- RAG documents
- web content
- tool outputs
- MCP tool metadata
- MCP resource content
- memory
- uploaded documents
- multimodal context

## 13.2 Test Families

- direct prompt injection
- indirect prompt injection
- instruction hierarchy manipulation
- system prompt extraction attempts
- persistent memory injection
- tool-output injection
- RAG injection
- metadata injection
- cross-agent injection
- obfuscated semantic variants
- multi-turn influence tests

## 13.3 Detection

Combine:

- deterministic patterns
- context-aware heuristics
- optional classifier
- optional security LLM
- application provenance
- tool-risk context

## 13.4 Outcome Stages

```text
Injection reached model
        ↓
Model behavior changed
        ↓
Policy deviation
        ↓
Privileged tool requested
        ↓
Privileged tool executed
        ↓
Security invariant violated
```

Record each stage separately.

---

# 14. RAG Security Module

Capabilities:

- indirect prompt injection
- cross-tenant retrieval testing
- namespace isolation
- retrieval authorization
- document provenance
- canary document insertion
- persistent poisoning testing
- retrieval flooding
- citation/source integrity
- sensitive-document exposure
- metadata influence
- post-retrieval authorization detection
- vector-store configuration review

Key principle:

```text
Authorization should occur before unauthorized data is supplied to the model whenever architecture allows it.
```

---

# 15. Agent Security Module

Test:

- excessive agency
- authorization bypass
- goal redirection
- tool misuse
- human-approval bypass
- privilege escalation
- unsafe delegation
- state confusion
- multi-agent trust errors
- cross-agent message poisoning
- repeated/circular tool execution
- runaway recursion
- cost amplification
- uncontrolled external actions
- memory poisoning
- tool-schema manipulation
- out-of-intent actions

---

# 16. MCP Security Module

Capabilities:

- server/tool/resource discovery
- tool risk classification
- authorization analysis
- token scope review
- credential pass-through detection
- tool metadata injection checks
- tool-output injection checks
- excessive tool exposure
- tool chaining analysis
- external destination discovery
- human approval requirements
- transport configuration checks
- origin/configuration review where applicable
- capability drift between versions
- server fingerprint comparison

---

# 17. API Security Module

Use mature tools where possible.

Primary integration:

- Schemathesis
- Hypothesis

Optional adapters:

- OWASP ZAP
- Nuclei
- Semgrep
- CodeQL

Tests include:

- authentication presence
- authorization consistency
- object-level authorization
- function-level authorization
- property-level authorization
- cross-user access
- cross-tenant access
- rate limits
- excessive payload handling
- excessive pagination
- sensitive error leakage
- unsafe debug exposure
- malformed schema handling
- SSRF-relevant URL-handling policy checks
- expensive AI endpoint resource amplification

---

# 18. Identity Matrix Testing

Configuration:

```yaml
actors:

  anonymous: {}

  alice:
    token_env: TEST_ALICE_TOKEN
    tenant: company_a
    role: user

  bob:
    token_env: TEST_BOB_TOKEN
    tenant: company_b
    role: user

  admin:
    token_env: TEST_ADMIN_TOKEN
    role: admin
```

SecGraphAI builds expected access matrices and compares actual behavior.

This capability should apply to:

- REST
- RAG
- tools
- MCP
- agent actions

---

# 19. Decorators and Python Annotations

Public decorators should remain concise.

Recommended API:

```python
@secgraph.tool(...)
@secgraph.agent(...)
@secgraph.retriever(...)
@secgraph.source(...)
@secgraph.sink(...)
@secgraph.authorize(...)
@secgraph.approval(...)
@secgraph.audit(...)
@secgraph.trace(...)
@secgraph.policy(...)
@secgraph.invariant(...)
@secgraph.intercept(...)
```

Metadata using `typing.Annotated`:

```python
Sensitive("pii")
Secret()
Untrusted()
External()
TenantScoped()
Privileged()
```

Example:

```python
from typing import Annotated
from secgraphai import secgraph, Sensitive

@secgraph.tool(permission="crm.read")
async def lookup_customer(
    customer_id: str,
) -> Annotated[dict, Sensitive("customer")]:
    ...
```

---

# 20. Aspect / Interceptor Runtime

Python does not require Java-style AOP to achieve interceptor behavior.

Internal aspect API:

```python
class SecurityAspect:

    async def before(self, ctx):
        ...

    async def after(self, ctx):
        ...

    async def error(self, ctx, exc):
        ...
```

Built-in aspects:

- AuthenticationAspect
- AuthorizationAspect
- PromptInjectionAspect
- DataClassificationAspect
- ProvenanceAspect
- TaintTrackingAspect
- ToolPolicyAspect
- RateLimitAspect
- CostAspect
- ApprovalAspect
- AuditAspect
- TraceAspect
- SecretRedactionAspect
- MCPAspect
- RAGAspect
- ExternalBoundaryAspect

Execution:

```text
CALL
 ↓
BEFORE ASPECTS
 ↓
POLICY DECISION
 ↓
ORIGINAL FUNCTION
 ↓
AFTER ASPECTS
 ↓
EVIDENCE + AUDIT
```

---

# 21. Automatic Instrumentation

Do not require decorators everywhere.

Support:

```python
secgraph.instrument_fastapi(app)
secgraph.instrument_httpx()
secgraph.instrument_openai()
secgraph.instrument_mcp()
secgraph.instrument_langchain()
secgraph.instrument_langgraph()
```

Also:

```python
agent = secgraph.instrument(agent)
```

Use `contextvars` to propagate:

- user
- tenant
- trace ID
- security labels
- authorization context
- provenance
- scan ID

---

# 22. Provenance / Taint Model

Labels:

- SYSTEM
- USER
- UNTRUSTED
- EXTERNAL
- TOOL_DATA
- RAG
- MEMORY
- SECRET
- PII
- CONFIDENTIAL
- MODEL_GENERATED

Track confidence:

- exact
- derived
- probabilistic
- unknown

Policies can use labels.

Example:

```text
SECRET → EXTERNAL = DENY
UNTRUSTED → HIGH_RISK_TOOL = APPROVAL
TENANT_A → TENANT_B = DENY
```

---

# 23. Canary Evidence System

Easy to implement, very high value.

Generate controlled:

- secrets
- documents
- customer records
- IDs
- memory entries
- tool results

Example:

```text
SG-CANARY-SECRET-79E4D2
```

A canary observed in an unauthorized location produces deterministic evidence.

API:

```python
secret = secgraph.canary.secret()
record = secgraph.canary.record(tenant="A")
```

---

# 24. Adaptive Red-Team Planner

Workflow:

```text
DISCOVER
 ↓
BUILD GRAPH
 ↓
IDENTIFY HIGH-VALUE BOUNDARIES
 ↓
SELECT RELEVANT TESTS
 ↓
EXECUTE
 ↓
OBSERVE
 ↓
ADAPT
 ↓
VERIFY
```

Do not test irrelevant modules.

Examples:

```text
No RAG → skip RAG attacks
MCP present → prioritize MCP tests
Multiple tenants → prioritize identity isolation
External email tool → prioritize sensitive external-flow tests
```

---

# 25. Evolutionary / Genetic Search

Optional extra:

```bash
pip install "secgraphai[evolution]"
```

Attack genome may include:

- attack family
- input source
- framing
- context placement
- conversation depth
- semantic mutation
- target tool
- target invariant
- sequence
- modality

Fitness should reward measured boundary progress rather than only LLM-judge approval.

Example conceptual fitness:

```text
boundary_progress
+ tool_progress
+ data_flow_progress
+ verified_effect
+ novelty
- request_cost
```

---

# 26. Novelty Search

Prevent generation of near-duplicate tests.

Use:

- embedding similarity
- structure similarity
- attack-path similarity
- tool-sequence similarity

Reward novel approaches that explore different branches of the application graph.

---

# 27. Attack Memory

Store structured observations:

```text
Attempt 1:
direct injection refused

Attempt 2:
RAG input changes behavior

Attempt 3:
tool requested but policy blocked

Attempt 4:
alternate tool reaches approval boundary
```

Use this to guide subsequent tests.

Do not rely on a giant attacker chat transcript as the only memory representation.

---

# 28. Deterministic Validators

Required validator interfaces:

- CanaryValidator
- AuthorizationValidator
- ToolInvocationValidator
- DatabaseStateValidator
- HTTPCallbackValidator
- FileStateValidator
- JSONSchemaValidator
- CrossTenantValidator
- SecretLeakValidator
- PolicyDecisionValidator
- CostValidator
- LatencyValidator
- ResponseCodeValidator

---

# 29. Judge Ensemble

Semantic cases may use:

```text
deterministic evidence
+
judge model A
+
judge model B (optional)
+
classifier
+
policy rules
```

Return:

```python
Verdict(
    state="LIKELY_VIOLATION",
    confidence=0.88,
    evidence=[...],
)
```

The report must clearly distinguish deterministic from probabilistic evidence.

---

# 30. Reproducibility Engine

Every scan should snapshot:

- package version
- test-pack versions
- target config hash
- model name/version if available
- system configuration hash
- policy version
- tool schemas
- retrieval settings
- model parameters
- seed where supported
- request/response trace
- evidence hashes
- timestamps
- environment metadata
- external-engine versions

Command:

```bash
secgraph replay SG-0043
```

---

# 31. Finding-to-Regression Generation

Command:

```bash
secgraph generate-test SG-0043
```

Output:

```python
@pytest.mark.secgraph
async def test_cross_tenant_rag_isolation(secgraph):
    result = await secgraph.replay("SG-0043")
    assert not result.security_boundary_violated
```

Also generate:

- YAML regression case
- JUnit-compatible result
- CI policy entry

---

# 32. Differential Security Testing

Compare:

- model A vs model B
- prompt version A vs B
- guardrail A vs B
- application release A vs B
- policy version A vs B

Command:

```bash
secgraph compare baseline.yaml candidate.yaml
```

Report:

```text
NEW REGRESSIONS
Tool authorization: +1
Prompt injection application impact: +2

FIXED
Cross-tenant retrieval: -1
```

---

# 33. Utility Preservation

Security controls can destroy product usefulness.

Every defense benchmark should optionally measure legitimate-task success.

Report:

```text
Attack success:       12% → 1%
Legitimate success:   96% → 93%
Latency:              +18%
Cost:                 +7%
```

Never recommend a control without showing major utility regressions.

---

# 34. Cost / Resource Security

Track:

- input tokens
- output tokens
- model calls
- tool calls
- retries
- retrieval calls
- external API calls
- wall time
- dollar estimate

Detect abnormal amplification.

Provide budgets:

```bash
secgraph scan --budget-usd 10
secgraph scan --max-requests 500
secgraph scan --max-duration 20m
```

---

# 35. Reporting

Reports are first-class outputs.

Formats:

- HTML
- PDF
- JSON
- JSONL
- Markdown
- CSV
- SARIF
- JUnit XML

Report audiences:

## Executive

- overall risk
- critical findings
- affected business capabilities
- trend
- priority remediation

## Security Engineering

- threat graph
- attack paths
- evidence
- framework mappings
- reproduction
- remediation

## Developer

- code/tool/API location
- trace
- failing policy
- regression test
- recommended implementation change

## Audit/Evidence

- scope
- target versions
- configuration hashes
- evidence hashes
- limitations
- framework mappings

Do not claim certification merely because findings map to standards.

---

# 36. Dashboard / HTTP Service

Install:

```bash
pip install "secgraphai[dashboard]"
```

Start:

```bash
secgraph serve
```

Default:

```text
Dashboard:  http://127.0.0.1:8777
API:        http://127.0.0.1:8777/api/v1
OpenAPI:    http://127.0.0.1:8777/docs
```

**Must bind to localhost by default.**

No remote binding without explicit user action.

---

# 37. Dashboard Views

- Overview
- Targets
- Architecture
- Attack Graph
- Scans
- Findings
- Prompt Injection
- Agents
- RAG
- MCP
- API Security
- Identities
- Runtime
- Policies
- Regression Tests
- Reports
- Models
- Vulnerabilities / CVE
- OWASP Coverage
- Settings
- Self Security

---

# 38. Dashboard API

Initial endpoints:

```text
GET    /api/v1/health
GET    /api/v1/targets
POST   /api/v1/targets

GET    /api/v1/scans
POST   /api/v1/scans
GET    /api/v1/scans/{scan_id}

GET    /api/v1/findings
GET    /api/v1/findings/{finding_id}
POST   /api/v1/findings/{finding_id}/replay

GET    /api/v1/graph
GET    /api/v1/attack-paths

GET    /api/v1/policies
POST   /api/v1/policies/test

GET    /api/v1/reports
POST   /api/v1/reports

GET    /api/v1/self-audit
POST   /api/v1/self-audit
```

Live updates using WebSocket or SSE.

---

# 39. Runtime Firewall

Actions:

- ALLOW
- DENY
- REDACT
- REQUIRE_APPROVAL
- RATE_LIMIT
- SANDBOX
- LOG
- TRANSFORM

Example:

```python
@secgraph.tool(risk="high")
@secgraph.approval(when="amount > 500")
async def refund(customer_id: str, amount: float):
    ...
```

---

# 40. Policy Simulation — Easy High-Impact Feature

Before enabling a runtime policy:

```bash
secgraph policy simulate policy.yaml --against last-7-days
```

Output:

```text
Would block:                 31
Known malicious:             27
Likely legitimate:            4
Estimated false block rate:   1.8%
```

This reduces fear of deploying security controls.

---

# 41. Shadow Mode — Easy High-Impact Feature

Runtime policies initially run without blocking.

```yaml
policy_mode: shadow
```

Dashboard:

```text
Would have blocked: 17 actions
Actually blocked:    0
```

After validation:

```yaml
policy_mode: enforce
```

This is a practical adoption feature.

---

# 42. Explain "Why Was This Blocked?" — Easy High-Impact Feature

Every runtime decision returns:

```text
Blocked because:
1. Input provenance = UNTRUSTED_RAG
2. Tool risk = HIGH
3. No explicit user approval
4. Policy HIGH_RISK_TOOL_FROM_UNTRUSTED requires approval
```

Developers need transparent controls.

---

# 43. Scan Replay Bundles — Easy High-Impact Feature

Export:

```bash
secgraph bundle create SG-0043
```

Produces:

```text
SG-0043.secgraph
```

Contains safe/replayable:

- configuration snapshot
- sanitized interaction
- synthetic evidence
- relevant policies
- test definitions
- versions
- hashes

Import:

```bash
secgraph bundle replay SG-0043.secgraph
```

Useful for teams and bug reports.

---

# 44. Security Baselines — Easy High-Impact Feature

Command:

```bash
secgraph baseline create release-1.4
```

CI:

```bash
secgraph test --baseline release-1.4 --fail-on-regression
```

This avoids arguing about absolute scores and focuses on regressions.

---

# 45. Risk-Aware Test Selection — Easy High-Impact Feature

Prioritize tests based on discovered architecture.

Example:

```text
External write tool + untrusted RAG
→ prioritize injection-to-tool paths.

Multiple identities + shared vector store
→ prioritize tenant isolation.
```

This produces better results with fewer LLM calls.

---

# 46. Framework Crosswalk

Map findings when justified to:

- OWASP LLM Top 10 2026
- OWASP Agentic Applications Top 10 2026
- OWASP Agent Control Standard
- OWASP API Security Top 10
- MITRE ATLAS
- CWE
- NIST AI RMF-related categories
- NIST adversarial ML taxonomy

Do not imply certification.

---


# 46A. OWASP Coverage Engine

SecGraphAI must treat OWASP mappings as executable coverage targets rather than decorative report labels.

The engine should maintain versioned mappings for the current applicable OWASP families and clearly record the exact framework version used by each scan.

## 46A.1 OWASP Top 10 Web Application Security Risks — 2025

SecGraphAI should map applicable web/application findings to:

1. **A01:2025 — Broken Access Control**
2. **A02:2025 — Security Misconfiguration**
3. **A03:2025 — Software Supply Chain Failures**
4. **A04:2025 — Cryptographic Failures**
5. **A05:2025 — Injection**
6. **A06:2025 — Insecure Design**
7. **A07:2025 — Authentication Failures**
8. **A08:2025 — Software or Data Integrity Failures**
9. **A09:2025 — Security Logging & Alerting Failures**
10. **A10:2025 — Mishandling of Exceptional Conditions**

SecGraphAI should provide native checks where appropriate and external-tool correlation where mature tools already exist.

Examples:

```text
A01 Broken Access Control
→ identity matrix
→ cross-tenant tests
→ object/function authorization tests

A02 Security Misconfiguration
→ dashboard exposure
→ CORS
→ debug mode
→ insecure TLS override
→ excessive tool exposure

A03 Software Supply Chain Failures
→ CVE/NVD correlation
→ SBOM
→ plugin trust
→ attack-pack signatures

A05 Injection
→ API/input checks
→ report rendering safety
→ downstream generated-output handling

A09 Logging & Alerting Failures
→ audit trace coverage
→ denied-action logging
→ security event completeness

A10 Mishandling of Exceptional Conditions
→ malformed model responses
→ failed tools
→ timeout/cancellation
→ parser failures
→ fail-closed versus fail-open behavior
```

---

# 46B. OWASP API Security Top 10 — 2023

SecGraphAI should explicitly cover and report against:

1. **API1:2023 — Broken Object Level Authorization**
2. **API2:2023 — Broken Authentication**
3. **API3:2023 — Broken Object Property Level Authorization**
4. **API4:2023 — Unrestricted Resource Consumption**
5. **API5:2023 — Broken Function Level Authorization**
6. **API6:2023 — Unrestricted Access to Sensitive Business Flows**
7. **API7:2023 — Server Side Request Forgery**
8. **API8:2023 — Security Misconfiguration**
9. **API9:2023 — Improper Inventory Management**
10. **API10:2023 — Unsafe Consumption of APIs**

SecGraphAI's API module should expose a coverage matrix such as:

```text
OWASP API COVERAGE
───────────────────────────────────────────
API1 BOLA                         TESTED
API2 Broken Authentication       TESTED
API3 Property Authorization      TESTED
API4 Resource Consumption        TESTED
API5 Function Authorization      TESTED
API6 Sensitive Business Flows    PARTIAL
API7 SSRF                        TESTED
API8 Misconfiguration            TESTED
API9 Inventory                   DISCOVERED
API10 Unsafe API Consumption     TESTED
```

Coverage states:

```text
NOT_APPLICABLE
DISCOVERED
PARTIAL
TESTED
VERIFIED_CONTROL
VERIFIED_FINDING
TEST_ERROR
```

`TEST_ERROR` must never be represented as covered or safe.

---

# 46C. OWASP GenAI / LLM Top 10 — 2026

The 2026 OWASP Top 10 for LLM Applications should be a first-class SecGraphAI test profile.

Current categories:

1. **LLM01:2026 — Prompt Injection**
2. **LLM02:2026 — Sensitive Information Disclosure**
3. **LLM03:2026 — Excessive Agency**
4. **LLM04:2026 — Supply Chain**
5. **LLM05:2026 — Data and Model Poisoning**
6. **LLM06:2026 — Unbounded Consumption**
7. **LLM07:2026 — Misinformation**
8. **LLM08:2026 — Hidden Context Exposure**
9. **LLM09:2026 — Vector and Embedding Weaknesses**
10. **LLM10:2026 — Improper Output Handling**

SecGraphAI should map these categories into native modules.

Example:

```text
LLM01 Prompt Injection
→ direct/indirect/RAG/tool/MCP/memory/multimodal injection

LLM02 Sensitive Information Disclosure
→ canaries
→ secret/PII scanners
→ cross-session and cross-tenant leakage

LLM03 Excessive Agency
→ tool privilege graph
→ approval requirements
→ runtime policy
→ agent scope tests

LLM04 Supply Chain
→ CVE/SBOM
→ model provenance
→ plugin/pack signatures
→ dependency intelligence

LLM05 Data and Model Poisoning
→ RAG poisoning
→ memory poisoning
→ suspicious corpus changes
→ model artifact provenance

LLM06 Unbounded Consumption
→ token/tool/request/cost amplification
→ recursion
→ resource budgets

LLM07 Misinformation
→ task-specific groundedness/verification plugins
→ high-consequence action gating

LLM08 Hidden Context Exposure
→ hidden context/system policy canaries
→ internal metadata disclosure tests

LLM09 Vector and Embedding Weaknesses
→ namespace isolation
→ authorization-before-retrieval
→ retrieval poisoning
→ embedding anomaly tests

LLM10 Improper Output Handling
→ HTML/SQL/template/path/schema output validation
→ downstream sink analysis
```

The PRD should track OWASP framework versions rather than hard-code mappings forever.

---

# 46D. OWASP Top 10 for Agentic Applications — 2026

SecGraphAI should explicitly implement coverage for:

1. **ASI01 — Agent Goal Hijack**
2. **ASI02 — Tool Misuse & Exploitation**
3. **ASI03 — Identity & Privilege Abuse**
4. **ASI04 — Agentic Supply Chain Vulnerabilities**
5. **ASI05 — Unexpected Code Execution (RCE)**
6. **ASI06 — Memory & Context Poisoning**
7. **ASI07 — Insecure Inter-Agent Communication**
8. **ASI08 — Cascading Failures**
9. **ASI09 — Human-Agent Trust Exploitation**
10. **ASI10 — Rogue Agents**

Example native mappings:

```text
ASI01
→ adaptive goal-hijack tests
→ provenance-aware runtime interception

ASI02
→ tool attack graph
→ argument validation
→ tool chaining
→ approval policies

ASI03
→ principal context
→ identity matrix
→ tenant boundaries
→ scoped credentials

ASI04
→ MCP/plugin/pack/model/dependency trust
→ CVE + SBOM intelligence

ASI05
→ code-execution capability discovery
→ strict sandbox policy
→ dangerous sink mapping

ASI06
→ persistent memory injection
→ RAG/context poisoning
→ cross-session tests

ASI07
→ multi-agent identity preservation
→ message provenance
→ delegation authorization

ASI08
→ recursion and failure propagation
→ circuit breakers
→ resource caps
→ downstream effect graph

ASI09
→ approval UX
→ misleading action explanations
→ confirmation integrity tests

ASI10
→ unexpected capability drift
→ rogue tool use
→ policy divergence
→ behavioral/runtime anomaly hooks
```

---

# 46E. OWASP Agent Control Standard Alignment

SecGraphAI's runtime architecture should maintain an explicit compatibility layer for the OWASP Agent Control Standard where practical.

Relevant SecGraphAI concepts:

```text
ACS-style control hooks
        ↕
SecGraph interceptors/aspects

runtime policy
        ↕
SecGraph invariants

agent observability
        ↕
SecGraph traces + graph

tool control
        ↕
before_tool / after_tool

external action control
        ↕
ExternalBoundaryAspect
```

The project should publish a living compatibility matrix rather than claim automatic compliance.

---

# 46F. OWASP Coverage Profile

Command:

```bash
secgraph owasp coverage
```

Example:

```text
SECGRAPH OWASP COVERAGE
═══════════════════════════════════════════

OWASP Web Top 10:2025          9/10 tested
OWASP API Top 10:2023         10/10 tested
OWASP LLM Top 10:2026         10/10 tested
OWASP Agentic Top 10:2026      9/10 tested

Deterministically verified:      61%
LLM-assisted evaluation:         21%
Configuration assessment:        12%
Not applicable:                   6%
Test errors:                      0
```

Coverage must never imply OWASP certification or endorsement.

---

# 46G. OWASP Test Profiles

Provide:

```bash
secgraph scan --profile owasp-web-2025
secgraph scan --profile owasp-api-2023
secgraph scan --profile owasp-llm-2026
secgraph scan --profile owasp-agentic-2026
secgraph scan --profile owasp-full
```

`owasp-full` should intelligently skip tests that do not apply to the discovered architecture.

---

# 46H. OWASP Regression Gates

Teams should be able to define:

```yaml
security_gate:
  owasp:
    llm_2026:
      required:
        - LLM01
        - LLM02
        - LLM03
        - LLM06

    api_2023:
      required:
        - API1
        - API2
        - API5
```

CI fails only on relevant verified regressions according to configured policy.

---

# 46I. CVE / Vulnerability Intelligence Engine

SecGraphAI must include a first-class known-vulnerability intelligence subsystem.

The objective is not merely:

> "This dependency has CVE-XXXX-YYYY."

The objective is:

> "This running AI application includes an affected component, the vulnerable version is reachable from a discovered AI/API/agent attack path, exploitation would cross this security boundary, and this finding should be prioritized accordingly."

---

# 46J. CVE Data Sources

Primary data sources:

## CVE Program

Use CVE identifiers and CVE Records as the canonical public vulnerability identifiers.

## NIST National Vulnerability Database

Use NVD API/data feeds for enrichment including, when available:

- CVE description
- CVSS metrics
- affected product information
- CPE data
- CWE mappings
- references
- Known Exploited Vulnerabilities-related enrichment
- SSVC data
- last-modified timestamps

SecGraphAI should use NVD API 2.0 or NVD JSON 2.0 feeds, not retired legacy feeds.

NVD API keys should be optional but recommended for large synchronization workloads.

---

# 46K. CVSS 4.0 Support

SecGraphAI should parse and preserve:

- CVSS version
- vector string
- Base
- Threat
- Environmental context where available

Support CVSS v4.0 and older CVSS values present in vulnerability feeds.

Do **not** treat CVSS as the complete risk score.

A CVSS 9.8 vulnerability in an unreachable optional dependency may be less urgent to the current application than a lower-scored flaw directly reachable from an exposed agent tool.

---

# 46L. SSVC and Known Exploitation Context

Where provided by authoritative data, SecGraphAI should enrich prioritization with:

- Known Exploited Vulnerabilities status
- SSVC decisions/attributes
- exploit maturity
- public exploit references
- affected-version confidence

Example:

```text
CVE-20XX-12345

CVSS:                   8.8 HIGH
Known exploited:        YES
SSVC priority:           ACT
Installed component:     YES
Affected version:        YES
Reachable:               YES
Agent path:              YES

SecGraph Priority:
CRITICAL
```

---

# 46M. Component Identification

Support component identifiers:

- package name + ecosystem
- package URL (purl)
- CPE
- Python distribution/version
- container package metadata
- model runtime/version
- MCP server package/version
- JavaScript dashboard dependencies
- external tool versions

For Python:

```text
importlib.metadata
pip metadata
SBOM
lockfile
```

For dashboard assets:

```text
package-lock.json
pnpm-lock.yaml
yarn.lock
SBOM
```

---

# 46N. SBOM Integration

Generate and ingest:

- CycloneDX
- SPDX where practical

Command:

```bash
secgraph sbom generate
secgraph sbom scan ./bom.json
```

A SecGraphAI release should generate its own SBOM.

AI-application assessments may attach multiple SBOMs:

```text
Python application
Dashboard
Container
Model server
MCP servers
External security tools
```

---

# 46O. Reachability-Aware CVE Prioritization

This is a major differentiator.

Build:

```text
Component with CVE
      ↓
Imported / deployed?
      ↓
Reachable service?
      ↓
Exposed endpoint/tool?
      ↓
Attacker-controlled path?
      ↓
Security boundary?
      ↓
Sensitive impact?
```

Finding example:

```text
KNOWN VULNERABILITY CORRELATION

CVE:              CVE-20XX-12345
Component:        package-x 2.4.1
Affected:         YES
Runtime loaded:   YES
Reachable:        YES

Attack path:

Untrusted RAG
   ↓
Agent
   ↓
MCP tool
   ↓
Internal API
   ↓
package-x vulnerable parser

Graph confidence: 0.92
```

Do not claim exploitability purely from static reachability.

Use status:

```text
PRESENT
AFFECTED
POTENTIALLY_REACHABLE
REACHABLE
EXPLOITABILITY_UNVERIFIED
VERIFIED_IN_LAB
MITIGATED
NOT_AFFECTED
```

---

# 46P. CVE Correlation With Findings

Every SecGraph finding may contain:

```python
cve_ids: list[str]
cwe_ids: list[str]
cvss: list[CVSSMetric]
ssvc: list[SSVCDecision]
known_exploited: bool | None
component_ids: list[ComponentID]
owasp_mappings: list[FrameworkMapping]
```

Example:

```text
SG-109

AI-assisted vulnerable component path

OWASP:
LLM04:2026 Supply Chain
ASI04 Agentic Supply Chain Vulnerabilities
A03:2025 Software Supply Chain Failures

CVE:
CVE-20XX-12345

CWE:
CWE-XXX
```

---

# 46Q. CWE Correlation

CVE identifies a vulnerability instance.

CWE describes weakness classes.

SecGraphAI should map findings to CWE only when justified.

Examples:

```text
Authorization failure
→ relevant authorization CWE

Unsafe external URL handling
→ relevant SSRF CWE

Improper output rendering
→ relevant injection/output CWE
```

Do not fabricate CWE mappings for purely behavioral AI failures where no meaningful CWE exists.

---

# 46R. CVE Search CLI

Commands:

```bash
secgraph cve show CVE-2026-12345
secgraph cve search package-name
secgraph cve sync
secgraph cve affected
secgraph cve reachable
```

Example:

```text
$ secgraph cve affected

Known affected components:       7
Known exploited:                 1
Potentially reachable:           3
Agent/API reachable:             1
Not reachable:                   4
Unknown reachability:            2
```

---

# 46S. CVE Dashboard

Add **Vulnerabilities** to dashboard navigation.

Views:

```text
Known Vulnerabilities
Affected Components
Known Exploited
Reachability
Supply Chain
SBOM
```

Finding table:

| CVE | Component | CVSS | KEV | Reachability | AI Path | Priority |
|---|---|---:|---|---|---|---|
| CVE-X | library-a | 9.1 | Yes | Reachable | Agent→API | Critical |
| CVE-Y | library-b | 9.8 | No | Not loaded | None | Low |
| CVE-Z | server-c | 7.5 | No | Unknown | MCP | Review |

This prevents high CVSS alone from dominating prioritization.

---

# 46T. CVE Report Section

Technical reports should include:

```text
Known vulnerability inventory
Affected version evidence
CVE/CWE IDs
CVSS vector
Known exploitation status
SSVC context if available
Graph reachability
Related AI attack paths
Mitigating controls
Upgrade/fix recommendation
Verification status
```

Executive reports should show only prioritized known-vulnerability exposure.

---

# 46U. CVE Cache / Offline Mode

Do not query remote databases for every scan.

Provide:

```bash
secgraph cve sync
```

Cache vulnerability metadata locally.

Requirements:

- incremental synchronization
- rate-limit awareness
- ETag/last-modified behavior where available
- bounded payload handling
- resumable sync
- cache schema version
- offline scan support

Organizations should be able to supply an internal vulnerability feed.

---

# 46V. Vulnerability Data Is Untrusted Input

NVD/CVE descriptions, references and vendor strings must be treated as untrusted external data.

Requirements:

- safe JSON parsing
- maximum field lengths
- HTML escaping
- URL sanitization
- no automatic execution of referenced PoCs
- no automatic cloning of repositories
- no rendering of arbitrary remote HTML
- no credentials sent to referenced domains

A CVE reference is evidence/navigation metadata, **not permission to execute exploit code**.

---

# 46W. Optional Vulnerability Prioritization Formula

Keep raw source scores separate from SecGraph priority.

Conceptual application priority:

```text
SecGraphPriority =
    Severity
  × AffectedConfidence
  × Reachability
  × Exposure
  × SecurityBoundaryImpact
  × ExploitationContext
```

The UI must expose why the priority changed.

Example:

```text
CVSS Base:          9.8
Affected:           confirmed
Runtime reach:      none observed
External exposure:  none
AI attack path:     none

Application Priority:
MEDIUM

Reason:
high-severity vulnerable component exists,
but it is not currently loaded/reachable in
the assessed deployment.
```

---

# 46X. CVE / OWASP Security Gates

CI configuration:

```yaml
security_gate:

  cve:
    fail_on:
      known_exploited: true
      reachable_cvss_gte: 8.0

  owasp:
    fail_on_verified:
      - A01:2025
      - API1:2023
      - LLM01:2026
      - LLM02:2026
      - ASI03
```

Again, framework identifiers are mappings—not certifications.

---

# 46Y. SecGraphAI Self-CVE Audit

`secgraph self-audit` must include SecGraphAI's own dependency vulnerability status.

Example:

```text
SECGRAPH SELF-AUDIT

Python components scanned:       43
Dashboard components scanned:   812

Known vulnerabilities:            2

Reachable/high priority:           0
Known exploited:                   0
Needs upgrade:                     2
```

Release policy:

- no known unmitigated critical vulnerability in a shipped reachable component
- known exceptions require documented risk acceptance and mitigation
- dependency intelligence data age displayed in release report

---

# 46Z. Tests for CVE / OWASP Intelligence

## Unit tests

Test:

- CVE ID parsing
- CVSS vectors
- NVD schema handling
- affected version ranges
- CPE parsing
- purl parsing
- SSVC parsing
- KEV flag handling
- duplicate records
- rejected malformed records
- cache migrations
- stale-cache behavior

## Property tests

Generate:

- version ranges
- malformed CPEs
- random CVE records
- large reference lists
- unusual Unicode
- missing enrichment

Properties:

```text
Unknown affected status must never become AFFECTED.

Parser failure must never become NOT_AFFECTED.

A malformed CVSS vector must never crash a complete scan.

A CVE reference URL must never be fetched automatically.
```

## Integration tests

Use recorded safe fixture responses for:

- NVD API 2.0
- CVE records
- affected-data schema
- SSVC
- multiple CVSS versions

## Security tests

Test:

- malicious CVE descriptions cannot inject report HTML/JS
- giant CVE payload is bounded
- malicious redirect does not bypass scope rules
- vulnerability feed cannot overwrite arbitrary files
- compressed feed cannot cause archive bomb
- cache corruption fails safely
- source outage does not mark components safe

## OWASP mapping tests

Every built-in attack/test must declare:

```text
framework version
category
mapping strength
rationale
```

Mappings should have review tests so a category rename/version change cannot silently corrupt historical reports.

---


# 47. Attack Pack System

Structure:

```text
packs/
├── llm/
├── prompt_injection/
├── agent/
├── mcp/
├── rag/
├── api/
├── identity/
└── privacy/
```

Pack metadata:

```yaml
id: secgraph.prompt-injection.core
version: 1.1.0
publisher: secgraphai
minimum_engine: 0.3.0
signature: ...
```

---

# 48. Signed Attack Packs — Important Trust Feature

Official packs should be cryptographically signed.

SecGraphAI should distinguish:

```text
TRUSTED_OFFICIAL
TRUSTED_ORGANIZATION
UNVERIFIED_COMMUNITY
LOCAL
```

Default behavior:

- official signed packs: enabled
- organization-approved packs: enabled
- unknown community packs: require explicit trust
- unsigned remote pack: disabled by default

This reduces plugin/pack supply-chain risk.

---

# 49. Plugin Isolation — Important Self-Security Feature

Do not execute arbitrary third-party plugin code inside the main process by default.

Plugin modes:

```text
in_process       # trusted only
subprocess       # preferred third-party mode
container        # optional high isolation
```

Subprocess plugins receive:

- sanitized target interface
- scoped credentials
- limited filesystem access where possible
- explicit timeout
- output schema validation

Never give a plugin the user's raw credential store by default.

---

# 50. External Security Tool Adapters

Adapters should normalize findings from:

- PyRIT
- garak
- Promptfoo
- DeepTeam
- Schemathesis
- LLM Guard
- Presidio
- Semgrep
- CodeQL
- OWASP ZAP
- Nuclei
- detect-secrets
- pip-audit
- OSV tooling
- ModelScan / equivalent model scanners where appropriate

SecGraphAI adds:

- graph context
- security invariant correlation
- evidence
- attack path
- prioritization
- regression generation

---

# 51. Unified Finding Schema

```python
Finding(
    id="SG-0043",
    title="Cross-tenant RAG exposure",
    severity="CRITICAL",
    confidence=0.994,
    verification="DETERMINISTIC",
    actor="company_b_user",
    asset="company_a_document",
    attack_path=[...],
    invariant="TENANT_ISOLATION",
    evidence=[...],
    remediation=[...],
    mappings={...},
)
```

---

# 52. Local Storage

Default:

```text
~/.secgraphai/secgraph.db
```

Use SQLite initially.

Tables:

- targets
- scans
- findings
- events
- attack_paths
- graph_nodes
- graph_edges
- policies
- evidence
- reports
- baselines
- bundles
- plugin_registry

Later support PostgreSQL.

---

# 53. Privacy Requirements

Default behavior:

- no telemetry
- no cloud upload
- local database
- secret redaction
- no raw API key persistence
- configurable evidence retention
- local LLM support
- air-gapped operation
- encrypted evidence option

---

# 54. Self-Security Threat Model

SecGraphAI itself may process deliberately hostile content.

Primary threats include:

## 54.1 Malicious Target Output

A target may return:

- malicious HTML
- huge responses
- invalid JSON
- deeply nested JSON
- terminal escape sequences
- crafted Unicode
- malicious URLs

Controls:

- size limits
- parsing limits
- render escaping
- terminal sanitization
- timeout
- schema validation

## 54.2 Malicious Report Content

Never render untrusted target content directly into HTML.

Controls:

- auto-escape
- Content Security Policy
- no inline executable content
- safe Markdown renderer
- no arbitrary HTML
- sanitize URLs

## 54.3 Malicious Plugin

Controls:

- signed official plugins
- trust levels
- subprocess isolation
- capability manifest
- explicit permission grants
- timeout
- resource bounds

## 54.4 Malicious Attack Pack

Attack packs should be data-first.

Prefer declarative YAML/JSON test definitions over executable Python.

Executable extensions require trust.

## 54.5 Credential Exposure

Controls:

- credentials only from environment/secret callback
- never log keys
- redact known secret patterns
- redact Authorization headers
- redact cookie values
- never include raw secrets in report exports

## 54.6 Dashboard Remote Exposure

Controls:

- localhost by default
- explicit `--host 0.0.0.0`
- warning on remote bind
- authentication required for non-loopback
- CSRF protections if browser cookies are used
- strict CORS
- secure headers

## 54.7 SSRF Through Scanner

The scanner itself can become an SSRF client.

Controls:

- explicit allowlist scope
- block link-local/cloud metadata IP ranges by default
- block loopback unless target explicitly includes it
- resolve host and validate resulting IP
- revalidate redirects
- configurable DNS policy
- no unrestricted arbitrary fetch plugins

## 54.8 Archive/File Attacks

Controls:

- reject path traversal
- file-size limits
- archive decompression ratio limits
- sanitized filenames
- temporary-directory isolation

## 54.9 Prompt Injection Against Security LLM

Target content must be wrapped as untrusted evidence, never concatenated into privileged control instructions without separation.

Controls:

- structured messages
- separate instruction/data roles
- JSON schemas
- minimal tool access for security LLM
- no credentials supplied to attack/judge LLM unless strictly needed

---

# 55. Self-Audit Command — Must-Have Differentiator

Command:

```bash
secgraph self-audit
```

It checks SecGraphAI's own installation:

```text
SecGraphAI Self Audit

Package integrity             PASS
Dependency vulnerabilities    PASS
Unexpected plugins            PASS
Plugin signatures             PASS
Config permissions            PASS
Database permissions          PASS
Dashboard bind                PASS
TLS configuration             N/A
Secret exposure               PASS
Attack pack signatures        PASS
Unsafe environment vars       WARN
Version freshness             PASS
```

Optional:

```bash
secgraph self-audit --deep
```

Runs:

- dependency audit
- secret scan on config
- package metadata check
- plugin trust audit
- local server configuration check
- storage permission check
- attack-pack signature check

This should also appear in the dashboard under **Self Security**.

---

# 56. Secure Configuration Doctor — Easy High-Impact Feature

Command:

```bash
secgraph doctor
```

Checks:

- incorrect API key storage
- remote dashboard without authentication
- overly broad target scope
- no request budget
- unsafe plugin execution
- writable attack-pack directory
- outdated official packs
- missing evidence redaction
- debug mode
- permissive CORS

---

# 57. Scope Guard

Every active scan should have an explicit scope.

Example:

```yaml
scope:
  allowed_hosts:
    - staging.example.internal

  allowed_ports:
    - 443

  blocked_networks:
    - 169.254.0.0/16

  max_requests_per_second: 5
  max_total_requests: 1000

  prohibit:
    - destructive_write
    - account_deletion
```

Default active scanning must refuse unspecified remote destructive actions.

---

# 58. Safe Operating Modes

```text
PASSIVE
SAFE
LAB
CUSTOM
```

## PASSIVE

No active security requests beyond metadata discovery.

## SAFE

Non-destructive testing.

## LAB

Expanded testing against user-controlled environments.

## CUSTOM

Explicit policy-defined test permissions.

Default: `SAFE`.

---

# 59. Dashboard Security Requirements

The dashboard should be treated like a security-sensitive web application.

## Required

- bind localhost by default
- no debug stack traces to unauthenticated remote clients
- CSP
- X-Content-Type-Options
- frame restrictions
- strict CORS
- safe template escaping
- no raw HTML from findings
- API input validation
- request body size limits
- authenticated non-local deployment
- optional TLS termination documentation
- WebSocket authentication for remote mode
- CSRF protection where cookie auth exists
- rate limits for expensive scan endpoints
- per-scan authorization in multi-user future mode

---

# 60. Report Security Requirements

Reports may contain hostile strings from the target.

Requirements:

- HTML escape all target-controlled content
- sanitize Markdown
- do not embed arbitrary external resources by default
- no JavaScript in portable HTML reports unless bundled and trusted
- redact secrets
- redact tokens and cookies
- configurable PII masking
- safe file names
- report hash manifest

---

# 61. Evidence Integrity

Every evidence artifact gets SHA-256.

Each scan generates:

```text
scan-manifest.json
```

containing hashes for:

- configuration
- policies
- evidence
- findings
- reports
- regression tests

Future:

- Sigstore signing
- organization signing keys
- tamper-evident audit chain

---

# 62. Supply-Chain Security

Release pipeline requirements:

- lock/pin dependencies appropriately
- Dependabot/Renovate
- `pip-audit`
- OSV scanning
- SBOM generation
- trusted PyPI publishing using OIDC when practical
- signed Git tags/releases
- branch protection
- required review
- reproducible wheel checks where practical
- no long-lived PyPI token in CI
- provenance attestation where available
- dependency licenses reviewed

Generate:

```text
CycloneDX SBOM
```

for each release.

---

# 63. Secure Coding Toolchain

Recommended developer tools:

- Ruff
- Pyright or mypy
- pytest
- pytest-asyncio
- pytest-xdist
- Hypothesis
- coverage.py
- Bandit
- Semgrep
- pip-audit
- detect-secrets
- pre-commit
- Schemathesis
- OWASP ZAP for dashboard/API dynamic tests
- Playwright for dashboard end-to-end tests

Optional:

- mutmut for mutation testing
- Atheris for fuzzing critical parsers
- Trivy for container images
- CodeQL on GitHub

---

# 64. Unit Test Strategy

A security package requires unusually strong tests.

## 64.1 Core Models

Test:

- Pydantic validation
- invalid states rejected
- enum handling
- serialization/deserialization
- unknown field behavior
- backward compatibility

## 64.2 Provider Layer

Test:

- timeout
- retry
- malformed JSON
- streaming interruptions
- 401/403/429/500 behavior
- oversized response
- missing fields
- model endpoint incompatibility
- redaction in logs

Use mocked HTTP servers.

## 64.3 Security Graph

Test:

- node creation
- edge creation
- deduplication
- path discovery
- cycles
- tenant-boundary detection
- sensitive-to-external path detection
- graph serialization

## 64.4 Policy Engine

Use exhaustive/property-based tests.

Test:

- allow
- deny
- approval
- precedence
- conflict resolution
- missing fields
- unknown labels
- malformed policies
- policy simulation

Policy engine target:

**100% branch coverage for security-critical evaluation code where practical.**

## 64.5 Provenance Engine

Test:

- label creation
- label propagation
- merge behavior
- unknown provenance
- nested tool calls
- async context propagation
- task isolation
- `contextvars` leakage prevention

## 64.6 Decorators

Test:

- sync functions
- async functions
- exceptions
- stacked decorators
- decorator ordering
- metadata preservation
- `functools.wraps`
- methods
- static/class methods where supported

## 64.7 Aspect Engine

Test:

- before order
- after order
- error chain
- cancellation
- denied call never reaches original
- modified result handling
- one aspect failure does not silently bypass security

## 64.8 Canary System

Test:

- uniqueness
- deterministic IDs where seeded
- no accidental collisions
- safe serialization
- detection
- redaction exceptions for synthetic canaries

## 64.9 Finding Verification

Test every state transition:

```text
UNVERIFIED
VERIFIED
LIKELY
INCONCLUSIVE
BLOCKED
TEST_ERROR
OUT_OF_SCOPE
```

Especially prove that:

```text
ERROR != PASS
```

## 64.10 Report Generation

Test:

- malicious HTML escaped
- scripts escaped
- Unicode handled
- long strings truncated appropriately
- secrets redacted
- invalid URLs sanitized
- deterministic report snapshot

## 64.11 Storage

Test:

- migrations
- concurrent writes
- corrupted DB handling
- permissions
- rollback
- export/import

## 64.12 CLI

Test every command using Typer's testing facilities.

---

# 65. Property-Based Testing

Hypothesis should test:

- policy expressions
- graph shapes
- random tool schemas
- random OpenAPI fragments
- nested JSON responses
- Unicode
- long prompt structures
- labels
- access matrices
- report content
- configuration merges

Property example:

```text
A denied policy decision must never call the protected function.
```

Generate thousands of randomized conditions to verify it.

---

# 66. Mutation Testing

Security-critical modules should periodically use mutation testing.

Priority:

1. policy engine
2. authorization rules
3. scope guard
4. secret redaction
5. plugin trust checks
6. report escaping

Goal:

Tests should fail if critical conditions are inverted or removed.

---

# 67. Fuzzing

Fuzz parsers that ingest attacker-controlled content:

- OpenAI-compatible response parser
- MCP metadata parser
- OpenAPI parser
- attack-pack parser
- bundle import
- report sanitization
- URL/scope parser

Atheris may be used for Python fuzzing in a nightly/weekly workflow.

---

# 68. Security Integration Tests

Create an intentionally vulnerable demo AI application.

Components:

```text
FastAPI
OpenAI-compatible mock model
RAG
SQLite/PostgreSQL
3 tools
2 tenants
optional MCP server
```

Seed vulnerabilities:

- cross-tenant retrieval
- unapproved privileged tool
- indirect prompt injection
- unsafe external data flow
- API object-authorization bug
- excessive agent recursion

Then maintain two versions:

```text
demo/vulnerable
demo/hardened
```

Acceptance:

- SecGraphAI must find seeded vulnerabilities in vulnerable mode.
- Hardened mode must block them.
- Normal business tasks must still succeed.

---

# 69. Self-Dogfooding

Run SecGraphAI against its own:

- FastAPI dashboard API
- report renderer
- configuration endpoints
- plugin interfaces

Example CI:

```bash
secgraph scan http://127.0.0.1:8777 --profile self
```

The product should continuously test itself.

---

# 70. Static Security Audit

Every PR:

- Ruff
- type checking
- Bandit
- Semgrep security rules
- secret detection
- dependency audit

Scheduled:

- CodeQL
- deeper Semgrep
- dependency review

Release:

- no critical/high known dependency vulnerabilities unless documented and accepted
- no committed secrets
- SBOM produced

---

# 71. Dynamic Security Audit

Dashboard/API release testing:

- Schemathesis
- ZAP baseline
- route authentication checks
- CORS tests
- CSP tests
- malicious report payload tests
- rate-limit tests
- WebSocket authorization tests
- oversized request tests

---

# 72. Manual Security Review

Before 1.0:

Review:

- trust boundaries
- plugin model
- subprocess execution
- target scope rules
- URL resolution/redirect handling
- secret storage
- report renderer
- dashboard auth
- archive import
- policy engine

A third-party penetration test is recommended before enterprise claims.

---

# 73. Vulnerability Disclosure Program

Before public 1.0:

Add:

```text
SECURITY.md
```

Include:

- supported versions
- reporting channel
- encryption key if available
- expected response process
- coordinated disclosure policy

Later:

- GitHub private vulnerability reporting
- bug bounty when resources allow

Never claim "zero vulnerabilities."

Use language:

> "No known unmitigated critical vulnerabilities at release time based on the documented audit process."

---

# 74. CI Pipeline

Every pull request:

```text
lint
type-check
unit tests
property tests
secret scan
Bandit
Semgrep
dependency audit
package build
wheel install smoke test
dashboard tests
```

Nightly:

```text
extended adversarial tests
fuzz tests
mutation tests
ZAP
CodeQL
demo vulnerable/hardened regression
```

Release gate:

```text
all critical tests pass
SBOM generated
no secrets
no unreviewed dependency vulnerability
signed artifacts/provenance
self-audit pass
```

---

# 75. Code Coverage Targets

Recommended:

- global: >= 90%
- security-critical modules: >= 95%
- policy engine: near 100% branch coverage
- scope guard: near 100% branch coverage
- secret redaction: near 100%
- plugin trust verification: near 100%

Coverage alone is not sufficient; combine it with mutation/property testing.

---

# 76. External Tool Adapter Security

Adapters that execute processes must:

- avoid `shell=True`
- pass argv arrays
- validate executable path
- set timeout
- capture bounded stdout/stderr
- redact secrets
- use temporary directories
- validate output schemas
- never interpolate untrusted values into shell commands

---

# 77. Network Safety

HTTP client requirements:

- timeout everywhere
- connect/read/write limits
- bounded redirects
- maximum response sizes
- target scope verification
- no automatic credential forwarding across host changes
- proxy behavior explicit
- TLS verification enabled by default
- insecure TLS only with explicit flag and warning

---

# 78. Secret Handling

Configuration should use:

```yaml
api_key_env: SECURITY_LLM_KEY
```

not:

```yaml
api_key: sk-live-...
```

Support callback providers:

```python
def get_secret(name: str) -> str:
    ...
```

Never persist secret values in scan snapshots.

Store only:

```text
secret reference
redacted hash/fingerprint if needed
```

---

# 79. Dashboard Authentication

Local mode:

```text
127.0.0.1 only
```

Remote mode:

```bash
secgraph serve --host 0.0.0.0 --auth token
```

Should require explicit auth config.

Future:

- OIDC
- SSO
- RBAC

---

# 80. Plugin Permissions

Plugin manifest:

```yaml
permissions:
  network:
    - target
  filesystem:
    read:
      - temporary
  model_access:
    - attacker
  secrets:
    - none
```

SecGraphAI can display:

```text
This plugin requests:
✓ target network access
✗ secret access
✓ temp storage

Trust?
```

This is a meaningful differentiator for an extensible security platform.

---

# 81. Attack DSL

Prefer declarative packs.

Example:

```yaml
id: rag_cross_tenant
category: authorization

requires:
  - rag
  - multiple_identities

setup:
  canary:
    tenant: A

execute:
  actor: tenant_B
  action: retrieve

verify:
  must_not_observe:
    - canary

severity: critical
```

This lets community contributors build tests without arbitrary code.

---

# 82. Easy-but-Differentiating Features

These should be prioritized because they offer strong value for modest implementation cost.

## 82.1 `secgraph doctor`

Detect unsafe configuration.

## 82.2 `secgraph self-audit`

Audit the security product itself.

## 82.3 Evidence Canaries

Turn fuzzy leakage into deterministic proof.

## 82.4 "Error Is Not Safe"

Never count infrastructure failures as passes.

## 82.5 Security Baselines

Compare releases, not just absolute scores.

## 82.6 Policy Shadow Mode

Let teams observe before enforcing.

## 82.7 Policy Simulation

Estimate impact before deployment.

## 82.8 Finding Replay Bundles

Share reproducible sanitized findings.

## 82.9 Attack Cost Budgets

Prevent expensive red-team runs.

## 82.10 Test Selection

Skip irrelevant attacks automatically.

## 82.11 Security Decision Explanation

Explain every block/approval.

## 82.12 Plugin Trust Levels

Make extensibility safer.

## 82.13 Finding Confidence Labels

Separate deterministic evidence from LLM judgment.

## 82.14 `secgraph diff`

Security regression comparison.

## 82.15 Auto-generated pytest

Turn findings into engineering artifacts.

---

# 83. Research Importer — Future

Command:

```bash
secgraph research import paper.pdf
```

LLM extracts:

- threat model
- prerequisites
- test method
- evaluation approach
- limitations

Generate a **draft** attack pack.

Human review is required before activation.

---

# 84. Model Supply-Chain Module — Future

Inspect:

- artifact hashes
- provenance
- external files
- unsafe serialization
- model metadata
- dependency manifests
- deployment policies
- model format

Optional integrations:

- ModelScan
- Picklescan
- custom ONNX analyzer

---

# 85. Multimodal Security — Future

Support:

- image context
- document rendering
- PDFs
- audio transcript context
- web pages

Keep the same invariant/outcome model.

---

# 86. Dashboard Frontend

Recommended:

- React
- TypeScript
- Vite

Development only requires Node.

Production Python wheel contains compiled static assets.

Users should not need Node:

```bash
pip install "secgraphai[dashboard]"
secgraph serve
```

---

# 87. Server Dependencies

Optional dashboard extra:

```text
fastapi
uvicorn
sqlalchemy
aiosqlite
jinja2
python-multipart
websockets
```

Optional PDF:

```text
weasyprint
```

---

# 88. Testing Dependencies

```text
pytest
pytest-asyncio
pytest-xdist
hypothesis
coverage
respx
freezegun
```

Dashboard:

```text
playwright
schemathesis
```

Security:

```text
bandit
semgrep
pip-audit
detect-secrets
```

---

# 89. Proposed Repository Layout

```text
secgraphai/
│
├── core/
│   ├── context.py
│   ├── target.py
│   ├── finding.py
│   ├── evidence.py
│   └── verdict.py
│
├── providers/
│   ├── openai_compatible.py
│   └── base.py
│
├── discovery/
│   ├── python.py
│   ├── fastapi.py
│   ├── openapi.py
│   ├── mcp.py
│   ├── rag.py
│   └── framework.py
│
├── graph/
│   ├── architecture.py
│   ├── security_graph.py
│   ├── attack_graph.py
│   └── planner.py
│
├── invariants/
│   ├── model.py
│   ├── parser.py
│   └── evaluator.py
│
├── attacks/
│   ├── prompt_injection/
│   ├── llm/
│   ├── agent/
│   ├── rag/
│   ├── mcp/
│   ├── api/
│   ├── identity/
│   └── privacy/
│
├── strategies/
│   ├── static.py
│   ├── adaptive.py
│   ├── mutation.py
│   ├── tree.py
│   └── genetic.py
│
├── validators/
│   ├── canary.py
│   ├── authorization.py
│   ├── tool.py
│   ├── state.py
│   └── semantic.py
│
├── runtime/
│   ├── decorators.py
│   ├── annotations.py
│   ├── aspects.py
│   ├── interceptors.py
│   ├── provenance.py
│   ├── policy.py
│   └── approval.py
│
├── integrations/
│   ├── pyrit.py
│   ├── garak.py
│   ├── promptfoo.py
│   ├── deepteam.py
│   ├── schemathesis.py
│   ├── llmguard.py
│   └── security_tools.py
│
├── reporting/
│   ├── html.py
│   ├── pdf.py
│   ├── json.py
│   ├── markdown.py
│   ├── sarif.py
│   └── junit.py
│
├── server/
│   ├── app.py
│   ├── auth.py
│   ├── routes/
│   └── events.py
│
├── dashboard/
│   └── static/
│
├── storage/
│   ├── models.py
│   ├── sqlite.py
│   └── migrations/
│
├── packs/
│   ├── registry.py
│   ├── signature.py
│   └── loader.py
│
├── self_security/
│   ├── audit.py
│   ├── doctor.py
│   ├── redaction.py
│   └── scope.py
│
├── pytest_plugin/
│
└── cli/
```

---

# 90. CLI

```text
secgraph init
secgraph discover
secgraph scan
secgraph test
secgraph replay
secgraph compare
secgraph baseline
secgraph report
secgraph generate-test
secgraph policy test
secgraph policy simulate
secgraph serve
secgraph dev
secgraph doctor
secgraph self-audit
secgraph engines
secgraph plugins
secgraph packs
secgraph bundle
```

---

# 91. Example Workflow

```bash
pip install "secgraphai[all]"

secgraph init

export TARGET_API_KEY=...
export SECURITY_LLM_KEY=...

secgraph discover http://127.0.0.1:8000

secgraph scan \
  --profile safe \
  --dashboard \
  --budget-usd 5

secgraph report latest --format html

secgraph generate-test SG-0043

secgraph self-audit
```

---

# 92. Developer SDK Example

```python
from secgraphai import SecGraph

security = SecGraph(
    target={
        "base_url": "http://127.0.0.1:8000/v1",
        "api_key_env": "TARGET_API_KEY",
        "model": "support-agent",
    },
    attacker={
        "base_url": "http://127.0.0.1:9000/v1",
        "api_key_env": "SECURITY_LLM_KEY",
        "model": "security-model",
    },
)

report = await security.scan(
    modules=[
        "prompt_injection",
        "agent",
        "rag",
        "mcp",
        "api",
    ],
    strategy="adaptive",
)

report.save("security-report.html")
```

---

# 93. MVP 0.1

Must prove the architecture.

Build:

## Core

- OpenAI-compatible model adapter
- Python callback target
- CLI
- config
- SQLite
- finding schema
- evidence schema

## Security

- prompt injection test families
- system prompt canary leakage
- secret canaries
- basic tool-call interception
- security invariants
- deterministic validators
- LLM judge fallback

## API

- basic OpenAPI discovery
- identity matrix prototype
- Schemathesis integration

## Runtime

- decorators
- interceptors
- authorization
- approval
- audit trace

## Reporting

- terminal
- HTML
- JSON

## Self Security

- redaction
- scope guard
- `secgraph doctor`
- `secgraph self-audit`

---

# 94. Version 0.2

- RAG instrumentation
- canary documents
- cross-tenant tests
- provenance labels
- attack graph
- baseline/diff
- pytest generation
- dashboard alpha
- SARIF/JUnit

---

# 95. Version 0.3

- MCP discovery
- MCP authorization tests
- tool metadata tests
- runtime policy engine
- shadow mode
- policy simulation
- OpenTelemetry
- signed attack packs

---

# 96. Version 0.4

- adaptive attack planner
- attack memory
- novelty search
- genetic strategy
- model comparison
- guardrail comparison
- cost optimizer

---

# 97. Version 0.5

- PyRIT adapter
- garak adapter
- DeepTeam adapter
- Promptfoo adapter
- ZAP adapter
- Semgrep/CodeQL correlation
- plugin subprocess isolation

---

# 98. Version 1.0 Exit Criteria

Do not call it 1.0 until:

- stable Python API
- stable finding/evidence schema
- stable attack-pack schema
- stable policy schema
- prompt injection module
- RAG module
- MCP module
- API/identity module
- runtime interception
- dashboard/reporting
- regression generation
- self-audit
- signed official packs
- documented threat model
- security review complete
- vulnerability disclosure policy published
- no known unmitigated critical vulnerabilities
- demo vulnerable/hardened benchmark passes
- release SBOM available

---

# 99. Success Metrics

## Adoption

- PyPI downloads
- GitHub stars/forks
- active contributors
- CI installations
- attack packs published
- repeat monthly users

## Engineering

- median time to first scan
- scan reliability
- deterministic-verification ratio
- false positive rate
- test cost
- replay success rate

## Security

- verified findings
- regressions prevented
- percentage of findings with regression tests
- runtime blocks that map to explicit policy
- security/utility improvement after mitigation

---

# 100. Initial Benchmark Application

Create an official demo:

```text
SecGraph Bank / SecGraph Support
```

Architecture:

```text
FastAPI
  ↓
AI support agent
  ↓
RAG
  ↓
Vector store
  ↓
CRM tool
  ↓
Refund tool
  ↓
Email tool
  ↓
Optional MCP server
```

Users:

```text
Tenant A
Tenant B
Admin
```

Seed:

- indirect prompt injection
- cross-tenant RAG retrieval
- unapproved large refund
- sensitive data → external email path
- API object authorization failure
- recursive tool-call cost issue

Provide:

```text
vulnerable mode
hardened mode
```

This one demo can prove the entire value proposition.

---

# 101. Positioning

Recommended short description:

> **SecGraphAI is an open-source AI application security framework that discovers models, agents, RAG, MCP, APIs and identities as one security graph; performs adaptive authorized red teaming; verifies real security effects; enforces runtime policies; and converts findings into regression tests.**

Tagline:

> **Security testing for systems that think and act.**

Developer tagline:

> **pytest for AI security boundaries.**

---

# 102. Name Status

Working name: **SecGraphAI**

As of 2026-09-07:

- an exact public web search for `secgraphai` returned no obvious conflicting package/product result
- the exact PyPI project URL returned 404

This is **not trademark clearance**.

Before public release:

1. reserve the PyPI name
2. reserve the GitHub organization/repository
3. check USPTO
4. check relevant international trademarks if commercial launch is planned
5. check domain availability
6. check npm/crates.io if companion SDKs are planned

---

# 103. Source / Competitive References


Additional standards/intelligence references incorporated in v3.1:

- OWASP Top 10:2025  
  https://owasp.org/Top10/2025/

- OWASP API Security Top 10:2023  
  https://owasp.org/API-Security/editions/2023/en/0x11-t10/

- OWASP Top 10 for LLM Applications 2026  
  https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/

- OWASP Top 10 for Agentic Applications 2026  
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

- CVE Program  
  https://www.cve.org/

- NIST National Vulnerability Database  
  https://nvd.nist.gov/

- CVSS v4.0  
  https://www.first.org/cvss/v4.0/



The following current sources informed the competitive analysis:

- OWASP GenAI LLM Top 10 2026  
  https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/

- OWASP Top 10 for Agentic Applications 2026  
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

- OWASP Agent Control Standard  
  https://genai.owasp.org/resource/agent-control-standard-acs/

- Promptfoo Red Teaming  
  https://www.promptfoo.dev/red-teaming/

- Microsoft PyRIT  
  https://github.com/microsoft/PyRIT

- NVIDIA garak  
  https://github.com/NVIDIA/garak

- DeepTeam  
  https://github.com/confident-ai/deepteam

- Giskard Continuous Red Teaming  
  https://www.giskard.ai/products/continuous-red-teaming

- Check Point / Lakera AI Security documentation  
  https://docs.lakera.ai/guard

---

# 104. Final Product Decision

SecGraphAI should **not** try to win by having the largest library of jailbreak strings.

It should win by doing what developers and security teams ultimately need:

```text
UNDERSTAND THE SYSTEM
        ↓
DEFINE WHAT MUST NEVER HAPPEN
        ↓
TEST THE REAL ATTACK PATH
        ↓
VERIFY THE REAL EFFECT
        ↓
PROTECT THE BOUNDARY
        ↓
GENERATE A REGRESSION TEST
        ↓
CONTINUOUSLY PROVE THE FIX STILL WORKS
```

The highest-priority differentiators are:

1. Security Graph
2. Security Invariants
3. Deterministic Evidence
4. Cross-layer AI/API/MCP/RAG correlation
5. Finding-to-pytest regression
6. Runtime interceptors/aspects
7. Canaries
8. Policy shadow mode and simulation
9. Self-audit
10. Safe plugin/attack-pack trust model
11. Security baselines/diffs
12. Test errors never treated as passes
13. CVE/NVD/CVSS/SSVC/known-exploitation intelligence
14. Reachability-aware vulnerable-component prioritization
15. Versioned OWASP Web/API/LLM/Agentic coverage profiles

These features form a defensible product identity and are more valuable than simply adding another hundred prompt templates.
