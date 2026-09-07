# SecGraphAI

**Security testing for systems that think and act.**

SecGraphAI is a local-first Python toolkit for describing an AI application's security
graph, declaring security invariants, collecting deterministic evidence, protecting
Python tools at runtime, and producing actionable scan reports. Version 0.1 is an alpha
that establishes the safe, extensible core described in the product requirements.

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
```

Remote targets must be explicitly allow-listed. API keys are referenced through
environment variables and are never serialized into reports.

## What 0.1 includes

- OpenAI-compatible async model client with bounded responses and strict timeouts
- callback targets and a deterministic prompt-injection/canary scanner
- typed findings, evidence, verdicts, and reports (`TEST_ERROR` is never a pass)
- directed security graph and common cross-boundary risk-path detection
- YAML security invariants and deterministic flow evaluation
- runtime tool decorators, authorization/approval aspects, and audit events
- scope guard, redaction, configuration doctor, SQLite result storage
- terminal, JSON, and escaped standalone HTML reports

See [`SecGraphAI_PRD_v3.1_CVE_OWASP.md`](SecGraphAI_PRD_v3.1_CVE_OWASP.md) for the
product roadmap. Only test systems you are authorized to assess.

## Development

```bash
python -m pip install -e '.[test]'
pytest
python -m build
```

## Security

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

