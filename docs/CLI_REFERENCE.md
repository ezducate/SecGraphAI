# SecGraphAI CLI reference

This reference covers every command shipped in SecGraphAI `1.0.0rc3`. Run
`secgraph COMMAND --help` for the parser's authoritative syntax. Exit code `0` means the
command completed successfully; individual security gates use `1` for a failed gate and
scans/replays use `2` when a test could not execute reliably.

## Global options

`secgraph --help` lists commands. `--install-completion` installs shell completion and
`--show-completion` prints the completion script. There is no implicit target: commands
that can contact a service require an explicit URL, callback, or configured dashboard target.

## Setup, configuration, and self-inspection

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph init [PATH]` | `PATH` defaults to `secgraph.yaml`; `--force` permits replacement | Create a conservative starter configuration before onboarding a repository |
| `secgraph doctor` | `--config`, `-c` (default `secgraph.yaml`) | Reject unsafe scope, secrets, and configuration before a scan |
| `secgraph self-audit` | `--deep`, `--config`/`-c`, `--database` | Check the installation, configuration, files, dependencies, and optional database; `--deep` runs extended checks |
| `secgraph schemas` | `--output`, `-o` (default `schemas`) | Export stable report, attack-pack, and policy JSON schemas for integrations |
| `secgraph engines` | No options | List normalized external-engine formats understood by adapters |

```bash
secgraph init security/secgraph.yaml
secgraph doctor --config security/secgraph.yaml
secgraph self-audit --deep --config security/secgraph.yaml --database secgraph.db
secgraph schemas --output generated-schemas
```

## Architecture and interface discovery

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph discover [TARGET]` | Target defaults to `.`; `--format terminal\|json`; `--allow-private` | Inventory local source/manifests without importing them, or fetch one explicitly scoped OpenAPI URL |
| `secgraph openapi PATH` | Local JSON or YAML document | List discovered API operations without sending requests |

```bash
secgraph discover ./services --format json > inventory.json
secgraph discover https://staging.example.test/openapi.json --format json
secgraph openapi ./contracts/openapi.yaml > operations.json
```

`--allow-private` intentionally permits a supplied private or loopback discovery URL. It is
for a controlled lab, not a general production-scope bypass.

## Scanning callbacks and model endpoints

`secgraph scan` requires exactly one of `--callback MODULE:FUNCTION` or `--target URL`.
The target form supports BYOK for bearer-authenticated OpenAI Chat Completions-compatible
endpoints. See the [BYOK and AI model guide](BYOK_AND_MODELS.md) for key handling, supported
endpoint patterns, role separation, local models, CI configuration, and limitations.

| Option | Default | Meaning |
| --- | --- | --- |
| `--callback MODULE:FUNCTION` | None | Importable synchronous or asynchronous application boundary |
| `--target URL` | None | OpenAI-compatible API base before `/chat/completions` |
| `--model NAME` | `target` | Model identifier sent to the endpoint |
| `--api-key-env NAME` | None | Environment-variable name containing the credential; the value is not stored |
| `--profile NAME` | `safe` | `safe`, `owasp-web-2025`, `owasp-api-2023`, `owasp-llm-2026`, `owasp-agentic-2026`, or `owasp-full` |
| `--mode MODE` | `SAFE` | `PASSIVE`, `SAFE`, `LAB`, or `CUSTOM`; active scanning is rejected in `PASSIVE` |
| `--budget-usd NUMBER` | Unlimited | Stop before target-reported cost would exceed the limit |
| `--max-requests INTEGER` | `100` | Maximum target requests and attack-planning budget |
| `--max-duration SECONDS` | `120` | Wall-clock scan limit |
| `--allow-private` | False | Permit the exact private/loopback target for an authorized lab |
| `--dashboard` | False | Persist the completed report in the default SQLite store |
| `--output`, `-o PATH` | None | Save a report instead of only printing a summary |
| `--format NAME` | `terminal` | Output renderer; common values are `json`, `jsonl`, `html`, `markdown`, `csv`, `sarif`, `junit`, and optional `pdf` |
| `--mask-pii` | False | Mask common email and phone data in rendered evidence |

```bash
secgraph scan --callback security_target:answer --profile owasp-full \
  --mode SAFE --max-requests 40 --max-duration 120 \
  --output report.json --format json --mask-pii

secgraph scan --target https://models.example.test/v1 --model assistant-v2 \
  --api-key-env STAGING_MODEL_TOKEN --profile owasp-llm-2026 \
  --budget-usd 2 --max-requests 40 --output model-report.json --format json
```

## Deterministic tests, comparison, and reproduction

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph test` | Required `--callback`; optional `--baseline`, `--root`, `--output`/`-o`, `--fail-on-regression` | Run the deterministic callback suite and fail only for findings absent from an approved baseline |
| `secgraph diff OLD NEW` | Two report paths | Compare stable finding fingerprints and print new/resolved/unchanged IDs |
| `secgraph compare OLD NEW` | Two report paths | Compare application, model, guardrail, or policy scan results; currently aliases report diffing |
| `secgraph replay PATH` | Optional `--callback`; `--fail-on-violation` | Validate a tamper-checked replay bundle, optionally re-execute its data-only cases |
| `secgraph generate-test REPORT FINDING_ID` | Optional `--output`, `-o` | Generate pytest, YAML, and CI regression material for one finding |
| `secgraph bundle create REPORT OUTPUT` | Two paths | Package a report and reproduction inputs into a safe replay archive |
| `secgraph bundle replay PATH` | Optional `--callback`; `--fail-on-violation` | Equivalent replay entry point within the bundle command group |

```bash
secgraph test --callback security_target:answer --baseline production \
  --root .secgraph/baselines --fail-on-regression --output candidate.json
secgraph diff production.json candidate.json
secgraph bundle create candidate.json candidate.secgraph
secgraph replay candidate.secgraph --callback security_target:answer --fail-on-violation
secgraph generate-test candidate.json FINDING_ID --output tests/test_security_regression.py
```

## Baselines

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph baseline create NAME REPORT` | `--root` defaults to `.secgraph/baselines` | Save an approved report under a stable name |
| `secgraph baseline compare NAME REPORT` | Same `--root` | Identify findings introduced or resolved relative to the approved report |

Do not update a baseline merely to make CI pass. Review evidence, remediation, accepted
risk, and test errors before replacing it.

## Runtime policy

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph policy test PATH` | `--event JSON` defaults to `{}` | Evaluate one representative tool/agent event against a YAML policy and inspect the explanation |
| `secgraph policy simulate PATH [EVENTS]` | Exactly one JSON event-array path or `--against last-N-days`; optional `--database` | Measure what a policy would block or require approval for before enforcement |

```bash
secgraph policy test policy.yaml --event '{"kind":"tool","permission":"billing.refund","risk":"high"}'
secgraph policy simulate policy.yaml captured-events.json
secgraph policy simulate policy.yaml --against last-14-days --database secgraph.db
```

Use `mode: shadow` in the policy during rollout. Simulation is evidence for review, not an
automatic authorization to enable a blocking rule.

## Reporting and dashboard

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph report render REPORT OUTPUT` | Optional `--format`; `--mask-pii` | Convert a stored report for humans, CI, or security tooling |
| `secgraph serve` | `--database`, `--host`, `--port`, `--token-env`, `--retention-days`, `--encryption-key-env`, `--mask-pii` | Run the authenticated dashboard/API; default host `127.0.0.1`, port `8777`, token variable `SECGRAPH_DASHBOARD_TOKEN` |
| `secgraph dev` | `--database`, `--port` | Start the loopback dashboard with the default token variable and development defaults |

```bash
secgraph report render report.json report.html --mask-pii
secgraph report render report.json report.sarif --format sarif
export SECGRAPH_DASHBOARD_TOKEN="replace-with-a-long-random-value"
secgraph serve --database secgraph.db --host 127.0.0.1 --port 8777 \
  --retention-days 30 --encryption-key-env SECGRAPH_STORAGE_KEY --mask-pii
```

A non-loopback bind requires a strong bearer token and trusted TLS termination. Keep the
storage encryption key outside the database and back it up separately.

## OWASP coverage

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph owasp coverage REPORT` | `--profile` defaults to `llm-2026` | Print the tested/control/finding/error matrix for a versioned profile |
| `secgraph owasp gate REPORT` | `--profile`; `--minimum-percent` defaults to `100` | Fail CI when measured coverage is below the threshold |

```bash
secgraph owasp coverage report.json --profile llm-2026
secgraph owasp gate report.json --profile llm-2026 --minimum-percent 90
```

Coverage says what the run exercised; it is not a certification of the target.

## SBOM and vulnerability intelligence

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph sbom generate` | `--output`/`-o` defaults to `bom.json`; `--format cyclonedx\|spdx` | Inventory installed Python distributions |
| `secgraph sbom scan PATH` | `--cache` defaults to `cve-cache.json` | Match an SBOM against the offline cache and apply the vulnerability gate |
| `secgraph cve sync` | `--query` defaults to `Python`; `--cache` | Fetch or resume a bounded NVD query and retain validators/delta metadata |
| `secgraph cve status` | `--cache` | Show cache schema, age, paging, query, and HTTP validators |
| `secgraph cve search QUERY` | `--cache` | Search cached identifiers, packages, descriptions, and metadata |
| `secgraph cve show ID` | `--cache` | Print one exact cached vulnerability record |
| `secgraph cve affected COMPONENT VERSION` | `--cache` | List records that may affect a concrete component version |
| `secgraph cve reachable` | `--cache` | List cached findings marked reachable by imported intelligence |

```bash
secgraph sbom generate --output bom.json --format cyclonedx
secgraph cve sync --query urllib3 --cache cve-cache.json
secgraph cve status --cache cve-cache.json
secgraph cve affected urllib3 2.2.1 --cache cve-cache.json
secgraph sbom scan bom.json --cache cve-cache.json
```

Package and version matching can be inconclusive. Reachability, CVSS, CWE, and known-
exploited status prioritize review; they do not prove exploitability in your application.

## Attack packs, plugins, and research import

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph packs official [NAME]` | Defaults to `prompt_injection_core` | Inspect a bundled integrity-checked pack |
| `secgraph packs verify PATH` | `--public-key`; `--allow-unverified` | Verify signature, engine compatibility, schema, and trust state |
| `secgraph plugins audit PATH...` | One or more manifests | Reject unsafe permissions, environment exposure, mutable container images, and invalid limits before execution |
| `secgraph research import PATH` | `--output`, `-o` defaults to `draft-pack.json` | Convert a paper into a disabled draft pack requiring human review |

```bash
secgraph packs official prompt_injection_core
secgraph packs verify reviewed-pack.yaml --public-key reviewer.pub
secgraph plugins audit adapters/promptfoo.json adapters/garak.json
secgraph research import paper.pdf --output review/draft-pack.json
```

`--allow-unverified` is only for a reviewed local draft. Importing research never enables or
runs generated attacks automatically.

## Model and multimodal artifact inspection

| Command | Arguments and options | Practical use |
| --- | --- | --- |
| `secgraph model inspect PATH` | File or directory | Inspect model artifacts for format, size, hashes, unsafe serialization signals, and supply-chain metadata |
| `secgraph media PATH` | Image, document, PDF, audio transcript, or saved web artifact | Perform bounded metadata/content inspection without executing embedded content |

```bash
secgraph model inspect ./model-release
secgraph media ./evidence/suspicious-document.pdf
```

Treat any artifact as untrusted input and perform deeper malware or sandbox analysis with
specialist tooling when required.

## Choosing the right entry point

| If you need to… | Start with… |
| --- | --- |
| Map an unfamiliar repository safely | `discover`, then review graph risks |
| Check one model-backed application flow | `scan --callback` |
| Check a hosted model API directly | `scan --target` with exact budgets and scope |
| Enforce permission at the moment a tool runs | `@secgraph.tool` and `SecurityContext` |
| Observe an existing framework without decorating every function | Instrumentation helpers |
| Prove a fix stays fixed | Baseline, replay bundle, generated test, and OWASP gate |
| Review results with a team | Render HTML/SARIF/JUnit or run the local dashboard |
| Triage dependency exposure offline | SBOM plus CVE cache commands |
| Extend SecGraphAI safely | Signed packs and permission-gated plugin manifests |
