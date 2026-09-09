# BYOK and AI model guide

SecGraphAI supports bring your own key (BYOK) for model endpoints that implement the
OpenAI Chat Completions request and response shape. SecGraphAI does not sell model access,
proxy requests through a SecGraphAI service, or require a particular model vendor. The
credential remains in the environment where the scan runs and is sent only to the endpoint
you explicitly configure.

This guide explains when SecGraphAI uses a model, how credentials are handled, which
endpoints are compatible, and how to keep target, attack, judge, and remediation models
separate.

## What BYOK means here

You provide three pieces of configuration:

1. `base_url`: the API base immediately before `/chat/completions`;
2. `model`: the model identifier understood by that endpoint;
3. `api_key_env`: the **name** of an environment variable containing the key.

For example, this configuration:

```text
base_url    = https://provider.example/v1
model       = security-model
api_key_env = SECURITY_MODEL_KEY
```

causes SecGraphAI to make this request:

```http
POST https://provider.example/v1/chat/completions
Authorization: Bearer <value of SECURITY_MODEL_KEY>
Accept: application/json
Content-Type: application/json

{
  "model": "security-model",
  "messages": [{"role": "user", "content": "...authorized test probe..."}]
}
```

The endpoint must return an OpenAI-compatible value at
`choices[0].message.content`. SecGraphAI currently performs non-streaming requests even if
the provider also supports streaming.

The key value is not placed in the model-role manifest or report. Reports identify model
roles by endpoint and model name so a run remains explainable without retaining its secret.

## When AI is and is not used

Supplying a target endpoint does not silently enable every AI role.

| Role | Purpose | When it is called |
| --- | --- | --- |
| Target | The model or AI application being tested | Once for each executed probe |
| Attack | Produces a bounded variation of an authorized probe | During adaptive or genetic attack evolution when configured |
| Judge | Interprets an otherwise unresolved target response | Only when deterministic checks did not already produce a finding for that interaction |
| Remediation | Suggests a reviewable fix for a finding | Only for findings that do not already contain remediation text |

The scanner still performs deterministic checks without an attack, judge, or remediation
model. Canaries, validators, invariants, authorization results, tool events, and state
comparisons should remain the primary evidence whenever possible. A judge produces
probabilistic evidence and should not be treated as an authorization control.

## Fastest CLI setup

The CLI can connect one target model. Put the secret in the current shell, pass the
environment-variable name—not its value—and set explicit cost, request, and time limits.

PowerShell:

```powershell
$env:SECGRAPH_TARGET_KEY = "your-provider-key"

secgraph scan `
  --target https://provider.example/v1 `
  --model your-model-id `
  --api-key-env SECGRAPH_TARGET_KEY `
  --profile owasp-llm-2026 `
  --budget-usd 2 `
  --max-requests 40 `
  --max-duration 120 `
  --output model-report.json `
  --format json
```

Bash, zsh, or another POSIX-style shell:

```bash
export SECGRAPH_TARGET_KEY="your-provider-key"

secgraph scan \
  --target https://provider.example/v1 \
  --model your-model-id \
  --api-key-env SECGRAPH_TARGET_KEY \
  --profile owasp-llm-2026 \
  --budget-usd 2 \
  --max-requests 40 \
  --max-duration 120 \
  --output model-report.json \
  --format json
```

Unset the variable when the session is finished:

```powershell
Remove-Item Env:SECGRAPH_TARGET_KEY
```

```bash
unset SECGRAPH_TARGET_KEY
```

If the key variable is missing or empty, SecGraphAI sends no `Authorization` header. This
is intentional for endpoints that do not require authentication, but a hosted provider will
normally reject the request. A failed request becomes `TEST_ERROR`; it is not evidence that
the target is secure.

## Known-compatible endpoint patterns

SecGraphAI needs a `POST /chat/completions` endpoint, bearer-token authentication when a
key is present, and a response containing `choices[0].message.content`.

| Endpoint type | `--target` example | Credential | Notes |
| --- | --- | --- | --- |
| OpenAI API | `https://api.openai.com/v1` | `OPENAI_API_KEY` | Supply a current Chat Completions model ID available to the account |
| OpenRouter | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | Use an OpenRouter model slug |
| Groq OpenAI-compatible API | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` | Use a model ID currently available to the Groq project |
| Ollama | `http://localhost:11434/v1` | Usually unnecessary | Add `--allow-private`; Ollama accepts the Chat Completions-compatible route |
| Another gateway or hosted provider | Provider's base before `/chat/completions` | Provider key variable | Verify bearer authentication and the response shape before scanning |

Model catalogs change independently of SecGraphAI, so obtain the model identifier from the
provider rather than copying an old identifier from this guide. Relevant provider references
are the [OpenAI Chat API](https://developers.openai.com/api/reference/resources/chat),
[OpenRouter quickstart](https://openrouter.ai/docs/quickstart),
[Groq OpenAI compatibility](https://console.groq.com/docs/openai), and
[Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility).

Native APIs that do not expose this contract are not directly supported by the current
adapter. For example, an endpoint requiring an `api-key` header instead of bearer
authentication, a provider-specific messages route, signed cloud requests, or a response
without `choices[0].message.content` needs an OpenAI-compatible gateway or a future provider
adapter. Do not put credentials into a URL to work around authentication differences; URLs
containing user information are rejected by the scope guard.

## Local Ollama example

No paid API key is required for a local compatible model. Pull the model in Ollama first,
then deliberately allow the loopback target:

```powershell
ollama pull <local-model-name>

secgraph scan `
  --target http://localhost:11434/v1 `
  --model <local-model-name> `
  --allow-private `
  --profile owasp-llm-2026 `
  --max-requests 20 `
  --max-duration 120 `
  --output ollama-report.json `
  --format json
```

`--allow-private` removes the CLI's private-network block for this exact configured target;
it does not create a wildcard network scope. Only use it for a local or private service that
you are authorized to test.

## Four roles with independent keys

The Python API supports a different provider, model, and key for every role. This is useful
when the production model is the target, a cheaper model mutates probes, and independent
models judge ambiguous results. It also prevents accidental credential reuse between trust
boundaries.

```python
from secgraphai import Model, ModelRoles, SecGraph
from secgraphai.security import Scope, ScopeGuard


def guarded_model(*, base_url: str, host: str, model: str, key_env: str) -> Model:
    return Model(
        base_url=base_url,
        model=model,
        api_key_env=key_env,
        timeout=30,
        max_response_bytes=2_000_000,
        scope_guard=ScopeGuard(
            Scope(
                allowed_hosts=frozenset({host}),
                allowed_ports=frozenset({443}),
                max_total_requests=50,
                max_requests_per_second=2,
                max_duration_seconds=120,
            )
        ),
    )


roles = ModelRoles(
    target=guarded_model(
        base_url="https://target-provider.example/v1",
        host="target-provider.example",
        model="target-model",
        key_env="TARGET_MODEL_KEY",
    ),
    attack=guarded_model(
        base_url="https://attack-provider.example/v1",
        host="attack-provider.example",
        model="attack-model",
        key_env="ATTACK_MODEL_KEY",
    ),
    judges=(
        guarded_model(
            base_url="https://judge-one.example/v1",
            host="judge-one.example",
            model="judge-model-a",
            key_env="JUDGE_ONE_KEY",
        ),
        guarded_model(
            base_url="https://judge-two.example/v1",
            host="judge-two.example",
            model="judge-model-b",
            key_env="JUDGE_TWO_KEY",
        ),
    ),
    remediation=guarded_model(
        base_url="https://review-provider.example/v1",
        host="review-provider.example",
        model="remediation-model",
        key_env="REMEDIATION_MODEL_KEY",
    ),
)

scanner = SecGraph(roles=roles, mode="SAFE")
report = await scanner.scan(
    prompts=["Authorized non-destructive security probe"],
)
```

The target receives the security probes. The attack model receives a bounded mutation
instruction only when adaptive evolution needs it. Each judge receives a redacted JSON
document containing the probe and target output and must return JSON with a boolean
`violation` plus a numeric `confidence` from 0 through 1. The remediation model receives a
redacted subset of the finding. Judge ties and unavailable judges do not become passes.

The CLI currently configures only the target role. Use `ModelRoles` for independent attack,
judge, and remediation endpoints.

## Use your existing application instead of giving SecGraphAI a model key

BYOK is optional. If the application already owns its provider credentials, expose an
authorized Python callback and let the callback call the application normally:

```python
from my_application import answer


async def security_target(prompt: str) -> str:
    return await answer(prompt)
```

```bash
secgraph scan \
  --callback security_target:security_target \
  --profile owasp-llm-2026 \
  --max-requests 40 \
  --output callback-report.json \
  --format json
```

In this arrangement SecGraphAI never receives the application's provider key. The callback
is responsible for authentication, tool execution, state capture, and returning useful
`TargetResult` metadata when validators need status, cost, tool, or flow evidence.

## Safe key handling

- Create a dedicated test-project key with the minimum permissions and spend limit needed.
- Use synthetic test data and a staging target; do not expose production secrets to attack
  or judge models.
- Prefer `api_key_env` over the Python `api_key` argument. The direct argument exists for
  controlled embedding but makes accidental source-code or debugger exposure easier.
- Give separate roles separate keys when they cross providers or trust boundaries.
- Do not put keys in command history, configuration files, callback source, target URLs,
  screenshots, reports, issue descriptions, or chat messages.
- In CI, save the value in the CI platform's secret store and map it to the environment only
  for the scan step. Pass the environment-variable name to `--api-key-env`.
- Set provider-side request and spend limits in addition to SecGraphAI's `--budget-usd`,
  `--max-requests`, and `--max-duration` bounds.
- Rotate a key immediately if it appears in a commit, log, report, terminal capture, or chat.
  Deleting it from the latest file does not remove it from history.

Example GitHub Actions step:

```yaml
- name: Run bounded SecGraphAI model scan
  env:
    SECGRAPH_TARGET_KEY: ${{ secrets.SECGRAPH_TARGET_KEY }}
  run: >-
    secgraph scan
    --target https://provider.example/v1
    --model your-model-id
    --api-key-env SECGRAPH_TARGET_KEY
    --profile owasp-llm-2026
    --budget-usd 2
    --max-requests 40
    --max-duration 120
    --output model-report.json
    --format json
```

## What is recorded

The report records interactions, findings, evidence, test definitions, and a model-role
manifest suitable for reproduction. Secret-looking values are redacted before common report
and role-evaluation paths. The key itself is not included in the role manifest.

The target's generated output can still contain sensitive application data that does not
match a known redaction pattern. Treat reports as security artifacts: restrict access, set a
retention period, use `--mask-pii` where appropriate, and inspect evidence before sharing.

## Troubleshooting

- **401 or 403 / `ModelError: model request failed: HTTPStatusError`**: verify that the
  environment variable exists in the same process launching `secgraph`, the key is valid,
  and the provider expects bearer authentication.
- **404**: `--target` must stop immediately before `/chat/completions`. Do not pass the full
  completion URL because SecGraphAI appends that suffix.
- **Invalid OpenAI-compatible response**: verify that the successful JSON response contains
  a string-compatible value at `choices[0].message.content`.
- **Target resolves to a blocked network**: use `--allow-private` only for an authorized
  private or local target. Public providers should not require it.
- **Request budget exhausted**: increase a bound only after confirming authorization,
  provider quota, cost, and target capacity.
- **Judge result becomes `TEST_ERROR`**: the judge must return JSON only, with boolean
  `violation` and numeric `confidence` between 0 and 1.
- **Provider requires custom headers or a native API**: use an OpenAI-compatible gateway or
  application callback; the current adapter cannot configure arbitrary headers.

## Testing without a real key

SecGraphAI's own provider tests use mocked HTTP endpoints. They verify URL construction,
bearer-header behavior, environment-variable lookup, malformed responses, HTTP failures,
response-size limits, model-role separation, judge parsing, and remediation behavior without
making a paid model call. A live smoke test is optional and should use a low-cost dedicated
test key after the mocked suite passes.
