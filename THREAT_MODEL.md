# SecGraphAI threat model

SecGraphAI treats target responses, OpenAPI and MCP metadata, vulnerability feeds,
attack packs, plugins, replay archives, and report fields as untrusted input.

## Trust boundaries

- Active network access crosses the configured target scope and is denied unless the
  scheme, host, port, resolved address, action, rate, duration, and request budget pass.
- Target credentials are read from named environment variables and are not serialized.
- Third-party engines run through an allow-listed executable in a temporary working
  directory, with a minimal environment, bounded input/output, timeout, and schema check.
- Remote/community attack packs are disabled unless trusted explicitly; official and
  organization packs require Ed25519 verification.
- Replay archives have a fixed file set, expanded-size limit, path validation, and hashes.
- Dashboard data routes require a bearer token; localhost binding, CSP, frame denial,
  MIME protection, no-store caching, body limits, and rate limits are enforced.

## Abuse cases

Hostile target output is escaped and redacted before portable reports. DNS targets are
resolved and checked against blocked networks for every request. Redirect following is
disabled. Test errors remain distinct from passes. Scanner and runtime budgets limit
resource amplification. Policy decisions include the matching rule and explanation.

## Residual risks

Subprocess isolation is not an operating-system sandbox. Container isolation and a
third-party penetration test are recommended for untrusted plugins and enterprise use.
Users remain responsible for authorization to test targets and for protecting local
environment variables and dashboard tokens.
