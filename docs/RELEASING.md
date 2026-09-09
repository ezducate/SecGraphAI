# Release runbook

SecGraphAI publishes from GitHub Actions to PyPI with OpenID Connect (OIDC) trusted
publishing. Maintainers do not create or store a PyPI API token in GitHub.

## One-time configuration

1. Create a GitHub environment named `pypi` in `ezducate/SecGraphAI`.
2. In PyPI, add a trusted publisher for project `secgraphai` with owner `ezducate`,
   repository `SecGraphAI`, workflow `release.yml`, and environment `pypi`. For the first
   publication, create it as a pending publisher before publishing the GitHub release.
3. Keep the release workflow's permissions limited to `contents: read`, `id-token: write`,
   and `attestations: write`.

## Publish a release candidate

1. Confirm the version in `pyproject.toml` and the package version recorded in generated
   manifests agree. The tag must be `v` followed by that version, such as `v1.0.0rc3`.
2. Run the full test, lint, type, dependency-audit, security, build, and wheel-install checks.
3. Confirm CI and Deep security pass on the exact commit being released.
4. Create a GitHub prerelease from that commit. Publishing the GitHub release triggers
   `.github/workflows/release.yml`; do not upload with a developer API token.
5. Wait for the workflow to finish. It rebuilds and tests the tagged source, audits the
   environment, generates a CycloneDX SBOM, attests every distribution, and publishes to
   PyPI from the protected `pypi` environment.

PyPI files are immutable. If publication fails after a version has uploaded, fix the cause,
increment the version, and publish a new tag rather than trying to replace an artifact.

## Verify publication

Use a clean virtual environment and the public index, not the repository checkout:

```bash
python -m pip install --index-url https://pypi.org/simple "secgraphai==1.0.0rc3"
python -c "from importlib.metadata import version; print(version('secgraphai'))"
secgraph --help
secgraph doctor
```

Also verify the GitHub release shows build-provenance attestations, download the
`release-sbom` artifact from the workflow, and confirm the PyPI project links point to the
canonical repository and security-advisory page.

## Stable 1.0 promotion

Do not retag the release candidate. Complete the independent security review, update the
version to `1.0.0`, rerun all gates, and create a new `v1.0.0` GitHub release. Update the
installation documentation to remove prerelease-only guidance when the stable artifact is
available.
