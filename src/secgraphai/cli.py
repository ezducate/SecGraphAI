"""SecGraphAI command-line interface."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
import yaml
from rich.console import Console
from rich.table import Table

from secgraphai.attacks import load_official_pack, load_pack
from secgraphai.config import Mode
from secgraphai.core import Report, Verdict
from secgraphai.dashboard import create_app
from secgraphai.discovery import discover_path, discover_url
from secgraphai.intelligence import (
    CoverageState,
    NVDClient,
    VulnerabilityCache,
    affected,
    generate_cyclonedx,
    generate_spdx,
    installed_components,
    owasp_gate,
    parse_cyclonedx,
    parse_spdx,
    security_gate,
)
from secgraphai.lifecycle import (
    BaselineStore,
    diff_reports,
    execute_replay,
    load_replay,
    regression_bundle,
    save_replay,
)
from secgraphai.multimodal import inspect_media
from secgraphai.plugins import audit_plugins, load_manifest
from secgraphai.policy import PolicyEngine
from secgraphai.reporting import save, to_json
from secgraphai.research import draft_attack_pack
from secgraphai.scanner import ScanBudget, SecGraph
from secgraphai.schemas import write_schemas
from secgraphai.security import Scope, redact
from secgraphai.security import doctor as inspect_config
from secgraphai.self_security import run_self_audit
from secgraphai.storage import Storage
from secgraphai.supply_chain import inspect_artifact, inspect_model_directory
from secgraphai.targets import discover_openapi

app = typer.Typer(help="Security testing for systems that think and act.", no_args_is_help=True)
console = Console()
policy_app = typer.Typer(help="Test and simulate runtime policies.")
baseline_app = typer.Typer(help="Manage security baselines.")
bundle_app = typer.Typer(help="Create and inspect safe replay bundles.")
report_app = typer.Typer(help="Render stored security reports.")
cve_app = typer.Typer(help="Search and synchronize vulnerability intelligence.")
sbom_app = typer.Typer(help="Generate and inspect software bills of materials.")
pack_app = typer.Typer(help="Inspect signed attack packs.")
plugin_app = typer.Typer(help="Audit external plugins.")
research_app = typer.Typer(help="Import security research as disabled draft packs.")
model_app = typer.Typer(help="Inspect model supply-chain artifacts.")
owasp_app = typer.Typer(help="Measure and gate versioned OWASP coverage.")
app.add_typer(policy_app, name="policy")
app.add_typer(baseline_app, name="baseline")
app.add_typer(bundle_app, name="bundle")
app.add_typer(report_app, name="report")
app.add_typer(cve_app, name="cve")
app.add_typer(sbom_app, name="sbom")
app.add_typer(pack_app, name="packs")
app.add_typer(plugin_app, name="plugins")
app.add_typer(research_app, name="research")
app.add_typer(model_app, name="model")
app.add_typer(owasp_app, name="owasp")

_STARTER = {
    "mode": "SAFE",
    "scope": {
        "allowed_hosts": ["localhost"],
        "allowed_ports": [8000],
        "blocked_networks": list(Scope().blocked_networks),
        "max_total_requests": 100,
        "max_requests_per_second": 5,
        "max_duration_seconds": 120,
        "require_stable_dns": True,
    },
    "privacy": {
        "telemetry": False,
        "cloud_upload": False,
        "mask_pii": False,
    },
    "invariants": [
        {
            "id": "NO_SECRET_EXFIL",
            "description": "Secrets must not reach external destinations",
            "source": {"sensitivity": "secret"},
            "destination": {"trust": "external"},
            "expected": "deny",
        }
    ],
}


@app.command("init")
def initialize(
    path: Annotated[Path, typer.Argument()] = Path("secgraph.yaml"),
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    """Create a safe starter configuration."""
    if path.exists() and not force:
        raise typer.BadParameter(f"{path} exists; use --force to replace it")
    path.write_text(yaml.safe_dump(_STARTER, sort_keys=False), encoding="utf-8")
    console.print(f"Created [bold]{path}[/bold]")


@app.command()
def doctor(config: Annotated[Path, typer.Option("--config", "-c")] = Path("secgraph.yaml")) -> None:
    """Detect unsafe SecGraphAI configuration."""
    if not config.exists():
        console.print("[red]Configuration not found. Run `secgraph init`.[/red]")
        raise typer.Exit(2)
    raw = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    problems = inspect_config(raw)
    if problems:
        for problem in problems:
            console.print(f"[yellow]WARN[/yellow] {problem}")
        raise typer.Exit(1)
    console.print("[green]OK[/green] Configuration passed safety checks.")


@app.command()
def discover(
    target: Annotated[str, typer.Argument()] = ".",
    format: Annotated[str, typer.Option("--format")] = "terminal",
    allow_private: Annotated[bool, typer.Option("--allow-private")] = False,
) -> None:
    """Discover local code/manifests or an explicitly scoped OpenAPI URL."""
    inventory = (
        asyncio.run(discover_url(target, allow_private=allow_private))
        if target.startswith(("http://", "https://"))
        else discover_path(target)
    )
    if format == "json":
        typer.echo(
            json.dumps(
                {
                    "counts": inventory.counts(),
                    "components": [item.__dict__ for item in inventory.components],
                    "graph": inventory.to_graph().to_dict(),
                },
                default=list,
            )
        )
        return
    if format != "terminal":
        raise typer.BadParameter("format must be terminal or json")
    table = Table("Component", "Count")
    for key, value in inventory.counts().items():
        table.add_row(key.title(), str(value))
    console.print(table)


def _run_callback_scan(
    callback: str,
    *,
    budget: ScanBudget,
    mode: Mode,
    modules: list[str],
    attack_budget: int,
) -> Report:
    module_name, separator, attribute = callback.partition(":")
    if not separator:
        raise typer.BadParameter("callback must use module:function syntax")
    target_callable = getattr(importlib.import_module(module_name), attribute)
    return asyncio.run(
        SecGraph(budget=budget, mode=mode).scan(
            target_callable,
            modules=modules,
            strategy="adaptive",
            attack_budget=attack_budget,
        )
    )


@app.command()
def scan(
    callback: Annotated[str | None, typer.Option(help="Import path module:function")] = None,
    target_url: Annotated[str | None, typer.Option("--target")] = None,
    model: Annotated[str, typer.Option("--model")] = "target",
    api_key_env: Annotated[str | None, typer.Option("--api-key-env")] = None,
    profile: Annotated[str, typer.Option("--profile")] = "safe",
    budget_usd: Annotated[float | None, typer.Option("--budget-usd")] = None,
    max_requests: Annotated[int, typer.Option("--max-requests")] = 100,
    max_duration: Annotated[float, typer.Option("--max-duration")] = 120,
    allow_private: Annotated[bool, typer.Option("--allow-private")] = False,
    dashboard: Annotated[bool, typer.Option("--dashboard")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    format: Annotated[str, typer.Option("--format")] = "terminal",
    mode: Annotated[Mode, typer.Option("--mode")] = Mode.SAFE,
    mask_pii: Annotated[bool, typer.Option("--mask-pii")] = False,
) -> None:
    """Run bounded security checks against a callback or OpenAI-compatible target."""
    if bool(callback) == bool(target_url):
        raise typer.BadParameter("provide exactly one of --callback or --target")
    budget = ScanBudget(
        max_requests=max_requests,
        max_duration_seconds=max_duration,
        max_cost_usd=budget_usd,
    )
    modules = {
        "safe": ["prompt-injection", "agent"],
        "owasp-web-2025": ["api", "identity"],
        "owasp-api-2023": ["api", "identity"],
        "owasp-llm-2026": ["llm", "prompt-injection", "rag"],
        "owasp-agentic-2026": ["agent", "mcp", "identity"],
        "owasp-full": ["llm", "prompt-injection", "rag", "agent", "mcp", "api", "identity"],
    }
    if profile not in modules:
        raise typer.BadParameter(f"unknown scan profile: {profile}")
    if callback:
        report = _run_callback_scan(
            callback,
            budget=budget,
            mode=mode,
            modules=modules[profile],
            attack_budget=max_requests,
        )
    else:
        parsed = urlsplit(target_url or "")
        target_config: dict[str, object] = {
            "base_url": target_url,
            "model": model,
            "api_key_env": api_key_env,
            "scope": {
                "allowed_hosts": [parsed.hostname],
                "allowed_ports": [parsed.port or (443 if parsed.scheme == "https" else 80)],
                "blocked_networks": [] if allow_private else list(Scope().blocked_networks),
            },
        }
        report = asyncio.run(
            SecGraph(target=target_config, budget=budget, mode=mode).scan(
                modules=modules[profile], strategy="adaptive", attack_budget=max_requests
            )
        )
    if dashboard:
        Storage().save(report)
    if output:
        save(report, output, None if format == "terminal" else format, mask_pii=mask_pii)
        console.print(f"Saved {output}")
    elif format == "json":
        typer.echo(to_json(report, mask_pii=mask_pii))
    else:
        console.print(redact(report.summary()))
    if report.errors:
        raise typer.Exit(2)


@app.command("self-audit")
def self_audit(
    deep: Annotated[bool, typer.Option("--deep")] = False,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    database: Annotated[Path | None, typer.Option("--database")] = None,
) -> None:
    """Run built-in installation safety checks."""
    raw = yaml.safe_load(config.read_text(encoding="utf-8")) if config and config.exists() else None
    result = run_self_audit(config=raw, config_path=config, database=database, deep=deep)
    typer.echo(json.dumps(result.as_dict(), sort_keys=True, default=str))
    if not result.passed:
        raise typer.Exit(1)


@app.command("openapi")
def openapi(path: Annotated[Path, typer.Argument()]) -> None:
    """Discover operations from a local OpenAPI JSON/YAML document."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    typer.echo(
        json.dumps([endpoint.__dict__ for endpoint in discover_openapi(document)], default=list)
    )


@app.command("diff")
def diff(old: Annotated[Path, typer.Argument()], new: Annotated[Path, typer.Argument()]) -> None:
    """Compare two report baselines using stable finding fingerprints."""
    result = diff_reports(
        Report.model_validate_json(old.read_text()), Report.model_validate_json(new.read_text())
    )
    typer.echo(json.dumps({key: [item.id for item in value] for key, value in result.items()}))


@app.command("test")
def test_command(
    callback: Annotated[str, typer.Option(help="Import path module:function")],
    baseline: Annotated[str | None, typer.Option("--baseline")] = None,
    root: Annotated[Path, typer.Option("--root")] = Path(".secgraph/baselines"),
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fail_on_regression: Annotated[bool, typer.Option("--fail-on-regression")] = False,
) -> None:
    """Run deterministic callback tests and optionally enforce a stored baseline."""
    report = _run_callback_scan(
        callback,
        budget=ScanBudget(max_requests=100, max_duration_seconds=120),
        mode=Mode.SAFE,
        modules=["prompt-injection", "agent"],
        attack_budget=100,
    )
    regressions: list[str] = []
    if baseline:
        regressions = [item.id for item in diff_reports(BaselineStore(root).load(baseline), report)["new"]]
    if output:
        save(report, output, "json")
    typer.echo(
        json.dumps(
            {"scan_id": report.scan_id, "summary": report.summary(), "regressions": regressions},
            sort_keys=True,
        )
    )
    if report.errors:
        raise typer.Exit(2)
    if fail_on_regression and regressions:
        raise typer.Exit(1)


@app.command("compare")
def compare(old: Annotated[Path, typer.Argument()], new: Annotated[Path, typer.Argument()]) -> None:
    """Compare application, model, guardrail, or policy scan results."""
    diff(old, new)


@app.command("replay")
def replay(
    path: Annotated[Path, typer.Argument()],
    callback: Annotated[
        str | None, typer.Option(help="Import path module:function used to re-run cases")
    ] = None,
    fail_on_violation: Annotated[bool, typer.Option("--fail-on-violation")] = False,
) -> None:
    """Validate a replay bundle and optionally re-run its cases."""
    report, inputs = load_replay(path)
    if callback:
        module_name, separator, attribute = callback.partition(":")
        if not separator:
            raise typer.BadParameter("callback must use module:function syntax")
        target_callable = getattr(importlib.import_module(module_name), attribute)
        result = asyncio.run(execute_replay(report, inputs, target_callable))
        typer.echo(result.model_dump_json())
        summary = result.summary()
        if summary[Verdict.TEST_ERROR.value]:
            raise typer.Exit(2)
        if fail_on_violation and summary[Verdict.VERIFIED_VIOLATION.value]:
            raise typer.Exit(1)
        return
    typer.echo(
        json.dumps(
            {"scan_id": report.scan_id, "summary": report.summary(), "inputs": redact(inputs)},
            sort_keys=True,
        )
    )


@app.command("generate-test")
def generate_test(
    report_path: Annotated[Path, typer.Argument()],
    finding_id: Annotated[str, typer.Argument()],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate pytest, YAML, and CI regression artifacts for a finding."""
    report = Report.model_validate_json(report_path.read_text(encoding="utf-8"))
    finding = next((item for item in report.findings if item.id == finding_id), None)
    if finding is None:
        raise typer.BadParameter("finding not present in report")
    bundle = regression_bundle(finding)
    if output:
        output.write_text(bundle["pytest"], encoding="utf-8")
    else:
        typer.echo(json.dumps(bundle, indent=2))


@app.command("serve")
def serve(
    database: Annotated[Path, typer.Option("--database")] = Path("secgraph.db"),
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8777,
    token_env: Annotated[str, typer.Option("--token-env")] = "SECGRAPH_DASHBOARD_TOKEN",  # noqa: S107
    retention_days: Annotated[int | None, typer.Option("--retention-days")] = None,
    encryption_key_env: Annotated[
        str | None, typer.Option("--encryption-key-env")
    ] = None,
    mask_pii: Annotated[bool, typer.Option("--mask-pii")] = False,
) -> None:  # nosec B107
    """Start the authenticated local dashboard API."""
    token = os.environ.get(token_env)
    if not token:
        raise typer.BadParameter(f"set {token_env} to a strong dashboard token")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        console.print("Warning: remote dashboard binding requires trusted TLS termination.")
    import uvicorn

    uvicorn.run(
        create_app(
            database=database,
            token=token,
            bind_host=host,
            retention_days=retention_days,
            encryption_key_env=encryption_key_env,
            mask_pii=mask_pii,
            allow_remote=host not in {"127.0.0.1", "localhost", "::1"},
        ),
        host=host,
        port=port,
    )


@app.command("dev")
def dev(
    database: Annotated[Path, typer.Option("--database")] = Path("secgraph.db"),
    port: Annotated[int, typer.Option("--port")] = 8777,
) -> None:
    """Start the local dashboard using the configured environment token."""
    serve(
        database=database,
        host="127.0.0.1",
        port=port,
        token_env="SECGRAPH_DASHBOARD_TOKEN",  # noqa: S106  # nosec B106
        retention_days=None,
        encryption_key_env=None,
        mask_pii=False,
    )


@app.command("engines")
def engines() -> None:
    from secgraphai.adapters import SUPPORTED_ENGINES

    typer.echo("\n".join(sorted(SUPPORTED_ENGINES)))


@policy_app.command("test")
def policy_test(
    path: Annotated[Path, typer.Argument()], event: Annotated[str, typer.Option("--event")] = "{}"
) -> None:
    decision = PolicyEngine.from_yaml(path).evaluate(json.loads(event))
    typer.echo(json.dumps(decision.__dict__, default=str, sort_keys=True))


@policy_app.command("simulate")
def policy_simulate(
    path: Annotated[Path, typer.Argument()],
    events: Annotated[Path | None, typer.Argument()] = None,
    against: Annotated[str | None, typer.Option("--against")] = None,
    database: Annotated[Path, typer.Option("--database")] = Path("secgraph.db"),
) -> None:
    if bool(events) == bool(against):
        raise typer.BadParameter("provide exactly one events file or --against last-N-days")
    if events:
        raw = json.loads(events.read_text(encoding="utf-8"))
    else:
        match = re.fullmatch(r"last-(\d+)-days", against or "")
        if not match or int(match.group(1)) < 1:
            raise typer.BadParameter("--against must use last-N-days with a positive N")
        cutoff = datetime.now(UTC) - timedelta(days=int(match.group(1)))
        raw = [
            interaction.model_dump(mode="json")
            for report in Storage(database).list(limit=1000)
            if report.finished_at >= cutoff
            for interaction in report.interactions
        ]
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise typer.BadParameter("policy simulation events must be a JSON array of objects")
    summary = PolicyEngine.from_yaml(path).summarize(raw)
    typer.echo(json.dumps(summary.__dict__, default=str, sort_keys=True))


@baseline_app.command("create")
def baseline_create(
    name: Annotated[str, typer.Argument()],
    report: Annotated[Path, typer.Argument()],
    root: Annotated[Path, typer.Option("--root")] = Path(".secgraph/baselines"),
) -> None:
    target = BaselineStore(root).save(
        name, Report.model_validate_json(report.read_text(encoding="utf-8"))
    )
    typer.echo(str(target))


@baseline_app.command("compare")
def baseline_compare(
    name: Annotated[str, typer.Argument()],
    report: Annotated[Path, typer.Argument()],
    root: Annotated[Path, typer.Option("--root")] = Path(".secgraph/baselines"),
) -> None:
    result = diff_reports(
        BaselineStore(root).load(name),
        Report.model_validate_json(report.read_text(encoding="utf-8")),
    )
    typer.echo(json.dumps({key: [item.id for item in value] for key, value in result.items()}))


@bundle_app.command("create")
def bundle_create(
    report: Annotated[Path, typer.Argument()], output: Annotated[Path, typer.Argument()]
) -> None:
    save_replay(Report.model_validate_json(report.read_text(encoding="utf-8")), output, {})


@bundle_app.command("replay")
def bundle_replay(
    path: Annotated[Path, typer.Argument()],
    callback: Annotated[str | None, typer.Option()] = None,
    fail_on_violation: Annotated[bool, typer.Option("--fail-on-violation")] = False,
) -> None:
    replay(path, callback=callback, fail_on_violation=fail_on_violation)


@report_app.command("render")
def report_render(
    report: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Argument()],
    format: Annotated[str | None, typer.Option("--format")] = None,
    mask_pii: Annotated[bool, typer.Option("--mask-pii")] = False,
) -> None:
    save(
        Report.model_validate_json(report.read_text(encoding="utf-8")),
        output,
        format,
        mask_pii=mask_pii,
    )


@cve_app.command("search")
def cve_search(
    query: Annotated[str, typer.Argument()],
    cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json"),
) -> None:
    typer.echo(
        json.dumps(
            [item.__dict__ for item in VulnerabilityCache(cache).search(query)], default=list
        )
    )


@cve_app.command("show")
def cve_show(
    identifier: Annotated[str, typer.Argument()],
    cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json"),
) -> None:
    matches = VulnerabilityCache(cache).search(identifier)
    typer.echo(
        json.dumps(
            next((item.__dict__ for item in matches if item.id == identifier), {}), default=list
        )
    )


@cve_app.command("sync")
def cve_sync(
    query: Annotated[str, typer.Option("--query")] = "Python",
    cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json"),
) -> None:
    stored = VulnerabilityCache(cache)
    previous = stored.metadata()
    next_index = previous.get("next_start_index") if previous.get("query") == query else None
    start_index = next_index if isinstance(next_index, int) and next_index >= 0 else 0
    client = NVDClient()
    synchronized_at = previous.get("synchronized_at")
    if previous.get("query") == query and start_index == 0 and isinstance(synchronized_at, str):
        prior_etag = previous.get("etag")
        prior_modified = previous.get("last_modified")
        values = asyncio.run(
            client.search(
                query,
                start_index=0,
                etag=prior_etag if isinstance(prior_etag, str) else None,
                last_modified=prior_modified if isinstance(prior_modified, str) else None,
                last_mod_start_date=synchronized_at,
                last_mod_end_date=datetime.now(UTC).isoformat(),
            )
        )
    else:
        values = asyncio.run(client.search(query, start_index=start_index))
    merged = stored.merge(values, metadata={"query": query, **client.response_metadata})
    typer.echo(
        json.dumps(
            {
                "fetched": merged,
                "cached": len(stored.search("")),
                "resumed_from": start_index,
                "metadata": stored.metadata(),
            },
            sort_keys=True,
        )
    )


@cve_app.command("affected")
def cve_affected(
    component: Annotated[str, typer.Argument()],
    version: Annotated[str, typer.Argument()],
    cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json"),
) -> None:
    from secgraphai.intelligence import Component

    matches = [
        item.id
        for item in VulnerabilityCache(cache).search(component)
        if affected(Component(component, version), item) is not False
    ]
    typer.echo(json.dumps(matches))


@cve_app.command("reachable")
def cve_reachable(cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json")) -> None:
    matches = [item.__dict__ for item in VulnerabilityCache(cache).search("") if item.reachable]
    typer.echo(json.dumps(matches, default=list))


@cve_app.command("status")
def cve_status(cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json")) -> None:
    """Show the offline cache schema, source validators, and data age."""
    stored = VulnerabilityCache(cache)
    typer.echo(
        json.dumps(
            {**stored.metadata(), "age_seconds": stored.age_seconds()},
            sort_keys=True,
        )
    )


def _owasp_results(report: Report) -> list[tuple[str, CoverageState]]:
    states = {
        Verdict.VERIFIED_VIOLATION: CoverageState.VERIFIED_FINDING,
        Verdict.LIKELY_VIOLATION: CoverageState.PARTIAL,
        Verdict.BLOCKED_BY_CONTROL: CoverageState.VERIFIED_CONTROL,
        Verdict.TEST_ERROR: CoverageState.TEST_ERROR,
        Verdict.PASS: CoverageState.TESTED,
        Verdict.INCONCLUSIVE: CoverageState.PARTIAL,
        Verdict.OUT_OF_SCOPE: CoverageState.NOT_APPLICABLE,
    }
    return [
        (category.split(":", 1)[0], states[finding.verdict])
        for finding in report.findings
        for categories in finding.mappings.values()
        for category in categories
    ]


@owasp_app.command("coverage")
def owasp_coverage(
    report: Annotated[Path, typer.Argument()],
    profile: Annotated[str, typer.Option("--profile")] = "llm-2026",
) -> None:
    value = Report.model_validate_json(report.read_text(encoding="utf-8"))
    _, matrix = owasp_gate(profile, _owasp_results(value), minimum_percent=0)
    typer.echo(json.dumps(matrix, indent=2))


@owasp_app.command("gate")
def owasp_regression_gate(
    report: Annotated[Path, typer.Argument()],
    profile: Annotated[str, typer.Option("--profile")] = "llm-2026",
    minimum: Annotated[float, typer.Option("--minimum-percent")] = 100,
) -> None:
    value = Report.model_validate_json(report.read_text(encoding="utf-8"))
    try:
        passed, matrix = owasp_gate(profile, _owasp_results(value), minimum_percent=minimum)
    except KeyError as exc:
        raise typer.BadParameter("unknown OWASP profile") from exc
    typer.echo(json.dumps(matrix, indent=2))
    if not passed:
        raise typer.Exit(1)


@sbom_app.command("generate")
def sbom_generate(
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("bom.json"),
    format: Annotated[str, typer.Option("--format")] = "cyclonedx",
) -> None:
    if format not in {"cyclonedx", "spdx"}:
        raise typer.BadParameter("format must be cyclonedx or spdx")
    generator = generate_spdx if format == "spdx" else generate_cyclonedx
    output.write_text(json.dumps(generator(installed_components()), indent=2), encoding="utf-8")


@sbom_app.command("scan")
def sbom_scan(
    path: Annotated[Path, typer.Argument()],
    cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json"),
) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    components = parse_spdx(document) if document.get("spdxVersion") else parse_cyclonedx(document)
    vulnerabilities = [
        item
        for component in components
        for item in VulnerabilityCache(cache).search(component.name)
        if affected(component, item) is not False
    ]
    passed, reasons = security_gate(vulnerabilities)
    typer.echo(json.dumps({"passed": passed, "reasons": reasons}))
    if not passed:
        raise typer.Exit(1)


@pack_app.command("verify")
def pack_verify(
    path: Annotated[Path, typer.Argument()],
    allow_unverified: Annotated[bool, typer.Option("--allow-unverified")] = False,
    public_key: Annotated[Path | None, typer.Option("--public-key")] = None,
) -> None:
    key = base64.b64decode(public_key.read_text().strip()) if public_key else None
    pack = load_pack(path, allow_unverified=allow_unverified, public_key=key)
    typer.echo(json.dumps({"id": pack.id, "version": pack.version, "trust": pack.trust.value}))


@pack_app.command("official")
def pack_official(name: Annotated[str, typer.Argument()] = "prompt_injection_core") -> None:
    pack = load_official_pack(name)
    typer.echo(
        json.dumps(
            {
                "id": pack.id,
                "version": pack.version,
                "trust": pack.trust.value,
                "attacks": len(pack.attacks),
            }
        )
    )


@plugin_app.command("audit")
def plugin_audit(paths: Annotated[list[Path], typer.Argument()]) -> None:
    problems = audit_plugins(load_manifest(path) for path in paths)
    typer.echo(json.dumps(problems))
    if problems:
        raise typer.Exit(1)


@research_app.command("import")
def research_import(
    path: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("draft-pack.json"),
) -> None:
    pack, review = draft_attack_pack(path)
    output.write_text(
        json.dumps({**pack.payload(), "trust": pack.trust.value, "review": review}, indent=2),
        encoding="utf-8",
    )
    typer.echo(f"Created disabled draft {output}; human review is required")


@model_app.command("inspect")
def model_inspect(path: Annotated[Path, typer.Argument()]) -> None:
    values = inspect_model_directory(path) if path.is_dir() else [inspect_artifact(path)]
    typer.echo(json.dumps([item.__dict__ for item in values], indent=2, default=str))


@app.command("media")
def media_inspect(path: Annotated[Path, typer.Argument()]) -> None:
    """Inspect a bounded image, document, PDF, audio transcript, or web artifact."""
    typer.echo(json.dumps(inspect_media(path).__dict__, indent=2))


@app.command("schemas")
def schemas(output: Annotated[Path, typer.Option("--output", "-o")] = Path("schemas")) -> None:
    """Export the stable public report, attack-pack, and policy schemas."""
    typer.echo("\n".join(str(path) for path in write_schemas(output)))


if __name__ == "__main__":
    app()
