"""SecGraphAI command-line interface."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
import yaml
from rich.console import Console
from rich.table import Table

from secgraphai.attacks import load_pack
from secgraphai.core import Report
from secgraphai.dashboard import create_app
from secgraphai.discovery import discover_path, discover_url
from secgraphai.intelligence import (
    NVDClient,
    VulnerabilityCache,
    affected,
    generate_cyclonedx,
    generate_spdx,
    installed_components,
    parse_cyclonedx,
    parse_spdx,
    security_gate,
)
from secgraphai.lifecycle import (
    BaselineStore,
    diff_reports,
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

_STARTER = {
    "mode": "SAFE",
    "scope": {"allowed_hosts": ["localhost"], "allowed_ports": [8000], "max_total_requests": 100},
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
        module_name, separator, attribute = callback.partition(":")
        if not separator:
            raise typer.BadParameter("callback must use module:function syntax")
        target_callable = getattr(importlib.import_module(module_name), attribute)
        report = asyncio.run(
            SecGraph(budget=budget).scan(
                target_callable,
                modules=modules[profile],
                strategy="adaptive",
                attack_budget=max_requests,
            )
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
            SecGraph(target=target_config, budget=budget).scan(
                modules=modules[profile], strategy="adaptive", attack_budget=max_requests
            )
        )
    if dashboard:
        Storage().save(report)
    if output:
        save(report, output, None if format == "terminal" else format)
        console.print(f"Saved {output}")
    elif format == "json":
        typer.echo(to_json(report))
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
) -> None:
    """Run the deterministic callback security test suite."""
    scan(callback=callback, output=None, format="terminal")


@app.command("compare")
def compare(old: Annotated[Path, typer.Argument()], new: Annotated[Path, typer.Argument()]) -> None:
    """Compare application, model, guardrail, or policy scan results."""
    diff(old, new)


@app.command("replay")
def replay(path: Annotated[Path, typer.Argument()]) -> None:
    """Validate and inspect a safe replay bundle."""
    report, inputs = load_replay(path)
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
) -> None:  # nosec B107
    """Start the authenticated local dashboard API."""
    token = os.environ.get(token_env)
    if not token:
        raise typer.BadParameter(f"set {token_env} to a strong dashboard token")
    import uvicorn

    uvicorn.run(create_app(database=database, token=token, bind_host=host), host=host, port=port)


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
    path: Annotated[Path, typer.Argument()], events: Annotated[Path, typer.Argument()]
) -> None:
    raw = json.loads(events.read_text(encoding="utf-8"))
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
def bundle_replay(path: Annotated[Path, typer.Argument()]) -> None:
    replay(path)


@report_app.command("render")
def report_render(
    report: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Argument()],
    format: Annotated[str | None, typer.Option("--format")] = None,
) -> None:
    save(Report.model_validate_json(report.read_text(encoding="utf-8")), output, format)


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
    values = asyncio.run(NVDClient().search(query))
    VulnerabilityCache(cache).save(values)
    typer.echo(f"Saved {len(values)} records")


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
) -> None:
    pack = load_pack(path, allow_unverified=allow_unverified)
    typer.echo(json.dumps({"id": pack.id, "version": pack.version, "trust": pack.trust.value}))


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
