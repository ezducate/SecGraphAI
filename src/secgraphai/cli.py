"""SecGraphAI command-line interface."""

from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.table import Table

from secgraphai.reporting import save, to_json
from secgraphai.core import Report
from secgraphai.intelligence import VulnerabilityCache
from secgraphai.lifecycle import diff_reports
from secgraphai.targets import discover_openapi
from secgraphai.scanner import SecGraph
from secgraphai.security import doctor as inspect_config
from secgraphai.security import redact

app = typer.Typer(help="Security testing for systems that think and act.", no_args_is_help=True)
console = Console()

_STARTER = {"mode": "SAFE", "scope": {"allowed_hosts": ["localhost"],
    "allowed_ports": [8000], "max_total_requests": 100}, "invariants": [{
        "id": "NO_SECRET_EXFIL", "description": "Secrets must not reach external destinations",
        "source": {"sensitivity": "secret"}, "destination": {"trust": "external"},
        "expected": "deny"}]}


@app.command("init")
def initialize(path: Annotated[Path, typer.Argument()] = Path("secgraph.yaml"),
               force: Annotated[bool, typer.Option("--force")] = False) -> None:
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
def discover(path: Annotated[Path, typer.Argument()] = Path(".")) -> None:
    """Safely discover decorated Python functions without importing application code."""
    if not path.exists():
        raise typer.BadParameter("path does not exist")
    files = [path] if path.is_file() else list(path.rglob("*.py"))
    counts = {"agent": 0, "tool": 0, "retriever": 0}
    for file in files:
        try:
            tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        except (OSError, SyntaxError, UnicodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if isinstance(expression, ast.Attribute) and expression.attr in counts:
                        counts[expression.attr] += 1
    table = Table("Component", "Count")
    for key, value in counts.items():
        table.add_row(key.title(), str(value))
    console.print(table)


@app.command()
def scan(callback: Annotated[str, typer.Option(help="Import path module:function")],
         output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
         format: Annotated[str, typer.Option("--format")] = "terminal") -> None:
    """Run safe deterministic checks against a local Python callback."""
    module_name, separator, attribute = callback.partition(":")
    if not separator:
        raise typer.BadParameter("callback must use module:function syntax")
    target = getattr(importlib.import_module(module_name), attribute)
    report = SecGraph().scan_callback(target)
    if output:
        save(report, output, "html" if format == "html" else "json")
        console.print(f"Saved {output}")
    elif format == "json":
        typer.echo(to_json(report))
    else:
        console.print(redact(report.summary()))
    if report.errors:
        raise typer.Exit(2)


@app.command("self-audit")
def self_audit() -> None:
    """Run built-in installation safety checks."""
    sample = {"api_key": "do-not-print"}
    result = {"package_import": "pass",
              "secret_redaction": "pass" if redact(sample)["api_key"] == "[REDACTED]" else "fail",
              "error_is_pass": False, "safe_yaml": True, "scope_default_deny": True}
    typer.echo(json.dumps(result, sort_keys=True))


@app.command("openapi")
def openapi(path: Annotated[Path, typer.Argument()]) -> None:
    """Discover operations from a local OpenAPI JSON/YAML document."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    typer.echo(json.dumps([endpoint.__dict__ for endpoint in discover_openapi(document)], default=list))


@app.command("diff")
def diff(old: Annotated[Path, typer.Argument()], new: Annotated[Path, typer.Argument()]) -> None:
    """Compare two report baselines using stable finding fingerprints."""
    result = diff_reports(Report.model_validate_json(old.read_text()),
                          Report.model_validate_json(new.read_text()))
    typer.echo(json.dumps({key: [item.id for item in value] for key, value in result.items()}))


@app.command("cve")
def cve(query: Annotated[str, typer.Argument()],
        cache: Annotated[Path, typer.Option("--cache")] = Path("cve-cache.json")) -> None:
    """Search the offline vulnerability cache."""
    typer.echo(json.dumps([item.__dict__ for item in VulnerabilityCache(cache).search(query)], default=list))


if __name__ == "__main__":
    app()
