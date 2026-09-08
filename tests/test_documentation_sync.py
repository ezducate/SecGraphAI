import tomllib
from pathlib import Path

from click import Command, Group, Option
from typer.main import get_command

from secgraphai.cli import app
from secgraphai.core import ScanManifest

ROOT = next(
    candidate
    for candidate in (Path.cwd(), *Path(__file__).parents)
    if (candidate / "pyproject.toml").exists()
)


def _leaf_commands(command: Command, prefix: tuple[str, ...] = ()):
    if isinstance(command, Group):
        for name, child in command.commands.items():
            yield from _leaf_commands(child, (*prefix, name))
        return
    yield prefix, command


def test_published_readme_and_runtime_manifest_match_project_version():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = project["version"]
    readme = (ROOT / project["readme"]).read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "USER_GUIDE.md").read_text(encoding="utf-8")

    assert f'"secgraphai=={version}"' in readme
    assert f'"secgraphai=={version}"' in guide
    assert ScanManifest.model_fields["package_version"].default == version


def test_cli_reference_contains_every_leaf_command_and_long_option():
    reference = (ROOT / "docs" / "CLI_REFERENCE.md").read_text(encoding="utf-8")
    missing: list[str] = []

    for path, command in _leaf_commands(get_command(app)):
        rendered = f"secgraph {' '.join(path)}"
        if rendered not in reference:
            missing.append(rendered)
        for parameter in command.params:
            if not isinstance(parameter, Option):
                continue
            long_options = [item for item in parameter.opts if item.startswith("--")]
            for option in long_options:
                if option != "--help" and option not in reference:
                    missing.append(f"{rendered} {option}")

    assert not missing, f"undocumented CLI surface: {missing}"


def test_pypi_readme_links_to_detailed_guides_and_uses_real_threat_scenarios():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for expected in (
        "docs/USER_GUIDE.md",
        "docs/CLI_REFERENCE.md",
        "unauthorized refund",
        "poisoned RAG",
        "cross-tenant API access",
        "MCP capability drift",
        "@secgraph.tool",
    ):
        assert expected.casefold() in readme.casefold()
