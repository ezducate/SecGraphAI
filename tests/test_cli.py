from typer.testing import CliRunner

from secgraphai.cli import app

runner = CliRunner()


def test_init_and_doctor(tmp_path):
    path = tmp_path / "secgraph.yaml"
    assert runner.invoke(app, ["init", str(path)]).exit_code == 0
    result = runner.invoke(app, ["doctor", "--config", str(path)])
    assert result.exit_code == 0, result.output


def test_help_lists_core_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "discover" in result.output and "self-audit" in result.output
