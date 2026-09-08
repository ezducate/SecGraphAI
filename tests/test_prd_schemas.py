import json

from typer.testing import CliRunner

from secgraphai.cli import app
from secgraphai.schemas import ATTACK_PACK_SCHEMA, POLICY_SCHEMA, public_schemas, write_schemas


def test_public_schema_contracts_and_export(tmp_path):
    schemas = public_schemas()
    assert set(schemas) == {"report-1.0.json", "attack-pack-1.0.json", "policy-1.0.json"}
    assert ATTACK_PACK_SCHEMA["additionalProperties"] is False
    assert POLICY_SCHEMA["additionalProperties"] is False
    paths = write_schemas(tmp_path)
    assert all(json.loads(path.read_text())["$schema"] for path in paths)
    result = CliRunner().invoke(app, ["schemas", "--output", str(tmp_path / "cli")])
    assert result.exit_code == 0
