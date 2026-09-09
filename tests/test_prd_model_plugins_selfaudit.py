from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest
import respx
from httpx import Response

from secgraphai.attacks import AttackPack, PackTrust
from secgraphai.model import Model, ModelError
from secgraphai.plugins import PluginManifest, PluginMode, audit_plugins, load_manifest, run_plugin
from secgraphai.self_security import (
    AuditStatus,
    dependency_audit,
    package_integrity,
    permissions_check,
    run_self_audit,
)


@pytest.mark.asyncio
@respx.mock
async def test_model_success_env_repr_and_failures(monkeypatch):
    monkeypatch.setenv("MODEL_KEY", "secret")
    model = Model(base_url="https://model.test/v1", model="x", api_key_env="MODEL_KEY")
    route = respx.post("https://model.test/v1/chat/completions")
    route.mock(return_value=Response(200, json={"choices": [{"message": {"content": "ok"}}]}))
    assert await model.complete([{"role": "user", "content": "x"}]) == "ok"
    assert "secret" not in repr(model)
    route.mock(return_value=Response(200, json={"invalid": True}))
    with pytest.raises(ModelError, match="invalid"):
        await model.complete([])
    route.mock(return_value=Response(500))
    with pytest.raises(ModelError, match="HTTPStatusError"):
        await model.complete([])


@pytest.mark.asyncio
@respx.mock
async def test_model_byok_reads_environment_at_request_time_and_never_embeds_it(monkeypatch):
    monkeypatch.setenv("ROTATING_MODEL_KEY", "first-secret")
    model = Model(
        base_url="https://model.test/v1",
        model="x",
        api_key_env="ROTATING_MODEL_KEY",
    )
    route = respx.post("https://model.test/v1/chat/completions").mock(
        return_value=Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    )

    await model.complete([{"role": "user", "content": "probe"}])
    assert route.calls[0].request.headers["Authorization"] == "Bearer first-secret"
    assert json.loads(route.calls[0].request.content) == {
        "model": "x",
        "messages": [{"role": "user", "content": "probe"}],
    }

    monkeypatch.setenv("ROTATING_MODEL_KEY", "rotated-secret")
    await model.complete([])
    assert route.calls[1].request.headers["Authorization"] == "Bearer rotated-secret"

    monkeypatch.delenv("ROTATING_MODEL_KEY")
    await model.complete([])
    assert "Authorization" not in route.calls[2].request.headers
    assert "first-secret" not in repr(model)
    assert "rotated-secret" not in repr(model)


@pytest.mark.asyncio
@respx.mock
async def test_explicit_model_key_takes_precedence_over_environment(monkeypatch):
    monkeypatch.setenv("MODEL_KEY", "environment-secret")
    model = Model(
        base_url="https://model.test/v1",
        model="x",
        api_key="explicit-secret",
        api_key_env="MODEL_KEY",
    )
    route = respx.post("https://model.test/v1/chat/completions").mock(
        return_value=Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    )

    await model.complete([])

    assert route.calls[0].request.headers["Authorization"] == "Bearer explicit-secret"


@pytest.mark.asyncio
@respx.mock
async def test_model_response_size_limit():
    model = Model(base_url="https://model.test", model="x", max_response_bytes=2)
    respx.post("https://model.test/chat/completions").mock(
        return_value=Response(200, content=b"long")
    )
    with pytest.raises(ModelError, match="size limit"):
        await model.complete([])


def test_plugin_runner_permissions_schema_and_manifest(tmp_path):
    script = tmp_path / "plugin.py"
    script.write_text(
        "import json,sys\ndata=json.load(sys.stdin)\nprint(json.dumps({'findings': [], 'seen': bool(data)}))\n"
    )
    manifest = PluginManifest(
        "test",
        ("python", str(script)),
        frozenset({"scan"}),
        output_schema={"required": ["findings"]},
    )
    assert run_plugin(manifest, {"x": 1}, allowed_permissions={"scan"})["seen"]
    with pytest.raises(PermissionError):
        run_plugin(manifest, {}, allowed_permissions=set())
    with pytest.raises(PermissionError):
        run_plugin(PluginManifest("x", (sys.executable,)), {})
    path = tmp_path / "plugin.json"
    path.write_text(json.dumps({"name": "test", "command": ["python"], "mode": "subprocess"}))
    assert load_manifest(path).name == "test"


def test_plugin_audit_catches_trust_and_credentials():
    manifest = PluginManifest(
        "x", ("python",), frozenset({"credentials.raw"}), mode=PluginMode.IN_PROCESS
    )
    problems = audit_plugins([manifest, manifest])
    assert len(problems) >= 4


def test_container_plugin_uses_digest_pinning_and_strong_isolation(monkeypatch):
    recorded = {}

    def which(name):
        return "C:/tools/docker.exe" if name == "docker" else None

    def run(command, **kwargs):
        recorded["command"] = command
        recorded["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout='{"findings": []}')

    monkeypatch.setattr("secgraphai.plugins.shutil.which", which)
    monkeypatch.setattr("secgraphai.plugins.subprocess.run", run)
    digest = "a" * 64
    manifest = PluginManifest(
        "isolated",
        (f"registry.example/plugin@sha256:{digest}", "scan"),
        mode=PluginMode.CONTAINER,
        output_schema={"required": ["findings"]},
    )
    assert run_plugin(manifest, {"target": "sanitized"}) == {"findings": []}
    command = recorded["command"]
    assert command[0] == "C:/tools/docker.exe"
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command and "--cap-drop" in command
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert recorded["kwargs"]["shell"] is False

    unpinned = PluginManifest("bad", ("registry.example/plugin:latest",), mode=PluginMode.CONTAINER)
    with pytest.raises(PermissionError, match="pinned"):
        run_plugin(unpinned, {})
    assert any("not digest-pinned" in item for item in audit_plugins([unpinned]))


def test_self_audit_components(tmp_path, monkeypatch):
    assert package_integrity().status in {AuditStatus.PASS, AuditStatus.WARN}
    assert dependency_audit(False).status == AuditStatus.WARN
    assert permissions_check(None, "x").status == AuditStatus.NA
    report = run_self_audit(
        config={"scope": {"allowed_hosts": ["localhost"], "max_total_requests": 1}},
        database=tmp_path / "missing",
        packs=[AttackPack("x", "1", "x", "1", (), PackTrust.UNVERIFIED_COMMUNITY)],
    )
    assert not report.passed and report.metadata["audit_sha256"]
