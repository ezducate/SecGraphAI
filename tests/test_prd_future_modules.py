from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from secgraphai.cli import app
from secgraphai.core import Finding, Interaction, Report, Severity, Verdict
from secgraphai.evaluation import (
    ResourceUsage,
    UtilityResult,
    compare_utility,
    detect_amplification,
    measure,
)
from secgraphai.multimodal import inspect_media
from secgraphai.research import draft_attack_pack, extract_text
from secgraphai.supply_chain import inspect_artifact, inspect_model_directory


def test_resource_and_utility_differential():
    report = Report(
        scan_id="x",
        findings=[
            Finding(
                id="x",
                title="x",
                severity=Severity.HIGH,
                verdict=Verdict.VERIFIED_VIOLATION,
                confidence=1,
            )
        ],
        interactions=[
            Interaction(test_id="x", duration_ms=10, input_tokens=2, output_tokens=3, model_calls=1)
        ],
    )
    value = measure(report, legitimate_passed=9, legitimate_total=10)
    result = compare_utility(UtilityResult(1, 1, 5, 0), value)
    assert value.attack_success_rate == 1 and value.legitimate_success_rate == 0.9
    assert result.utility_delta < 0 and result.latency_delta_ms == 5
    alerts = detect_amplification(
        ResourceUsage(model_calls=1, retries=1),
        ResourceUsage(model_calls=5, retries=2),
    )
    assert [item.metric for item in alerts] == ["model_calls"]
    assert detect_amplification(ResourceUsage(), ResourceUsage()) == []
    with pytest.raises(ValueError, match="thresholds"):
        detect_amplification(ResourceUsage(), ResourceUsage(), max_ratio=1)


def test_research_importer_is_disabled_draft(tmp_path):
    path = tmp_path / "paper.txt"
    path.write_text("We describe an attack. It can bypass authorization. Limitations apply.")
    assert "attack" in extract_text(path)
    pack, review = draft_attack_pack(path)
    assert len(pack.attacks) == 2 and review["human_review_required"]
    assert review["activated"] is False
    oversized = tmp_path / "large.txt"
    oversized.write_text("123")
    with pytest.raises(ValueError):
        extract_text(oversized, max_bytes=2)


def test_model_supply_chain_and_multimodal(tmp_path):
    unsafe = tmp_path / "model.pkl"
    unsafe.write_bytes(b"not executed")
    unsafe.with_suffix(".pkl.json").write_text(json.dumps({"source": "local"}))
    safe = tmp_path / "model.onnx"
    safe.write_bytes(b"onnx")
    inspected = inspect_artifact(unsafe)
    assert inspected.unsafe_serialization and inspected.metadata == {"source": "local"}
    assert len(inspect_model_directory(tmp_path)) == 2
    text = tmp_path / "transcript.txt"
    text.write_text("untrusted audio transcript")
    assert "untrusted" in inspect_media(text).extracted_text
    with pytest.raises(ValueError):
        inspect_media(tmp_path / "missing")


def test_future_cli_surfaces(tmp_path):
    runner = CliRunner()
    paper = tmp_path / "paper.txt"
    paper.write_text("An attack can bypass a control.")
    assert (
        runner.invoke(
            app, ["research", "import", str(paper), "--output", str(tmp_path / "draft.json")]
        ).exit_code
        == 0
    )
    model = tmp_path / "model.onnx"
    model.write_bytes(b"onnx")
    assert runner.invoke(app, ["model", "inspect", str(model)]).exit_code == 0
    assert runner.invoke(app, ["media", str(paper)]).exit_code == 0
