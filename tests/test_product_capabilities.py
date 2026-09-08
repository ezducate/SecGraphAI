from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from secgraphai.attacks import (
    BUILTIN_ATTACKS,
    AttackMemory,
    evolve,
    novelty,
    select_attacks,
    sign_pack,
    verify_pack,
)
from secgraphai.config import Config, Mode
from secgraphai.core import Evidence, Finding, Report, Severity, Verdict
from secgraphai.intelligence import (
    Component,
    Vulnerability,
    coverage,
    parse_cyclonedx,
    security_gate,
)
from secgraphai.lifecycle import diff_reports, fingerprint, pytest_regression, to_junit, to_sarif
from secgraphai.policy import Effect, PolicyEngine, Rule
from secgraphai.provenance import Provenance, Trust
from secgraphai.targets import (
    Identity,
    audit_mcp_tools,
    discover_openapi,
    identity_matrix,
    load_schemathesis_schema,
    schemathesis_cases,
)
from secgraphai.validators import Validators, judge_ensemble


def finding(title="issue", verdict=Verdict.VERIFIED_VIOLATION):
    return Finding(
        id="SG-1",
        title=title,
        severity=Severity.HIGH,
        verdict=verdict,
        confidence=1,
        evidence=[Evidence(kind="x", description="x", observed="MARK")],
    )


@pytest.mark.parametrize("index", range(120))
def test_deterministic_marker_validator_matrix(index):
    marker = f"CANARY-{index}"
    assert Validators.contains(f"prefix {marker}", marker).verdict == Verdict.VERIFIED_VIOLATION
    assert Validators.contains("safe", marker).verdict == Verdict.PASS


@pytest.mark.parametrize("index", range(80))
def test_regex_and_json_validators_matrix(index):
    assert (
        Validators.regex(f"tenant-{index}", rf"tenant-{index}$").verdict
        == Verdict.VERIFIED_VIOLATION
    )
    payload = json.dumps({"records": [{"owner": index}]})
    assert (
        Validators.json_path(payload, "$.records.0.owner", index).verdict
        == Verdict.VERIFIED_VIOLATION
    )


@pytest.mark.parametrize("profile", ["llm-2026", "api-2023", "web-2025", "agentic-2026"])
@pytest.mark.parametrize("covered", range(11))
def test_owasp_coverage_matrix(profile, covered):
    prefix = {"llm-2026": "LLM", "api-2023": "API", "web-2025": "A", "agentic-2026": "ASI"}[profile]
    labels = [f"{prefix}{i:02d}" if prefix != "API" else f"API{i}" for i in range(1, covered + 1)]
    result = coverage(profile, labels)
    assert result["percent"] == covered * 10


@pytest.mark.parametrize(
    "score,known,reachable",
    [(s, k, r) for s in range(1, 11) for k in (False, True) for r in (False, True, None)],
)
def test_vulnerability_priority_is_bounded(score, known, reachable):
    value = Vulnerability("CVE-X", "lib", score, known, reachable).priority
    assert 0 <= value <= 10


def test_openapi_identity_and_schemathesis():
    spec = {
        "security": [{"bearer": []}],
        "paths": {
            "/users": {"get": {"operationId": "users"}},
            "/admin": {"post": {"security": [{"admin": []}]}},
        },
    }
    endpoints = discover_openapi(spec)
    assert len(endpoints) == 2 and endpoints[0].security == ("bearer",)
    cases = identity_matrix(
        [Identity("guest"), Identity("root", roles=frozenset({"admin"}))],
        endpoints,
        lambda identity, endpoint: "admin" in identity.roles,
    )
    assert len(cases) == 4 and schemathesis_cases(spec)[0]["method"] == "GET"


def test_optional_schemathesis_loader(monkeypatch):
    expected = object()
    fake = SimpleNamespace(openapi=SimpleNamespace(from_dict=lambda document: expected))
    monkeypatch.setitem(sys.modules, "schemathesis", fake)
    assert load_schemathesis_schema({"openapi": "3.1.0"}) is expected


def test_mcp_metadata_audit():
    issues = audit_mcp_tools([{"name": "x", "description": "", "inputSchema": {}}, {"name": "x"}])
    assert len(issues) >= 3


def test_policy_shadow_simulation_and_explanation():
    engine = PolicyEngine(
        [Rule("deny-shell", Effect.DENY, {"tool": "shell"}, "dangerous")], shadow=True
    )
    decision = engine.evaluate({"tool": "shell"})
    assert (
        decision.effect == Effect.DENY and not decision.enforced and decision.reason == "dangerous"
    )
    assert len(engine.simulate([{"tool": "shell"}, {"tool": "read"}])) == 2


def test_provenance_merge():
    left = Provenance(frozenset({"user"}), Trust.UNTRUSTED, "a", frozenset({"pii"}))
    right = Provenance(frozenset({"db"}), Trust.TRUSTED, "a")
    merged = left.merge(right).transformed("summarize")
    assert (
        merged.trust == Trust.MIXED
        and merged.tenant == "a"
        and "summarize" in merged.transformations
    )


def test_attack_planning_memory_novelty_evolution_and_signing():
    memory = AttackMemory()
    memory.record(BUILTIN_ATTACKS[-1], 0.9)
    assert select_attacks(BUILTIN_ATTACKS, 1, memory)[0] == BUILTIN_ATTACKS[-1]
    assert novelty("completely novel phrase", ["old attack text"]) == 1
    assert evolve(BUILTIN_ATTACKS[0], 7) == evolve(BUILTIN_ATTACKS[0], 7)
    pack = {"schema": 1, "attacks": ["x"]}
    signature = sign_pack(pack, b"secret")
    assert verify_pack(pack, signature, b"secret") and not verify_pack(pack, signature, b"wrong")


def test_lifecycle_formats_and_diff():
    old = Report(scan_id="old", findings=[])
    new = Report(scan_id="new", findings=[finding()])
    assert len(diff_reports(old, new)["new"]) == 1
    assert fingerprint(finding()) == fingerprint(finding())
    assert 'assert "MARK" not in output' in pytest_regression(finding())
    assert to_sarif(new)["version"] == "2.1.0" and "testsuite" in to_junit(new)


def test_sbom_gate_and_config():
    assert parse_cyclonedx({"components": [{"name": "x", "version": "1"}]}) == [Component("x", "1")]
    assert security_gate([Vulnerability("CVE-1", "x", 9, reachable=True)])[0] is False
    assert security_gate([Vulnerability("CVE-2", "x", 9, reachable=False)])[0] is True
    assert Config().mode == Mode.SAFE


@pytest.mark.asyncio
async def test_judge_ensemble_majority_and_tie():
    async def yes(prompt, output):
        return True, 0.8

    async def no(prompt, output):
        return False, 0.9

    assert (await judge_ensemble("p", "o", [yes, yes, no])).verdict == Verdict.LIKELY_VIOLATION
    assert (await judge_ensemble("p", "o", [yes, no])).verdict == Verdict.INCONCLUSIVE
