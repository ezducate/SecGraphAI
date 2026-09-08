from __future__ import annotations

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secgraphai.attacks import (
    Attack,
    AttackMemory,
    AttackPlanner,
    PackTrust,
    evolve,
    load_pack,
    novelty,
    sign_pack_ed25519,
    verify_pack_ed25519,
)
from secgraphai.policy import Effect, PolicyEngine, Rule
from secgraphai.provenance import Confidence, Label, Provenance, Trust
from secgraphai.runtime import PolicyDenied, secgraph


def test_attack_pack_trust_and_ed25519(tmp_path):
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload = {
        "id": "official",
        "version": "1.0",
        "publisher": "secgraphai",
        "minimum_engine": "1.0.0rc1",
        "attacks": [
            {
                "id": "a",
                "family": "rag",
                "prompt": "probe",
                "cost": 1,
                "tags": [],
                "source": "rag",
                "target_invariant": None,
                "conversation_depth": 1,
            }
        ],
    }
    signature = sign_pack_ed25519(payload, private_bytes)
    assert verify_pack_ed25519(payload, signature, public_bytes)
    document = {**payload, "trust": "TRUSTED_OFFICIAL", "signature": signature}
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(document))
    pack = load_pack(path, public_key=public_bytes)
    assert pack.trust == PackTrust.TRUSTED_OFFICIAL and pack.attacks[0].source == "rag"


def test_unverified_pack_requires_opt_in(tmp_path):
    path = tmp_path / "pack.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "x",
                "version": "1",
                "publisher": "community",
                "minimum_engine": "1.0.0rc1",
                "trust": "UNVERIFIED_COMMUNITY",
                "attacks": [{"id": "a", "family": "x", "prompt": "x"}],
            }
        )
    )
    with pytest.raises(PermissionError):
        load_pack(path)
    assert load_pack(path, allow_unverified=True).id == "x"

    with pytest.raises(RuntimeError, match="requires SecGraphAI"):
        load_pack(path, allow_unverified=True, engine_version="0.9.0")


def test_planner_memory_relevance_and_budget():
    attacks = [
        Attack("a", "rag", "one", 2, frozenset({"rag"})),
        Attack("b", "mcp", "two", 1, frozenset({"mcp"})),
    ]
    memory = AttackMemory()
    memory.observe(attacks[0], stage="reached", score=0.9)
    plan = AttackPlanner(attacks, memory).plan({"rag"}, budget=2)
    assert plan == [attacks[0]] and memory.observations[0].stage == "reached"
    assert evolve(attacks[0], 4) == evolve(attacks[0], 4)
    assert novelty("new unique phrase", ["old text"]) == 1


@pytest.mark.parametrize(
    "expression,event,expected",
    [
        ("amount__gt", {"amount": 501}, True),
        ("amount__lte", {"amount": 500}, True),
        ("actor.role", {"actor": {"role": "admin"}}, True),
        ("labels__contains", {"labels": ["UNTRUSTED"]}, True),
    ],
)
def test_policy_expression_matrix(expression, event, expected):
    value = 500 if "amount" in expression else ("UNTRUSTED" if "labels" in expression else "admin")
    decision = PolicyEngine([Rule("r", Effect.ALLOW, {expression: value})]).evaluate(event)
    assert (decision.effect == Effect.ALLOW) is expected


def test_policy_yaml_priority_and_summary(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "mode": "shadow",
                "default": "allow",
                "rules": [
                    {"id": "deny", "effect": "deny", "priority": 10, "match": {"tool": "shell"}}
                ],
            }
        )
    )
    engine = PolicyEngine.from_yaml(path)
    summary = engine.summarize([{"tool": "shell"}, {"tool": "read"}])
    assert engine.shadow and summary.would_block == 1 and summary.allowed == 1


def test_runtime_policy_enforces_sync_and_redacts():
    deny = PolicyEngine([Rule("deny", Effect.DENY, {"kind": "tool"}, "blocked")])
    secgraph.use_policy(deny)

    @secgraph.tool()
    def tool():
        return "value"

    with pytest.raises(PolicyDenied):
        tool()
    redact_engine = PolicyEngine([Rule("redact", Effect.REDACT, {"kind": "tool"})])
    secgraph.use_policy(redact_engine)

    @secgraph.tool()
    def secret_tool():
        return {"api_key": "value"}

    assert secret_tool()["api_key"] == "[REDACTED]"
    secgraph.aspects = []


def test_provenance_labels_merge_and_map():
    left = Provenance(frozenset({"user"}), Trust.UNTRUSTED, labels=frozenset({Label.USER}))
    right = Provenance(
        frozenset({"rag"}),
        Trust.TRUSTED,
        labels=frozenset({Label.RAG}),
        confidence=Confidence.PROBABILISTIC,
    )
    merged = left.merge(right)
    assert merged.trust == Trust.MIXED and merged.confidence == Confidence.DERIVED
    assert merged.labels == {Label.USER, Label.RAG}
