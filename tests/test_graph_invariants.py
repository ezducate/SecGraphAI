from secgraphai import InvariantEngine, NodeType, SecurityGraph, Verdict, invariant


def test_graph_detects_cross_boundary_paths():
    graph = SecurityGraph()
    graph.add_node("prompt", NodeType.PROMPT, trust="untrusted")
    graph.add_node("agent", NodeType.AGENT)
    graph.add_node("refund", NodeType.TOOL, privileged=True)
    graph.add_edge("prompt", "agent", "CAN_INFLUENCE")
    graph.add_edge("agent", "refund", "CAN_CALL")
    assert graph.risk_paths() == [
        {"category": "UNTRUSTED_TO_PRIVILEGED", "path": ["prompt", "agent", "refund"]}
    ]


def test_deny_invariant_produces_verified_violation():
    engine = InvariantEngine(
        [
            invariant(
                "NO_SECRET_EXFIL",
                source={"sensitivity": "secret"},
                destination={"trust": "external"},
                expected="deny",
            )
        ]
    )
    result = engine.evaluate_flow({"sensitivity": "secret"}, {"trust": "external"})
    assert result[0].verdict is Verdict.VERIFIED_VIOLATION


def test_invariants_enforce_tenant_equality_and_conditional_controls():
    engine = InvariantEngine(
        [
            invariant(
                "TENANT_ISOLATION",
                principal={"tenant": "$resource.tenant"},
                expected="equal",
            ),
            invariant(
                "REFUND_APPROVAL",
                tool="issue_refund",
                when={"amount_gt": 500},
                requires=["authenticated", "explicit_confirmation"],
                expected="allow",
            ),
        ]
    )
    unequal = engine.evaluate_flow(
        {}, {"tenant": "A"}, principal={"tenant": "B"}, controls=()
    )
    assert unequal[0].verdict is Verdict.VERIFIED_VIOLATION
    missing = engine.evaluate_flow(
        {},
        {},
        tool="issue_refund",
        context={"amount": 750},
        controls={"authenticated"},
    )
    missing_approval = next(item for item in missing if item.invariant_id == "REFUND_APPROVAL")
    assert missing_approval.verdict is Verdict.VERIFIED_VIOLATION
    assert missing_approval.evidence[0].metadata["missing_controls"] == [
        "explicit_confirmation"
    ]
    passed = engine.evaluate_flow(
        {},
        {},
        tool="issue_refund",
        context={"amount": 750},
        controls={"authenticated", "explicit_confirmation"},
    )
    assert next(item for item in passed if item.invariant_id == "REFUND_APPROVAL").verdict is Verdict.PASS


def test_invariant_yaml_and_all_condition_operators(tmp_path):
    path = tmp_path / "invariants.yaml"
    path.write_text(
        "invariants:\n"
        "  - id: CONDITIONS\n"
        "    source: {kind: user}\n"
        "    destination: {trust: external}\n"
        "    principal: {role: admin}\n"
        "    tool: send\n"
        "    when: {minimum_gte: 2, maximum_lte: 9, positive_gt: 0, low_lt: 5, state_eq: ready}\n"
        "    expected: allow\n",
        encoding="utf-8",
    )
    engine = InvariantEngine.from_yaml(path)
    result = engine.evaluate_flow(
        {"kind": "user"},
        {"trust": "external"},
        principal={"role": "admin"},
        tool="send",
        context={"minimum": 2, "maximum": 9, "positive": 1, "low": 4, "state": "ready"},
        controls="logged",
    )
    assert result[0].verdict is Verdict.PASS
    assert engine.evaluate_flow({}, {}) == []
    path.write_text("not-invariants: []\n", encoding="utf-8")
    try:
        InvariantEngine.from_yaml(path)
    except ValueError as exc:
        assert "invariants list" in str(exc)
    else:
        raise AssertionError("invalid invariant document was accepted")
