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
