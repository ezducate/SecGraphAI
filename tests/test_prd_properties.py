from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from secgraphai.core import Report
from secgraphai.graph import EdgeType, NodeType, SecurityGraph
from secgraphai.policy import Effect, PolicyEngine, Rule
from secgraphai.reporting import to_html
from secgraphai.security import redact
from secgraphai.targets import discover_openapi
from secgraphai.validators import Validators


@given(st.text())
@settings(max_examples=100)
def test_report_html_never_emits_raw_target_text(value):
    report = Report(scan_id=value)
    rendered = to_html(report)
    assert "<script>" not in rendered.casefold() or "<script>" not in value.casefold()


@given(st.dictionaries(st.text(min_size=1, max_size=20), st.text(max_size=50), max_size=10))
@settings(max_examples=100)
def test_recursive_redaction_does_not_change_shape(value):
    assert set(redact(value)) == set(value)


@given(st.integers(), st.integers())
@settings(max_examples=100)
def test_denied_policy_never_allows(value, threshold):
    engine = PolicyEngine(
        [Rule("deny", Effect.DENY, {"value__gte": threshold})], default=Effect.ALLOW
    )
    decision = engine.evaluate({"value": value})
    assert decision.effect == (Effect.DENY if value >= threshold else Effect.ALLOW)


@given(
    st.dictionaries(
        st.sampled_from(["get", "post", "put", "delete", "x-extra"]),
        st.dictionaries(st.text(max_size=5), st.text(max_size=5)),
        max_size=5,
    )
)
@settings(max_examples=100)
def test_openapi_parser_ignores_unknown_methods(methods):
    endpoints = discover_openapi({"paths": {"/x": methods}})
    assert all(item.method.casefold() in {"get", "post", "put", "delete"} for item in endpoints)


@given(st.text(max_size=200), st.text(min_size=1, max_size=30))
@settings(max_examples=100)
def test_marker_validator_is_deterministic(output, marker):
    first, second = Validators.contains(output, marker), Validators.contains(output, marker)
    assert first.verdict == second.verdict
    assert first.evidence[0].sha256 == second.evidence[0].sha256


@given(st.lists(st.sampled_from(list(NodeType)), min_size=2, max_size=8))
@settings(max_examples=50)
def test_graph_serialization_handles_generated_shapes(kinds):
    graph = SecurityGraph()
    for index, kind in enumerate(kinds):
        graph.add_node(str(index), kind)
    for index in range(len(kinds) - 1):
        graph.add_edge(str(index), str(index + 1), EdgeType.CAN_CALL)
    assert len(graph.to_dict()["nodes"]) == len(kinds)
