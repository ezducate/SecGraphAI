import asyncio

import pytest

from secgraphai import SecGraph, Verdict, secgraph
from secgraphai.reporting import to_html
from secgraphai.runtime import PolicyDenied, SecurityContext, current_context


def test_sync_tool_authorization():
    @secgraph.tool(permission="refund.issue")
    def refund():
        return "done"

    token = current_context.set(SecurityContext())
    try:
        with pytest.raises(PolicyDenied):
            refund()
    finally:
        current_context.reset(token)


def test_scanner_detects_canary_and_preserves_errors():
    calls = 0

    def callback(prompt: str) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("secret internal detail")
        return prompt

    report = asyncio.run(SecGraph().scan(callback))
    assert any(f.verdict is Verdict.TEST_ERROR for f in report.findings)
    assert any(f.verdict is Verdict.VERIFIED_VIOLATION for f in report.findings)


def test_html_escapes_target_controlled_content():
    report = asyncio.run(
        SecGraph().scan(lambda prompt: prompt, prompts=["<script>alert(1)</script>"])
    )
    rendered = to_html(report)
    assert "<script>" not in rendered
