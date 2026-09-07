"""Safe JSON and HTML report serialization."""

from __future__ import annotations

import html
import json
from pathlib import Path

from secgraphai.core import Report
from secgraphai.security import redact
from secgraphai.lifecycle import to_junit, to_sarif


def to_json(report: Report, *, indent: int = 2) -> str:
    safe = redact(report.model_dump(mode="json"))
    return json.dumps(safe, indent=indent, sort_keys=True)


def to_html(report: Report) -> str:
    rows = []
    for finding in report.findings:
        rows.append("<tr>" + "".join(
            f"<td>{html.escape(str(value))}</td>" for value in
            (finding.id, finding.severity.value, finding.verdict.value, finding.title)
        ) + "</tr>")
    template = """<!doctype html><html><head><meta charset=\"utf-8\"><title>SecGraphAI report</title>
<style>body{font:16px system-ui;margin:2rem;color:#172033}table{border-collapse:collapse;width:100%}
th,td{padding:.6rem;border:1px solid #ccd3df;text-align:left}th{background:#edf2f7}</style></head>
<body><h1>SecGraphAI security report</h1><p>Scan: %s</p><table><thead><tr><th>ID</th>
<th>Severity</th><th>Verdict</th><th>Finding</th></tr></thead><tbody>%s</tbody></table></body></html>"""
    return template.replace("%s", html.escape(report.scan_id), 1).replace("%s", "".join(rows), 1)


def save(report: Report, path: str | Path, format: str | None = None) -> None:
    target = Path(path)
    selected = format or target.suffix.removeprefix(".") or "json"
    if selected == "html":
        content = to_html(report)
    elif selected == "sarif":
        content = json.dumps(to_sarif(report), indent=2)
    elif selected in {"junit", "xml"}:
        content = to_junit(report)
    else:
        content = to_json(report)
    target.write_text(content, encoding="utf-8")
