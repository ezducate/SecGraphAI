"""Safe JSON and HTML report serialization."""

from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path

from secgraphai.core import Report
from secgraphai.lifecycle import to_junit, to_sarif
from secgraphai.security import redact


def to_json(report: Report, *, indent: int = 2) -> str:
    safe = redact(report.model_dump(mode="json"))
    return json.dumps(safe, indent=indent, sort_keys=True)


def to_html(report: Report) -> str:
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(value))}</td>"
                for value in (
                    finding.id,
                    finding.severity.value,
                    finding.verdict.value,
                    finding.title,
                )
            )
            + "</tr>"
        )
    template = """<!doctype html><html><head><meta charset=\"utf-8\"><title>SecGraphAI report</title>
<style>body{font:16px system-ui;margin:2rem;color:#172033}table{border-collapse:collapse;width:100%}
th,td{padding:.6rem;border:1px solid #ccd3df;text-align:left}th{background:#edf2f7}</style></head>
<body><h1>SecGraphAI security report</h1><p>Scan: %s</p><table><thead><tr><th>ID</th>
<th>Severity</th><th>Verdict</th><th>Finding</th></tr></thead><tbody>%s</tbody></table></body></html>"""
    return template.replace("%s", html.escape(report.scan_id), 1).replace("%s", "".join(rows), 1)


def to_markdown(report: Report) -> str:
    def safe(value: object) -> str:
        return str(redact(value)).replace("|", "\\|").replace("\r", " ").replace("\n", " ")

    rows = [
        "# SecGraphAI security report",
        "",
        f"Scan: `{safe(report.scan_id)}`",
        "",
        "| ID | Severity | Verdict | Finding |",
        "|---|---|---|---|",
    ]
    rows.extend(
        f"| {safe(item.id)} | {item.severity.value} | {item.verdict.value} | {safe(item.title)} |"
        for item in report.findings
    )
    return "\n".join(rows) + "\n"


def to_csv(report: Report) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["id", "severity", "verdict", "title", "fingerprint"])
    for item in report.findings:
        writer.writerow(
            [
                redact(item.id),
                item.severity.value,
                item.verdict.value,
                redact(item.title),
                item.fingerprint or "",
            ]
        )
    return output.getvalue()


def to_jsonl(report: Report) -> str:
    return "\n".join(
        json.dumps(redact(item.model_dump(mode="json")), sort_keys=True, default=str)
        for item in report.findings
    ) + ("\n" if report.findings else "")


def safe_report_path(path: str | Path) -> Path:
    target = Path(path)
    if not re.fullmatch(r"[A-Za-z0-9_. -]{1,200}", target.name):
        raise ValueError("unsafe report file name")
    return target


def save(report: Report, path: str | Path, format: str | None = None) -> None:
    target = safe_report_path(path)
    selected = format or target.suffix.removeprefix(".") or "json"
    if selected == "html":
        content = to_html(report)
    elif selected == "sarif":
        content = json.dumps(to_sarif(report), indent=2)
    elif selected in {"junit", "xml"}:
        content = to_junit(report)
    elif selected in {"md", "markdown"}:
        content = to_markdown(report)
    elif selected == "csv":
        content = to_csv(report)
    elif selected == "jsonl":
        content = to_jsonl(report)
    elif selected == "pdf":
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError("PDF output requires the pdf extra") from exc
        HTML(string=to_html(report)).write_pdf(target)
        return
    else:
        content = to_json(report)
    target.write_text(content, encoding="utf-8")
