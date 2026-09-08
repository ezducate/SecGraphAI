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


def to_json(report: Report, *, indent: int = 2, mask_pii: bool = False) -> str:
    safe = redact(report.model_dump(mode="json"), mask_pii=mask_pii)
    return json.dumps(safe, indent=indent, sort_keys=True)


def to_html(report: Report, *, mask_pii: bool = False) -> str:
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(redact(value, mask_pii=mask_pii)))}</td>"
                for value in (
                    finding.id,
                    finding.severity.value,
                    finding.verdict.value,
                    finding.title,
                )
            )
            + "</tr>"
        )
    summary = "".join(
        f"<li><strong>{html.escape(key)}</strong>: {value}</li>"
        for key, value in report.summary().items()
        if value
    )
    resources = "".join(
        f"<li><strong>{html.escape(key)}</strong>: {value}</li>"
        for key, value in report.resources().items()
    )
    limitations = "".join(
        f"<li>{html.escape(str(redact(item, mask_pii=mask_pii)))}</li>"
        for item in report.limitations
    )
    manifest = html.escape(
        json.dumps(redact(report.manifest.model_dump(mode="json"), mask_pii=mask_pii), indent=2)
    )
    template = """<!doctype html><html><head><meta charset=\"utf-8\"><title>SecGraphAI report</title>
<meta name=\"referrer\" content=\"no-referrer\"><style>body{font:16px system-ui;margin:2rem;color:#172033;max-width:1200px}
table{border-collapse:collapse;width:100%}th,td{padding:.6rem;border:1px solid #ccd3df;text-align:left}
th{background:#edf2f7}section{margin:2rem 0}pre{white-space:pre-wrap;background:#f5f7fa;padding:1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}</style></head>
<body><h1>SecGraphAI security report</h1><p>Scan: %s</p>
<section class=\"grid\"><div><h2>Executive summary</h2><ul>%s</ul></div>
<div><h2>Resources</h2><ul>%s</ul></div></section>
<section><h2>Security engineering findings</h2><table><thead><tr><th>ID</th>
<th>Severity</th><th>Verdict</th><th>Finding</th></tr></thead><tbody>%s</tbody></table></section>
<section><h2>Audit evidence</h2><h3>Limitations</h3><ul>%s</ul><h3>Manifest</h3><pre>%s</pre></section>
</body></html>"""
    for value in (
        html.escape(str(redact(report.scan_id, mask_pii=mask_pii))),
        summary,
        resources,
        "".join(rows),
        limitations,
        manifest,
    ):
        template = template.replace("%s", value, 1)
    return template


def to_markdown(report: Report, *, mask_pii: bool = False) -> str:
    def safe(value: object) -> str:
        return (
            str(redact(value, mask_pii=mask_pii))
            .replace("|", "\\|")
            .replace("\r", " ")
            .replace("\n", " ")
        )

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
    rows.extend(["", "## Resource usage", ""])
    rows.extend(f"- {safe(key)}: {value}" for key, value in report.resources().items())
    rows.extend(
        [
            "",
            "## Audit manifest",
            "",
            "```json",
            json.dumps(
                redact(report.manifest.model_dump(mode="json"), mask_pii=mask_pii), indent=2
            ),
            "```",
        ]
    )
    if report.limitations:
        rows.extend(["", "## Limitations", ""])
        rows.extend(f"- {safe(item)}" for item in report.limitations)
    return "\n".join(rows) + "\n"


def to_csv(report: Report, *, mask_pii: bool = False) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["id", "severity", "verdict", "title", "fingerprint"])
    for item in report.findings:
        writer.writerow(
            [
                redact(item.id, mask_pii=mask_pii),
                item.severity.value,
                item.verdict.value,
                redact(item.title, mask_pii=mask_pii),
                item.fingerprint or "",
            ]
        )
    return output.getvalue()


def to_jsonl(report: Report, *, mask_pii: bool = False) -> str:
    return "\n".join(
        json.dumps(
            redact(item.model_dump(mode="json"), mask_pii=mask_pii),
            sort_keys=True,
            default=str,
        )
        for item in report.findings
    ) + ("\n" if report.findings else "")


def safe_report_path(path: str | Path) -> Path:
    target = Path(path)
    if not re.fullmatch(r"[A-Za-z0-9_. -]{1,200}", target.name):
        raise ValueError("unsafe report file name")
    return target


def save(
    report: Report,
    path: str | Path,
    format: str | None = None,
    *,
    mask_pii: bool = False,
) -> None:
    target = safe_report_path(path)
    selected = format or target.suffix.removeprefix(".") or "json"
    if selected == "html":
        content = to_html(report, mask_pii=mask_pii)
    elif selected == "sarif":
        content = json.dumps(to_sarif(report), indent=2)
    elif selected in {"junit", "xml"}:
        content = to_junit(report)
    elif selected in {"md", "markdown"}:
        content = to_markdown(report, mask_pii=mask_pii)
    elif selected == "csv":
        content = to_csv(report, mask_pii=mask_pii)
    elif selected == "jsonl":
        content = to_jsonl(report, mask_pii=mask_pii)
    elif selected == "pdf":
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError("PDF output requires the pdf extra") from exc
        HTML(string=to_html(report, mask_pii=mask_pii)).write_pdf(target)
        return
    else:
        content = to_json(report, mask_pii=mask_pii)
    target.write_text(content, encoding="utf-8")
