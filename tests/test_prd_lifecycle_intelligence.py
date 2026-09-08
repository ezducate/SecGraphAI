from __future__ import annotations

import zipfile

import pytest

from secgraphai.core import Evidence, Finding, Report, Severity, Verdict
from secgraphai.intelligence import (
    Component,
    Reachability,
    Vulnerability,
    VulnerabilityCache,
    affected,
    enrich_known_exploited,
    generate_cyclonedx,
    generate_spdx,
    parse_cyclonedx,
    parse_nvd,
    parse_spdx,
)
from secgraphai.lifecycle import BaselineStore, finalize_report, load_replay, save_replay
from secgraphai.reporting import save, to_csv, to_jsonl, to_markdown


def report():
    return Report(
        scan_id="scan",
        findings=[
            Finding(
                id="SG-1",
                title="hostile | <script>",
                severity=Severity.HIGH,
                verdict=Verdict.VERIFIED_VIOLATION,
                confidence=1,
                evidence=[Evidence(kind="test", description="evidence")],
            )
        ],
    )


def test_finalize_hashes_and_all_text_formats(tmp_path):
    value = finalize_report(report(), configuration={"api_key": "secret"}, policies=[{"id": "p"}])
    assert value.findings[0].fingerprint and len(value.manifest.artifact_hashes) >= 8
    assert value.findings[0].evidence[0].sha256
    assert "\\|" in to_markdown(value) and "SG-1" in to_csv(value) and "SG-1" in to_jsonl(value)
    for suffix in ("json", "html", "md", "csv", "jsonl", "sarif", "xml"):
        path = tmp_path / f"report.{suffix}"
        save(value, path)
        assert path.stat().st_size > 0


def test_replay_bundle_hash_validation(tmp_path):
    path = tmp_path / "scan.secgraph"
    save_replay(report(), path, {"token": "secret"}, configuration={"mode": "SAFE"})
    loaded, inputs = load_replay(path)
    assert loaded.scan_id == "scan" and inputs["token"] == "[REDACTED]"
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("inputs.json", "{}")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_replay(path)


def test_baseline_names_are_confined(tmp_path):
    store = BaselineStore(tmp_path)
    store.save("release-1.0", report())
    assert store.load("release-1.0").scan_id == "scan"
    with pytest.raises(ValueError):
        store.save("../escape", report())


def test_nvd_parsing_and_version_correlation():
    document = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0001",
                    "descriptions": [{"lang": "en", "value": "issue"}],
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "metrics": {
                        "cvssMetricV40": [
                            {
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": "CVSS:4.0/AV:N",
                                    "baseScore": 9.3,
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://example.test"}],
                }
            }
        ]
    }
    vulnerability = parse_nvd(document)[0]
    assert vulnerability.cvss[0].version == "4.0" and vulnerability.cwe_ids == {"CWE-79"}
    vulnerable = Vulnerability("CVE-X", "demo", 8, affected_versions=("<2.0",))
    assert affected(Component("demo", "1.5"), vulnerable) is True
    assert affected(Component("demo", "2.5"), vulnerable) is False


def test_cyclonedx_and_transactional_cache(tmp_path):
    components = [Component("demo", "1.0", "pkg:pypi/demo@1.0")]
    assert parse_cyclonedx(generate_cyclonedx(components))[0].name == "demo"
    cache = VulnerabilityCache(tmp_path / "data" / "cve.json")
    cache.save([Vulnerability("CVE-1", "demo", 9, status=Reachability.AFFECTED)])
    assert cache.search("demo")[0].status == Reachability.AFFECTED


def test_spdx_roundtrip_and_offline_kev_enrichment():
    components = [
        Component("demo", "1.0", "pkg:pypi/demo@1.0", cpe="cpe:2.3:a:demo:demo:1.0:*:*:*:*:*:*:*")
    ]
    assert parse_spdx(generate_spdx(components))[0] == components[0]
    enriched = enrich_known_exploited(
        [Vulnerability("CVE-1", "demo", 5)],
        {"vulnerabilities": [{"cveID": "CVE-1"}]},
    )
    assert enriched[0].known_exploited is True
