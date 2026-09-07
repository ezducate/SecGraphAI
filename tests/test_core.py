from secgraphai import Evidence, Finding, Report, Severity, Verdict


def test_error_is_never_pass():
    assert not Verdict.TEST_ERROR.passed
    report = Report(scan_id="scan", errors=["timeout"])
    assert report.summary()["TEST_ERROR"] == 1


def test_models_are_immutable():
    finding = Finding(id="SG-1", title="x", severity=Severity.HIGH,
                      verdict=Verdict.VERIFIED_VIOLATION, confidence=1,
                      evidence=[Evidence(kind="canary", description="observed")])
    assert finding.verdict is Verdict.VERIFIED_VIOLATION

