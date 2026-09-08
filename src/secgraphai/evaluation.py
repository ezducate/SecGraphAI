"""Security/utility differential measurement and resource amplification budgets."""

from __future__ import annotations

from dataclasses import dataclass

from secgraphai.core import Report, Verdict


@dataclass(frozen=True)
class ResourceUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    model_calls: int = 0
    tool_calls: int = 0
    retries: int = 0
    retrieval_calls: int = 0
    external_calls: int = 0
    wall_time_seconds: float = 0
    cost_usd: float = 0

    @classmethod
    def from_report(cls, report: Report) -> ResourceUsage:
        return cls(
            input_tokens=sum(item.input_tokens for item in report.interactions),
            output_tokens=sum(item.output_tokens for item in report.interactions),
            model_calls=sum(item.model_calls for item in report.interactions),
            tool_calls=sum(item.tool_calls for item in report.interactions),
            wall_time_seconds=max(0, (report.finished_at - report.started_at).total_seconds()),
        )


@dataclass(frozen=True)
class UtilityResult:
    attack_success_rate: float
    legitimate_success_rate: float
    latency_ms: float
    cost_usd: float


@dataclass(frozen=True)
class DifferentialResult:
    security_delta: float
    utility_delta: float
    latency_delta_ms: float
    cost_delta_usd: float


def measure(
    report: Report, *, legitimate_passed: int = 0, legitimate_total: int = 0
) -> UtilityResult:
    security_tests = len(report.findings)
    violations = sum(
        item.verdict in {Verdict.VERIFIED_VIOLATION, Verdict.LIKELY_VIOLATION}
        for item in report.findings
    )
    usage = ResourceUsage.from_report(report)
    latency = sum(item.duration_ms for item in report.interactions) / max(
        1, len(report.interactions)
    )
    return UtilityResult(
        violations / max(1, security_tests),
        legitimate_passed / max(1, legitimate_total),
        latency,
        usage.cost_usd,
    )


def compare_utility(baseline: UtilityResult, candidate: UtilityResult) -> DifferentialResult:
    return DifferentialResult(
        candidate.attack_success_rate - baseline.attack_success_rate,
        candidate.legitimate_success_rate - baseline.legitimate_success_rate,
        candidate.latency_ms - baseline.latency_ms,
        candidate.cost_usd - baseline.cost_usd,
    )
