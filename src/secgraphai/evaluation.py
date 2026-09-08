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
            retries=sum(item.retries for item in report.interactions),
            retrieval_calls=sum(item.retrieval_calls for item in report.interactions),
            external_calls=sum(item.external_calls for item in report.interactions),
            wall_time_seconds=max(0, (report.finished_at - report.started_at).total_seconds()),
            cost_usd=sum(item.cost_usd for item in report.interactions),
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


@dataclass(frozen=True)
class ResourceAmplification:
    metric: str
    baseline: float
    observed: float
    ratio: float


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


def detect_amplification(
    baseline: ResourceUsage,
    observed: ResourceUsage,
    *,
    max_ratio: float = 3,
    minimum_increase: float = 1,
) -> list[ResourceAmplification]:
    """Return resource dimensions whose growth exceeds both relative and absolute limits."""
    if max_ratio <= 1 or minimum_increase < 0:
        raise ValueError("amplification thresholds are invalid")
    alerts = []
    for metric in (
        "input_tokens",
        "output_tokens",
        "model_calls",
        "tool_calls",
        "retries",
        "retrieval_calls",
        "external_calls",
        "wall_time_seconds",
        "cost_usd",
    ):
        before = float(getattr(baseline, metric))
        after = float(getattr(observed, metric))
        ratio = after / before if before > 0 else (float("inf") if after > 0 else 1.0)
        if after - before >= minimum_increase and ratio > max_ratio:
            alerts.append(ResourceAmplification(metric, before, after, ratio))
    return alerts
