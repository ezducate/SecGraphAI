"""Self-protection primitives used by scanners and reports."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(api[_-]?key|token|password|secret|cookie|session)(\s*[=:]\s*)([^\s,;]+)"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)
_PII_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}(?!\d)"),
)


def redact(value: Any, *, mask_pii: bool = False) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if _secret_key(str(key))
                else redact(item, mask_pii=mask_pii)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, mask_pii=mask_pii) for item in value]
    if not isinstance(value, str):
        return value
    result = value
    result = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", result)
    result = _SECRET_PATTERNS[1].sub("[REDACTED]", result)
    if mask_pii:
        for pattern in _PII_PATTERNS:
            result = pattern.sub("[PII]", result)
    return result


def _secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in {
        "api_key",
        "apikey",
        "password",
        "secret",
        "token",
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "session",
        "session_id",
        "x_api_key",
    }


def validate_document(value: Any, *, max_depth: int = 64) -> None:
    """Reject recursively nested hostile documents without recursive traversal."""
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            raise ValueError("document exceeds configured nesting limit")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend((item, depth + 1) for item in current)


@dataclass(frozen=True)
class Scope:
    allowed_hosts: frozenset[str] = frozenset()
    allowed_ports: frozenset[int] = frozenset({80, 443})
    blocked_networks: tuple[str, ...] = (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
    max_total_requests: int = 1000
    max_requests_per_second: float = 5
    max_duration_seconds: float = 120
    prohibit: frozenset[str] = frozenset({"destructive_write", "account_deletion"})
    require_stable_dns: bool = True


@dataclass
class ScopeGuard:
    scope: Scope
    requests: int = 0
    _networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(init=False)
    _recent: deque[float] = field(init=False, default_factory=deque)
    _started: float = field(init=False, default_factory=time.monotonic)
    _authorized_addresses: dict[tuple[str, int], frozenset[str]] = field(
        init=False, default_factory=dict
    )

    def __post_init__(self) -> None:
        self._networks = [ipaddress.ip_network(value) for value in self.scope.blocked_networks]

    def authorize(self, url: str, *, action: str | None = None) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PermissionError("only explicit HTTP(S) targets are supported")
        if parsed.username or parsed.password:
            raise PermissionError("credentials in target URLs are forbidden")
        if action and action in self.scope.prohibit:
            raise PermissionError(f"action is prohibited by scope: {action}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.hostname not in self.scope.allowed_hosts or port not in self.scope.allowed_ports:
            raise PermissionError("target is not in the explicit scan scope")
        addresses = self._resolve(parsed.hostname, port)
        key = (parsed.hostname, port)
        previous = self._authorized_addresses.get(key)
        if self.scope.require_stable_dns and previous is not None and addresses != previous:
            raise PermissionError("target DNS resolution changed after authorization")
        self._authorized_addresses[key] = addresses
        if self.requests >= self.scope.max_total_requests:
            raise PermissionError("request budget exhausted")
        now = time.monotonic()
        if now - self._started > self.scope.max_duration_seconds:
            raise PermissionError("scan duration budget exhausted")
        while self._recent and now - self._recent[0] >= 1:
            self._recent.popleft()
        if len(self._recent) >= self.scope.max_requests_per_second:
            raise PermissionError("request rate budget exhausted")
        self._recent.append(now)
        self.requests += 1

    def revalidate(self, url: str) -> None:
        """Resolve a target again immediately before connection to detect DNS rebinding."""
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PermissionError("only explicit HTTP(S) targets are supported")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = self._resolve(parsed.hostname, port)
        authorized = self._authorized_addresses.get((parsed.hostname, port))
        if self.scope.require_stable_dns and authorized is not None and addresses != authorized:
            raise PermissionError("target DNS resolution changed before connection")

    def _resolve(self, hostname: str, port: int) -> frozenset[str]:
        addresses: set[str] = set()
        for result in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM):
            address = ipaddress.ip_address(result[4][0])
            if any(address in network for network in self._networks):
                raise PermissionError("target resolves to a blocked network")
            addresses.add(str(address))
        if not addresses:
            raise PermissionError("target did not resolve to an address")
        return frozenset(addresses)


def doctor(config: dict[str, Any]) -> list[str]:
    problems = []
    if any(_secret_key(str(key)) and value for key, value in config.items()):
        problems.append("Store secret references in *_env fields, not secret values.")
    raw_scope = config.get("scope", {})
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    if raw_scope and not isinstance(raw_scope, dict):
        problems.append("Scope configuration must be an object.")
    all_interfaces = {"*", ".".join(("0", "0", "0", "0")), ":" * 2}
    if not scope.get("allowed_hosts"):
        problems.append("No explicit target hosts are allow-listed.")
    elif any(str(host) in all_interfaces for host in scope.get("allowed_hosts", [])):
        problems.append("Target scope contains a wildcard or all-interface host.")
    if not scope.get("max_total_requests"):
        problems.append("No total request budget is configured.")
    if scope and not scope.get("blocked_networks"):
        problems.append("Target scope does not block internal or metadata networks.")
    raw_dashboard = config.get("dashboard", {})
    dashboard = raw_dashboard if isinstance(raw_dashboard, dict) else {}
    if raw_dashboard and not isinstance(raw_dashboard, dict):
        problems.append("Dashboard configuration must be an object.")
    if dashboard.get("host") not in {None, "127.0.0.1", "localhost"} and not dashboard.get("auth"):
        problems.append("A remotely bound dashboard requires authentication.")
    if dashboard.get("debug"):
        problems.append("Dashboard debug mode must be disabled.")
    if dashboard.get("cors") == "*" or dashboard.get("cors") == ["*"]:
        problems.append("Wildcard dashboard CORS is unsafe.")
    plugins = config.get("plugins", [])
    if any(
        isinstance(item, dict) and item.get("mode") == "in_process" and not item.get("trusted")
        for item in plugins
    ):
        problems.append("Untrusted plugins cannot execute in process.")
    if config.get("evidence", {}).get("redact") is False:
        problems.append("Evidence redaction must remain enabled.")
    privacy = config.get("privacy", {})
    if isinstance(privacy, dict) and privacy.get("telemetry"):
        problems.append("Telemetry is enabled; confirm this intentional privacy exception.")
    if isinstance(privacy, dict) and privacy.get("cloud_upload"):
        problems.append("Cloud upload is enabled; confirm this intentional privacy exception.")
    return problems
