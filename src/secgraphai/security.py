"""Self-protection primitives used by scanners and reports."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|password|secret)(\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if _secret_key(str(key)) else redact(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value
    result = value
    result = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", result)
    result = _SECRET_PATTERNS[1].sub("[REDACTED]", result)
    return result


def _secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in {"api_key", "apikey", "password", "secret", "token", "authorization"}


@dataclass(frozen=True)
class Scope:
    allowed_hosts: frozenset[str] = frozenset()
    allowed_ports: frozenset[int] = frozenset({80, 443})
    blocked_networks: tuple[str, ...] = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
                                             "224.0.0.0/4", "::1/128", "fe80::/10")
    max_total_requests: int = 1000


@dataclass
class ScopeGuard:
    scope: Scope
    requests: int = 0
    _networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(init=False)

    def __post_init__(self) -> None:
        self._networks = [ipaddress.ip_network(value) for value in self.scope.blocked_networks]

    def authorize(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PermissionError("only explicit HTTP(S) targets are supported")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.hostname not in self.scope.allowed_hosts or port not in self.scope.allowed_ports:
            raise PermissionError("target is not in the explicit scan scope")
        for result in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM):
            address = ipaddress.ip_address(result[4][0])
            if any(address in network for network in self._networks):
                raise PermissionError("target resolves to a blocked network")
        if self.requests >= self.scope.max_total_requests:
            raise PermissionError("request budget exhausted")
        self.requests += 1


def doctor(config: dict[str, Any]) -> list[str]:
    problems = []
    if any(_secret_key(str(key)) and value for key, value in config.items()):
        problems.append("Store secret references in *_env fields, not secret values.")
    scope = config.get("scope", {})
    if not scope.get("allowed_hosts"):
        problems.append("No explicit target hosts are allow-listed.")
    if not scope.get("max_total_requests"):
        problems.append("No total request budget is configured.")
    dashboard = config.get("dashboard", {})
    if dashboard.get("host") not in {None, "127.0.0.1", "localhost"} and not dashboard.get("auth"):
        problems.append("A remotely bound dashboard requires authentication.")
    return problems

