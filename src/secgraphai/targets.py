"""Discovery and testing primitives for API, RAG, MCP, agents, and identities."""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from typing import Any, Callable, Iterable

from secgraphai.canary import CanaryFactory


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    operation_id: str | None = None
    security: tuple[str, ...] = ()


def discover_openapi(document: dict[str, Any]) -> list[Endpoint]:
    """Parse operations without resolving remote references or executing code."""
    endpoints = []
    global_security = _security_names(document.get("security", []))
    for path, item in document.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in {"get", "put", "post", "delete", "patch", "head", "options"}:
                continue
            operation = operation if isinstance(operation, dict) else {}
            endpoints.append(Endpoint(method.upper(), path, operation.get("operationId"),
                                      _security_names(operation.get("security", global_security))))
    return endpoints


def _security_names(items: Any) -> tuple[str, ...]:
    if isinstance(items, tuple):
        return items
    return tuple(sorted({name for item in items if isinstance(item, dict) for name in item}))


@dataclass(frozen=True)
class Identity:
    name: str
    tenant: str | None = None
    roles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class IdentityCase:
    identity: Identity
    endpoint: Endpoint
    expected_status: frozenset[int]


def identity_matrix(identities: Iterable[Identity], endpoints: Iterable[Endpoint],
                    authorize: Callable[[Identity, Endpoint], bool]) -> list[IdentityCase]:
    return [IdentityCase(identity, endpoint,
                         frozenset({200, 201, 204}) if authorize(identity, endpoint)
                         else frozenset({401, 403}))
            for identity, endpoint in product(identities, endpoints)]


@dataclass
class RAGProbe:
    tenant: str
    canary: str = field(init=False)

    def __post_init__(self) -> None:
        self.canary = CanaryFactory().record(tenant=self.tenant).value

    def detect_cross_tenant(self, output: str, output_tenant: str) -> bool:
        return output_tenant != self.tenant and self.canary in output


@dataclass(frozen=True)
class MCPTool:
    name: str
    description: str
    permissions: frozenset[str] = frozenset()


def audit_mcp_tools(tools: Iterable[dict[str, Any]]) -> list[str]:
    problems = []
    seen: set[str] = set()
    for tool in tools:
        name = str(tool.get("name", ""))
        if not name or name in seen:
            problems.append(f"invalid or duplicate tool name: {name!r}")
        seen.add(name)
        if not tool.get("description"):
            problems.append(f"tool {name!r} has no description")
        if tool.get("inputSchema", {}).get("additionalProperties", True):
            problems.append(f"tool {name!r} accepts undeclared properties")
    return problems


def schemathesis_cases(schema: dict[str, Any]) -> list[dict[str, str]]:
    """Return Schemathesis-compatible operation selectors without requiring its extra."""
    return [{"method": item.method, "path": item.path} for item in discover_openapi(schema)]
