"""Discovery and testing primitives for API, RAG, MCP, agents, and identities."""

from __future__ import annotations

import inspect
import json
import os
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from itertools import product
from typing import Any

import httpx

from secgraphai.canary import CanaryFactory
from secgraphai.security import ScopeGuard


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
            endpoints.append(
                Endpoint(
                    method.upper(),
                    path,
                    operation.get("operationId"),
                    _security_names(operation.get("security", global_security)),
                )
            )
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
    token_env: str | None = None

    def authorization(self) -> str | None:
        token = os.environ.get(self.token_env) if self.token_env else None
        return f"Bearer {token}" if token else None


@dataclass(frozen=True)
class IdentityCase:
    identity: Identity
    endpoint: Endpoint
    expected_status: frozenset[int]


def identity_matrix(
    identities: Iterable[Identity],
    endpoints: Iterable[Endpoint],
    authorize: Callable[[Identity, Endpoint], bool],
) -> list[IdentityCase]:
    return [
        IdentityCase(
            identity,
            endpoint,
            frozenset({200, 201, 204}) if authorize(identity, endpoint) else frozenset({401, 403}),
        )
        for identity, endpoint in product(identities, endpoints)
    ]


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


def load_schemathesis_schema(schema: dict[str, Any]) -> Any:
    """Load an in-memory OpenAPI document through the optional Schemathesis engine."""
    try:
        import schemathesis  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("Schemathesis integration requires the integrations extra") from exc
    return schemathesis.openapi.from_dict(schema)


@dataclass(frozen=True)
class TargetResponse:
    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    duration_ms: float = 0

    def json(self) -> Any:
        return json.loads(self.text)


class APITarget:
    """Bounded HTTP target that enforces scope before every request."""

    def __init__(
        self,
        base_url: str,
        *,
        scope_guard: ScopeGuard,
        timeout: float = 20,
        max_response_bytes: int = 2_000_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.scope_guard = scope_guard
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.transport = transport

    async def request(
        self,
        method: str,
        path: str,
        *,
        identity: Identity | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> TargetResponse:
        url = f"{self.base_url}/{path.lstrip('/')}"
        self.scope_guard.authorize(url)
        request_headers = dict(headers or {})
        if identity and identity.authorization():
            request_headers["Authorization"] = identity.authorization() or ""
        started = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, transport=self.transport
        ) as client:
            async with client.stream(
                method, url, json=json_body, headers=request_headers
            ) as response:
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise ValueError("target response exceeds configured limit")
                    chunks.append(chunk)
        return TargetResponse(
            response.status_code,
            b"".join(chunks).decode("utf-8", "replace"),
            dict(response.headers),
            (time.perf_counter() - started) * 1000,
        )


async def execute_identity_matrix(
    target: APITarget, cases: Iterable[IdentityCase]
) -> list[tuple[IdentityCase, TargetResponse]]:
    results = []
    for case in cases:
        response = await target.request(
            case.endpoint.method, case.endpoint.path, identity=case.identity
        )
        results.append((case, response))
    return results


Retriever = Callable[[str, str], Any | Awaitable[Any]]


@dataclass(frozen=True)
class RAGDocument:
    id: str
    tenant: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


class RAGTarget:
    def __init__(self, retriever: Retriever) -> None:
        self.retriever = retriever

    async def retrieve(self, query: str, tenant: str) -> list[RAGDocument]:
        value = self.retriever(query, tenant)
        raw = await value if inspect.isawaitable(value) else value
        documents = [item if isinstance(item, RAGDocument) else RAGDocument(**item) for item in raw]
        return documents

    async def cross_tenant_probe(self, requesting_tenant: str, other_tenant: str) -> bool:
        probe = RAGProbe(other_tenant)
        documents = await self.retrieve(probe.canary, requesting_tenant)
        return any(
            document.tenant != requesting_tenant or probe.canary in document.text
            for document in documents
        )


MCPTransport = Callable[[str, dict[str, Any]], dict[str, Any] | Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class MCPInventory:
    server: dict[str, Any]
    tools: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]
    prompts: tuple[dict[str, Any], ...]


class MCPClient:
    """Transport-independent MCP metadata discovery with no tool execution."""

    def __init__(self, transport: MCPTransport) -> None:
        self.transport = transport

    async def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        value = self.transport(method, params or {})
        result = await value if inspect.isawaitable(value) else value
        if not isinstance(result, dict):
            raise ValueError("MCP response must be an object")
        return result

    async def discover(self) -> MCPInventory:
        server = await self._call("initialize")
        tools = (await self._call("tools/list")).get("tools", [])
        resources = (await self._call("resources/list")).get("resources", [])
        prompts = (await self._call("prompts/list")).get("prompts", [])
        for collection in (tools, resources, prompts):
            if not isinstance(collection, list):
                raise ValueError("MCP inventory collections must be lists")
        return MCPInventory(server, tuple(tools), tuple(resources), tuple(prompts))
