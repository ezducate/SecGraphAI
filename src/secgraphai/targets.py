"""Discovery and testing primitives for API, RAG, MCP, agents, and identities."""

from __future__ import annotations

import hashlib
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
from secgraphai.config import Mode
from secgraphai.security import ScopeGuard, validate_document


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
    max_json_depth: int = 64

    def json(self) -> Any:
        try:
            value = json.loads(self.text)
        except RecursionError as exc:
            raise ValueError("target JSON exceeds nesting limit") from exc
        validate_document(value, max_depth=self.max_json_depth)
        return value


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
        mode: Mode | str = Mode.SAFE,
        allowed_actions: Iterable[str] = (),
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.scope_guard = scope_guard
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.transport = transport
        self.mode = Mode(mode)
        self.allowed_actions = frozenset(allowed_actions)

    async def request(
        self,
        method: str,
        path: str,
        *,
        identity: Identity | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        action: str | None = None,
    ) -> TargetResponse:
        url = f"{self.base_url}/{path.lstrip('/')}"
        normalized_method = method.upper()
        classified_action = action or {
            "GET": "read",
            "HEAD": "metadata_discovery",
            "OPTIONS": "metadata_discovery",
            "DELETE": "destructive_write",
        }.get(normalized_method, "active_write")
        if self.mode == Mode.PASSIVE and classified_action != "metadata_discovery":
            raise PermissionError("PASSIVE mode permits metadata discovery only")
        if self.mode == Mode.SAFE and classified_action in {
            "active_write",
            "destructive_write",
            "account_deletion",
            "external_side_effect",
        }:
            raise PermissionError(f"SAFE mode blocks action: {classified_action}")
        if (
            self.mode == Mode.CUSTOM
            and classified_action not in self.allowed_actions
            and classified_action != "metadata_discovery"
        ):
            raise PermissionError(f"CUSTOM mode does not allow action: {classified_action}")
        self.scope_guard.authorize(url, action=classified_action)
        request_headers = dict(headers or {})
        if identity and identity.authorization():
            request_headers["Authorization"] = identity.authorization() or ""
        started = time.perf_counter()
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, transport=self.transport
        ) as client:
            revalidate = getattr(self.scope_guard, "revalidate", None)
            if callable(revalidate):
                revalidate(url)
            async with client.stream(
                normalized_method, url, json=json_body, headers=request_headers
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
    def __init__(
        self,
        retriever: Retriever,
        *,
        writer: Callable[[RAGDocument], Any | Awaitable[Any]] | None = None,
        deleter: Callable[[str, str], Any | Awaitable[Any]] | None = None,
        configuration: dict[str, Any] | None = None,
        max_documents: int = 1_000,
        max_document_chars: int = 1_000_000,
    ) -> None:
        self.retriever = retriever
        self.writer = writer
        self.deleter = deleter
        self.configuration = dict(configuration or {})
        self.max_documents = max_documents
        self.max_document_chars = max_document_chars

    async def retrieve(self, query: str, tenant: str) -> list[RAGDocument]:
        value = self.retriever(query, tenant)
        raw = await value if inspect.isawaitable(value) else value
        if not isinstance(raw, (list, tuple)):
            raise ValueError("RAG retrieval response must be a list")
        if len(raw) > self.max_documents:
            raise ValueError("RAG retrieval response exceeds document limit")
        documents = [item if isinstance(item, RAGDocument) else RAGDocument(**item) for item in raw]
        if any(len(item.text) > self.max_document_chars for item in documents):
            raise ValueError("RAG document exceeds configured character limit")
        return documents

    async def cross_tenant_probe(self, requesting_tenant: str, other_tenant: str) -> bool:
        probe = RAGProbe(other_tenant)
        documents = await self.retrieve(probe.canary, requesting_tenant)
        return any(
            document.tenant != requesting_tenant or probe.canary in document.text
            for document in documents
        )

    async def insert(self, document: RAGDocument) -> None:
        if self.writer is None:
            raise RuntimeError("RAG target does not provide a safe document writer")
        value = self.writer(document)
        if inspect.isawaitable(value):
            await value

    async def delete(self, document_id: str, tenant: str) -> None:
        if self.deleter is None:
            raise RuntimeError("RAG target does not provide a safe document deleter")
        value = self.deleter(document_id, tenant)
        if inspect.isawaitable(value):
            await value


MCPTransport = Callable[[str, dict[str, Any]], dict[str, Any] | Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class MCPInventory:
    server: dict[str, Any]
    tools: tuple[dict[str, Any], ...]
    resources: tuple[dict[str, Any], ...]
    prompts: tuple[dict[str, Any], ...]

    def fingerprint(self) -> str:
        payload = json.dumps(
            {
                "server": self.server,
                "tools": self.tools,
                "resources": self.resources,
                "prompts": self.prompts,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
        return hashlib.sha256(payload).hexdigest()


class MCPClient:
    """Transport-independent MCP metadata discovery with no tool execution."""

    def __init__(self, transport: MCPTransport, *, max_response_bytes: int = 2_000_000) -> None:
        self.transport = transport
        self.max_response_bytes = max_response_bytes

    async def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        value = self.transport(method, params or {})
        result = await value if inspect.isawaitable(value) else value
        if not isinstance(result, dict):
            raise ValueError("MCP response must be an object")
        if len(json.dumps(result, default=str).encode()) > self.max_response_bytes:
            raise ValueError("MCP response exceeds configured limit")
        validate_document(result, max_depth=64)
        return result

    async def discover(self) -> MCPInventory:
        server = await self._call("initialize")
        tools = (await self._call("tools/list")).get("tools", [])
        resources = (await self._call("resources/list")).get("resources", [])
        prompts = (await self._call("prompts/list")).get("prompts", [])
        for collection in (tools, resources, prompts):
            if not isinstance(collection, list) or not all(
                isinstance(item, dict) for item in collection
            ):
                raise ValueError("MCP inventory collections must be lists of objects")
        return MCPInventory(server, tuple(tools), tuple(resources), tuple(prompts))
