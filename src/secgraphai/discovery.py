"""Non-importing local and explicitly scoped remote architecture discovery."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from secgraphai.graph import EdgeType, NodeType, SecurityGraph
from secgraphai.security import Scope, ScopeGuard
from secgraphai.targets import APITarget, Endpoint, discover_openapi

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "options", "head"})


@dataclass(frozen=True)
class DiscoveredComponent:
    id: str
    kind: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DiscoveryInventory:
    components: list[DiscoveredComponent] = field(default_factory=list)

    def add(self, component: DiscoveredComponent) -> None:
        if component.id not in {item.id for item in self.components}:
            self.components.append(component)

    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for item in self.components:
            result[item.kind] = result.get(item.kind, 0) + 1
        return dict(sorted(result.items()))

    def to_graph(self) -> SecurityGraph:
        graph = SecurityGraph()
        kind_map = {
            "agent": NodeType.AGENT,
            "tool": NodeType.TOOL,
            "retriever": NodeType.RETRIEVER,
            "model": NodeType.MODEL,
            "mcp_server": NodeType.MCP_SERVER,
            "api": NodeType.API_ENDPOINT,
            "identity": NodeType.IDENTITY,
            "vector_store": NodeType.VECTOR_STORE,
            "external_service": NodeType.EXTERNAL_SERVICE,
            "trust_boundary": NodeType.NETWORK_BOUNDARY,
        }
        for item in self.components:
            kind = kind_map.get(item.kind)
            if kind is not None:
                metadata = {key: value for key, value in item.metadata.items() if key != "kind"}
                graph.add_node(item.id, kind, source=item.source, **metadata)
        agents = [item.id for item in self.components if item.kind == "agent"]
        callable_nodes = [
            item.id for item in self.components if item.kind in {"tool", "retriever", "model"}
        ]
        for agent in agents:
            for target in callable_nodes:
                graph.add_edge(agent, target, EdgeType.CAN_CALL)
        return graph


def discover_path(path: str | Path) -> DiscoveryInventory:
    """Discover Python decorators, framework routes, annotations, and local manifests."""
    root = Path(path)
    if not root.exists():
        raise ValueError("discovery path does not exist")
    inventory = DiscoveryInventory()
    files = [root] if root.is_file() else list(root.rglob("*"))
    for file in files:
        if file.suffix == ".py":
            _discover_python(file, inventory)
        elif file.suffix.casefold() in {".yaml", ".yml", ".json"}:
            try:
                within_limit = file.stat().st_size <= 2_000_000
            except OSError:
                within_limit = False
            if within_limit:
                _discover_manifest(file, inventory)
    return inventory


def _discover_python(path: Path, inventory: DiscoveryInventory) -> None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                expression = decorator.func if isinstance(decorator, ast.Call) else decorator
                kind = _call_name(expression).casefold()
                if kind in {"agent", "tool", "retriever"}:
                    inventory.add(
                        DiscoveredComponent(
                            f"python:{path}:{node.name}", kind, str(path), {"function": node.name}
                        )
                    )
                elif kind in HTTP_METHODS:
                    route = _first_string_argument(decorator) or f"/{node.name}"
                    inventory.add(
                        DiscoveredComponent(
                            f"api:{kind.upper()}:{route}",
                            "api",
                            str(path),
                            {"method": kind.upper(), "path": route},
                        )
                    )
                elif kind in {"field", "mutation", "subscription"}:
                    inventory.add(
                        DiscoveredComponent(
                            f"api:GRAPHQL:{node.name}",
                            "api",
                            str(path),
                            {"protocol": "graphql", "operation": kind, "field": node.name},
                        )
                    )
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                annotation = ast.unparse(argument.annotation) if argument.annotation else ""
                normalized = annotation.casefold()
                for marker, discovered_kind in {
                    "identity": "identity",
                    "principal": "identity",
                    "tool": "tool",
                    "retriever": "retriever",
                    "model": "model",
                }.items():
                    if "annotated" in normalized and marker in normalized:
                        inventory.add(
                            DiscoveredComponent(
                                f"annotation:{path}:{node.name}:{argument.arg}:{discovered_kind}",
                                discovered_kind,
                                str(path),
                                {"function": node.name, "parameter": argument.arg},
                            )
                        )
        elif isinstance(node, ast.Call):
            name = _call_name(node.func).casefold()
            inferred = {
                "model": "model",
                "ragtarget": "retriever",
                "mcpclient": "mcp_server",
                "chroma": "vector_store",
                "faiss": "vector_store",
            }.get(name)
            if inferred:
                inventory.add(
                    DiscoveredComponent(
                        f"python:{path}:{node.lineno}:{inferred}", inferred, str(path)
                    )
                )


def _discover_manifest(path: Path, inventory: DiscoveryInventory) -> None:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError):
        return
    if not isinstance(raw, dict):
        return
    if isinstance(raw.get("paths"), dict):
        for endpoint in discover_openapi(raw):
            _add_endpoint(endpoint, str(path), inventory)
    for key, kind in {
        "models": "model",
        "agents": "agent",
        "tools": "tool",
        "retrievers": "retriever",
        "mcp_servers": "mcp_server",
        "identities": "identity",
        "vector_stores": "vector_store",
        "external_services": "external_service",
        "trust_boundaries": "trust_boundary",
    }.items():
        values = raw.get(key, [])
        if isinstance(values, dict):
            values = [
                {"id": name, **(value if isinstance(value, dict) else {})}
                for name, value in values.items()
            ]
        if isinstance(values, list):
            for index, value in enumerate(values):
                metadata = value if isinstance(value, dict) else {"value": value}
                identifier = str(metadata.get("id") or metadata.get("name") or index)
                inventory.add(
                    DiscoveredComponent(f"{kind}:{identifier}", kind, str(path), dict(metadata))
                )
    graphql = raw.get("graphql")
    if isinstance(graphql, dict):
        for operation, fields in graphql.items():
            if isinstance(fields, list):
                for field_name in fields:
                    inventory.add(
                        DiscoveredComponent(
                            f"api:GRAPHQL:{field_name}",
                            "api",
                            str(path),
                            {
                                "protocol": "graphql",
                                "operation": str(operation),
                                "field": str(field_name),
                            },
                        )
                    )
    traces = raw.get("http_traces", [])
    if isinstance(traces, list):
        for trace in traces:
            if not isinstance(trace, dict):
                continue
            url = urlsplit(str(trace.get("url", "")))
            if url.hostname:
                inventory.add(
                    DiscoveredComponent(
                        f"external:{url.hostname}",
                        "external_service",
                        str(path),
                        {"host": url.hostname, "trust": "external"},
                    )
                )


async def discover_url(
    url: str,
    *,
    allow_private: bool = False,
    max_response_bytes: int = 2_000_000,
) -> DiscoveryInventory:
    """Fetch OpenAPI only from the exact explicitly supplied, scope-checked host."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("remote discovery requires an explicit HTTP(S) URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scope = Scope(
        allowed_hosts=frozenset({parsed.hostname}),
        allowed_ports=frozenset({port}),
        blocked_networks=() if allow_private else Scope().blocked_networks,
        max_total_requests=1,
    )
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    target = APITarget(
        base_url,
        scope_guard=ScopeGuard(scope),
        max_response_bytes=max_response_bytes,
    )
    response = await target.request("GET", parsed.path or "/openapi.json")
    if response.status_code != 200:
        raise RuntimeError(f"OpenAPI discovery returned HTTP {response.status_code}")
    document = response.json()
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document must be an object")
    inventory = DiscoveryInventory()
    for endpoint in discover_openapi(document):
        _add_endpoint(endpoint, url, inventory)
    return inventory


def _add_endpoint(endpoint: Endpoint, source: str, inventory: DiscoveryInventory) -> None:
    inventory.add(
        DiscoveredComponent(
            f"api:{endpoint.method}:{endpoint.path}",
            "api",
            source,
            {
                "method": endpoint.method,
                "path": endpoint.path,
                "operation_id": endpoint.operation_id,
                "security": list(endpoint.security),
                "protected": bool(endpoint.security),
            },
        )
    )


def _first_string_argument(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
        value = node.args[0].value
        return value if isinstance(value, str) else None
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""
