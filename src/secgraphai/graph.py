"""Application security graph and risk-path analysis."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Any

import networkx as nx


class NodeType(StrEnum):
    USER = "User"
    PRINCIPAL = "Principal"
    IDENTITY = "Identity"
    SESSION = "Session"
    AGENT = "Agent"
    MODEL = "Model"
    PROMPT = "Prompt"
    MEMORY = "Memory"
    RETRIEVER = "Retriever"
    DOCUMENT = "Document"
    EMBEDDING = "Embedding"
    VECTOR_STORE = "VectorStore"
    TOOL = "Tool"
    MCP_SERVER = "MCPServer"
    MCP_RESOURCE = "MCPResource"
    API_ENDPOINT = "APIEndpoint"
    DATABASE = "Database"
    FILE = "File"
    # Graph classification label, not a credential.
    SECRET = "Secret"  # noqa: S105  # nosec B105
    DATA_ASSET = "DataAsset"
    EXTERNAL_SERVICE = "ExternalService"
    BROWSER = "Browser"
    NETWORK_BOUNDARY = "NetworkBoundary"
    COMPONENT = "Component"
    VULNERABILITY = "Vulnerability"
    POLICY = "Policy"


class EdgeType(StrEnum):
    CAN_READ = "CAN_READ"
    CAN_WRITE = "CAN_WRITE"
    CAN_CALL = "CAN_CALL"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    CAN_INFLUENCE = "CAN_INFLUENCE"
    RETRIEVES_FROM = "RETRIEVES_FROM"
    SENDS_TO = "SENDS_TO"
    RECEIVES_FROM = "RECEIVES_FROM"
    EXECUTES = "EXECUTES"
    CONTAINS = "CONTAINS"
    BELONGS_TO_TENANT = "BELONGS_TO_TENANT"
    REQUIRES_PERMISSION = "REQUIRES_PERMISSION"
    CROSSES_BOUNDARY = "CROSSES_BOUNDARY"
    AFFECTED_BY = "AFFECTED_BY"
    GUARDED_BY = "GUARDED_BY"


class SecurityGraph:
    def __init__(self) -> None:
        self._graph: nx.MultiDiGraph[Any] = nx.MultiDiGraph()

    def add_node(self, identifier: str, kind: NodeType | str, **attributes: Any) -> None:
        self._graph.add_node(identifier, kind=NodeType(kind).value, **attributes)

    def add_edge(
        self, source: str, destination: str, kind: EdgeType | str, **attributes: Any
    ) -> None:
        if source not in self._graph or destination not in self._graph:
            raise ValueError("both edge endpoints must exist")
        self._graph.add_edge(source, destination, kind=EdgeType(kind).value, **attributes)

    @property
    def nodes(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self._graph.nodes(data=True))

    @property
    def edges(self) -> list[tuple[str, str, dict[str, Any]]]:
        """Return graph edges and their attributes without exposing the backend."""
        return list(self._graph.edges(data=True))

    def paths(
        self, sources: Iterable[str], destinations: Iterable[str], cutoff: int = 8
    ) -> list[list[str]]:
        paths: list[list[str]] = []
        simple: nx.DiGraph[Any] = nx.DiGraph(self._graph)
        for source in sources:
            for destination in destinations:
                if source in simple and destination in simple:
                    paths.extend(nx.all_simple_paths(simple, source, destination, cutoff=cutoff))
        return paths

    def risk_paths(self) -> list[dict[str, Any]]:
        """Detect sensitive/external and untrusted/privileged reachability."""
        untrusted = [n for n, a in self.nodes if a.get("trust") == "untrusted"]
        privileged = [n for n, a in self.nodes if a.get("privileged") is True]
        sensitive = [
            n for n, a in self.nodes if a.get("sensitivity") in {"secret", "pii", "confidential"}
        ]
        external = [n for n, a in self.nodes if a.get("trust") == "external"]
        anonymous = [
            n
            for n, a in self.nodes
            if a.get("anonymous") is True or a.get("authentication") == "anonymous"
        ]
        protected = [n for n, a in self.nodes if a.get("protected") is True]
        low_privilege = [n for n, a in self.nodes if a.get("privilege") == "low"]
        high_privilege = [n for n, a in self.nodes if a.get("privilege") == "high"]
        tool_output = [
            n
            for n, a in self.nodes
            if a.get("kind") == NodeType.TOOL.value and a.get("produces_output", True)
        ]
        control_plane = [n for n, a in self.nodes if a.get("control_plane") is True]
        rag_content = [
            n
            for n, a in self.nodes
            if a.get("kind") in {NodeType.DOCUMENT.value, NodeType.RETRIEVER.value}
        ]
        privileged_tools = [
            n
            for n, a in self.nodes
            if a.get("kind") == NodeType.TOOL.value and a.get("privileged") is True
        ]
        tenant_nodes: dict[str, list[str]] = {}
        for node, attributes in self.nodes:
            if tenant := attributes.get("tenant"):
                tenant_nodes.setdefault(str(tenant), []).append(node)
        result: list[dict[str, Any]] = []
        for category, starts, ends in (
            ("UNTRUSTED_TO_PRIVILEGED", untrusted, privileged),
            ("SENSITIVE_TO_EXTERNAL", sensitive, external),
            ("ANONYMOUS_TO_PROTECTED", anonymous, protected),
            ("LOW_TO_HIGH_PRIVILEGE", low_privilege, high_privilege),
            ("TOOL_OUTPUT_TO_CONTROL_PLANE", tool_output, control_plane),
            ("RAG_CONTENT_TO_PRIVILEGED_TOOL", rag_content, privileged_tools),
        ):
            result.extend({"category": category, "path": path} for path in self.paths(starts, ends))
        tenants = sorted(tenant_nodes)
        for source_tenant in tenants:
            for destination_tenant in tenants:
                if source_tenant == destination_tenant:
                    continue
                result.extend(
                    {
                        "category": "CROSS_TENANT",
                        "path": path,
                        "source_tenant": source_tenant,
                        "destination_tenant": destination_tenant,
                    }
                    for path in self.paths(
                        tenant_nodes[source_tenant], tenant_nodes[destination_tenant]
                    )
                )
        simple: nx.DiGraph[Any] = nx.DiGraph(self._graph)
        result.extend(
            {"category": "EXECUTION_CYCLE", "path": cycle + [cycle[0]]}
            for cycle in nx.simple_cycles(simple, length_bound=8)
        )
        return result

    def features(self) -> frozenset[str]:
        features = {attributes["kind"].casefold() for _, attributes in self.nodes}
        if (
            len(
                {
                    attributes.get("tenant")
                    for _, attributes in self.nodes
                    if attributes.get("tenant")
                }
            )
            > 1
        ):
            features.add("multiple-tenants")
        if self.risk_paths():
            features.add("risk-path")
        return frozenset(features)

    def attack_paths(self) -> list[dict[str, Any]]:
        return [
            {
                **item,
                "length": len(item["path"]),
                "score": round(1 / max(1, len(item["path"]) - 1), 3),
            }
            for item in self.risk_paths()
        ]

    def to_dict(self) -> dict[str, Any]:
        return nx.node_link_data(self._graph, edges="edges")
