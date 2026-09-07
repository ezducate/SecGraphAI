"""Application security graph and risk-path analysis."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Iterable

import networkx as nx


class NodeType(StrEnum):
    USER = "User"
    IDENTITY = "Identity"
    AGENT = "Agent"
    MODEL = "Model"
    PROMPT = "Prompt"
    MEMORY = "Memory"
    RETRIEVER = "Retriever"
    DOCUMENT = "Document"
    VECTOR_STORE = "VectorStore"
    TOOL = "Tool"
    MCP_SERVER = "MCPServer"
    API_ENDPOINT = "APIEndpoint"
    DATABASE = "Database"
    SECRET = "Secret"
    DATA_ASSET = "DataAsset"
    EXTERNAL_SERVICE = "ExternalService"
    NETWORK_BOUNDARY = "NetworkBoundary"


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


class SecurityGraph:
    def __init__(self) -> None:
        self._graph = nx.MultiDiGraph()

    def add_node(self, identifier: str, kind: NodeType | str, **attributes: Any) -> None:
        self._graph.add_node(identifier, kind=NodeType(kind).value, **attributes)

    def add_edge(self, source: str, destination: str, kind: EdgeType | str,
                 **attributes: Any) -> None:
        if source not in self._graph or destination not in self._graph:
            raise ValueError("both edge endpoints must exist")
        self._graph.add_edge(source, destination, kind=EdgeType(kind).value, **attributes)

    @property
    def nodes(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self._graph.nodes(data=True))

    def paths(self, sources: Iterable[str], destinations: Iterable[str], cutoff: int = 8) -> list[list[str]]:
        paths: list[list[str]] = []
        simple = nx.DiGraph(self._graph)
        for source in sources:
            for destination in destinations:
                if source in simple and destination in simple:
                    paths.extend(nx.all_simple_paths(simple, source, destination, cutoff=cutoff))
        return paths

    def risk_paths(self) -> list[dict[str, Any]]:
        """Detect sensitive/external and untrusted/privileged reachability."""
        untrusted = [n for n, a in self.nodes if a.get("trust") == "untrusted"]
        privileged = [n for n, a in self.nodes if a.get("privileged") is True]
        sensitive = [n for n, a in self.nodes if a.get("sensitivity") in {"secret", "pii", "confidential"}]
        external = [n for n, a in self.nodes if a.get("trust") == "external"]
        result = []
        for category, starts, ends in (
            ("UNTRUSTED_TO_PRIVILEGED", untrusted, privileged),
            ("SENSITIVE_TO_EXTERNAL", sensitive, external),
        ):
            result.extend({"category": category, "path": path} for path in self.paths(starts, ends))
        return result

    def to_dict(self) -> dict[str, Any]:
        return nx.node_link_data(self._graph, edges="edges")

