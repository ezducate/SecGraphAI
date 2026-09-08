"""Framework-neutral automatic instrumentation and OpenTelemetry-compatible tracing."""

from __future__ import annotations

import functools
import inspect
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

from secgraphai.runtime import SecurityContext, current_context, get_context

F = TypeVar("F", bound=Callable[..., Any])


@dataclass(frozen=True)
class TraceEvent:
    trace_id: str
    kind: str
    name: str
    started_at: float
    duration_ms: float
    success: bool
    metadata: dict[str, Any] = field(default_factory=dict)


class TraceRecorder:
    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def record(self, event: TraceEvent) -> None:
        self.events.append(event)
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            if span.is_recording():
                span.add_event(
                    f"secgraph.{event.kind}",
                    attributes={
                        "secgraph.name": event.name,
                        "secgraph.success": event.success,
                        "secgraph.duration_ms": event.duration_ms,
                    },
                )
        except ImportError:
            pass


def instrument(
    target: F,
    *,
    kind: str = "callable",
    recorder: TraceRecorder | None = None,
    metadata: dict[str, Any] | None = None,
) -> F:
    recorder = recorder or TraceRecorder()
    details = dict(metadata or {})

    def finish(started: float, ok: bool) -> None:
        ctx = get_context()
        trace_id = ctx.trace_id or uuid.uuid4().hex
        recorder.record(
            TraceEvent(
                trace_id,
                kind,
                getattr(target, "__name__", type(target).__name__),
                started,
                (time.perf_counter() - started) * 1000,
                ok,
                details,
            )
        )

    if inspect.iscoroutinefunction(target):

        @functools.wraps(target)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            try:
                result = await target(*args, **kwargs)
            except Exception:
                finish(started, False)
                raise
            finish(started, True)
            return result

        cast(Any, async_wrapper).__secgraph_recorder__ = recorder
        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(target)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        started = time.perf_counter()
        try:
            result = target(*args, **kwargs)
        except Exception:
            finish(started, False)
            raise
        finish(started, True)
        return result

    cast(Any, sync_wrapper).__secgraph_recorder__ = recorder
    return sync_wrapper  # type: ignore[return-value]


def instrument_fastapi(app: Any, recorder: TraceRecorder | None = None) -> TraceRecorder:
    recorder = recorder or TraceRecorder()

    @app.middleware("http")
    async def secgraph_trace(request: Any, call_next: Callable[..., Any]) -> Any:
        started = time.perf_counter()
        trace_id = request.headers.get("x-request-id", uuid.uuid4().hex)
        token = current_context.set(SecurityContext(trace_id=trace_id))
        try:
            response = await call_next(request)
            recorder.record(
                TraceEvent(
                    trace_id,
                    "fastapi",
                    request.url.path,
                    started,
                    (time.perf_counter() - started) * 1000,
                    response.status_code < 500,
                    {"method": request.method, "status": response.status_code},
                )
            )
            response.headers["X-SecGraph-Trace"] = trace_id
            return response
        finally:
            current_context.reset(token)

    return recorder


def httpx_event_hooks(recorder: TraceRecorder | None = None) -> dict[str, list[Callable[..., Any]]]:
    recorder = recorder or TraceRecorder()

    async def request_hook(request: Any) -> None:
        request.extensions["secgraph_started"] = time.perf_counter()

    async def response_hook(response: Any) -> None:
        started = response.request.extensions.get("secgraph_started", time.perf_counter())
        recorder.record(
            TraceEvent(
                uuid.uuid4().hex,
                "httpx",
                str(response.request.url),
                started,
                (time.perf_counter() - started) * 1000,
                response.status_code < 500,
                {"method": response.request.method, "status": response.status_code},
            )
        )

    return {"request": [request_hook], "response": [response_hook]}


def instrument_openai(client: Any, recorder: TraceRecorder | None = None) -> Any:
    if not hasattr(client, "chat") or not hasattr(client.chat, "completions"):
        raise TypeError("client does not expose chat.completions")
    client.chat.completions.create = instrument(
        client.chat.completions.create, kind="openai", recorder=recorder
    )
    return client


def instrument_mcp(call: F, recorder: TraceRecorder | None = None) -> F:
    return instrument(call, kind="mcp", recorder=recorder)


def instrument_langchain(call: F, recorder: TraceRecorder | None = None) -> F:
    return instrument(call, kind="langchain", recorder=recorder)


def instrument_langgraph(call: F, recorder: TraceRecorder | None = None) -> F:
    return instrument(call, kind="langgraph", recorder=recorder)
