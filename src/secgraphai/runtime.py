"""Runtime metadata, context, decorators, and policy aspects."""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

from secgraphai.policy import Effect, PolicyEngine
from secgraphai.security import redact


@dataclass(frozen=True)
class Sensitive:
    classification: str = "sensitive"


@dataclass
class SecurityContext:
    user: str | None = None
    tenant: str | None = None
    permissions: frozenset[str] = frozenset()
    approved: bool = False
    trace_id: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    labels: frozenset[str] = frozenset()
    provenance: Any = None
    scan_id: str | None = None


current_context: ContextVar[SecurityContext | None] = ContextVar(
    "secgraph_security_context", default=None
)


def get_context() -> SecurityContext:
    context = current_context.get()
    if context is None:
        context = SecurityContext()
        current_context.set(context)
    return context


class PolicyDenied(PermissionError):
    pass


class SecurityAspect:
    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None: ...
    async def after(self, ctx: SecurityContext, metadata: dict[str, Any], result: Any) -> Any:
        return result

    async def error(
        self, ctx: SecurityContext, metadata: dict[str, Any], exc: Exception
    ) -> None: ...


class AuthorizationAspect(SecurityAspect):
    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        permission = metadata.get("permission")
        if permission and permission not in ctx.permissions:
            raise PolicyDenied(f"missing permission: {permission}")


class ApprovalAspect(SecurityAspect):
    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        if metadata.get("approval") and not ctx.approved:
            raise PolicyDenied("explicit approval required")


class RuntimePolicyAspect(SecurityAspect):
    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        self.before_sync(ctx, metadata)

    def before_sync(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        event = {
            **metadata,
            "user": ctx.user,
            "tenant": ctx.tenant,
            "permissions": sorted(ctx.permissions),
            "labels": sorted(ctx.labels),
        }
        decision = self.engine.evaluate(event)
        ctx.events.append(
            {
                "kind": "policy",
                "effect": decision.effect.value,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "enforced": decision.enforced,
                "explanation": list(decision.explanation),
            }
        )
        if not decision.enforced:
            return
        if decision.effect == Effect.DENY:
            raise PolicyDenied(decision.reason)
        if decision.effect == Effect.REQUIRE_APPROVAL and not ctx.approved:
            raise PolicyDenied(decision.reason or "policy requires approval")

    async def after(self, ctx: SecurityContext, metadata: dict[str, Any], result: Any) -> Any:
        return self.after_sync(ctx, metadata, result)

    def after_sync(self, ctx: SecurityContext, metadata: dict[str, Any], result: Any) -> Any:
        decision = self.engine.evaluate(
            {**metadata, "user": ctx.user, "tenant": ctx.tenant, "labels": sorted(ctx.labels)}
        )
        return redact(result) if decision.enforced and decision.effect == Effect.REDACT else result


class RateLimitAspect(SecurityAspect):
    def __init__(self, maximum: int, window_seconds: float = 60) -> None:
        self.maximum, self.window_seconds = maximum, window_seconds
        self._events: list[float] = []

    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        self.before_sync(ctx, metadata)

    def before_sync(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        now = time.monotonic()
        self._events = [event for event in self._events if now - event < self.window_seconds]
        if len(self._events) >= self.maximum:
            raise PolicyDenied("runtime rate limit exceeded")
        self._events.append(now)


F = TypeVar("F", bound=Callable[..., Any])


class _SecGraphDecorators:
    def __init__(self) -> None:
        self.aspects: list[SecurityAspect] = [AuthorizationAspect(), ApprovalAspect()]

    def tool(
        self, *, permission: str | None = None, approval: bool = False, risk: str = "normal"
    ) -> Callable[[F], F]:
        metadata = {"kind": "tool", "permission": permission, "approval": approval, "risk": risk}
        return self._decorate(metadata)

    def agent(self, **metadata: Any) -> Callable[[F], F]:
        return self._decorate({"kind": "agent", **metadata})

    def retriever(self, **metadata: Any) -> Callable[[F], F]:
        return self._decorate({"kind": "retriever", **metadata})

    def approval(self, *, when: str | None = None) -> Callable[[F], F]:
        return self._decorate({"kind": "approval", "approval": True, "when": when})

    def use_policy(self, engine: PolicyEngine) -> None:
        self.aspects = [AuthorizationAspect(), ApprovalAspect(), RuntimePolicyAspect(engine)]

    def instrument(self, target: F, **metadata: Any) -> F:
        from secgraphai.instrumentation import instrument

        return instrument(target, metadata=metadata)

    def instrument_fastapi(self, app: Any):
        from secgraphai.instrumentation import instrument_fastapi

        return instrument_fastapi(app)

    def instrument_httpx(self):
        from secgraphai.instrumentation import httpx_event_hooks

        return httpx_event_hooks()

    def instrument_openai(self, client: Any):
        from secgraphai.instrumentation import instrument_openai

        return instrument_openai(client)

    def instrument_mcp(self, call: F) -> F:
        from secgraphai.instrumentation import instrument_mcp

        return instrument_mcp(call)

    def instrument_langchain(self, call: F) -> F:
        from secgraphai.instrumentation import instrument_langchain

        return instrument_langchain(call)

    def instrument_langgraph(self, call: F) -> F:
        from secgraphai.instrumentation import instrument_langgraph

        return instrument_langgraph(call)

    def _decorate(self, metadata: dict[str, Any]) -> Callable[[F], F]:
        def decorator(function: F) -> F:
            cast(Any, function).__secgraph__ = metadata
            if inspect.iscoroutinefunction(function):

                @functools.wraps(function)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    return await self._invoke(function, metadata, args, kwargs)

                cast(Any, async_wrapper).__secgraph__ = metadata
                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(function)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = get_context()
                permission = metadata.get("permission")
                if permission and permission not in ctx.permissions:
                    raise PolicyDenied(f"missing permission: {permission}")
                if metadata.get("approval") and not ctx.approved:
                    raise PolicyDenied("explicit approval required")
                try:
                    for aspect in self.aspects:
                        before_sync = getattr(aspect, "before_sync", None)
                        if before_sync:
                            before_sync(ctx, metadata)
                    result = function(*args, **kwargs)
                    for aspect in reversed(self.aspects):
                        after_sync = getattr(aspect, "after_sync", None)
                        if after_sync:
                            result = after_sync(ctx, metadata, result)
                    ctx.events.append(
                        {"kind": metadata["kind"], "function": function.__name__, "allowed": True}
                    )
                    return result
                except Exception as exc:
                    ctx.events.append(
                        {
                            "kind": metadata["kind"],
                            "function": function.__name__,
                            "allowed": False,
                            "reason": type(exc).__name__,
                        }
                    )
                    raise

            cast(Any, sync_wrapper).__secgraph__ = metadata
            return sync_wrapper  # type: ignore[return-value]

        return decorator

    async def _invoke(
        self,
        function: Callable[..., Any],
        metadata: dict[str, Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        ctx = get_context()
        try:
            for aspect in self.aspects:
                await aspect.before(ctx, metadata)
            result = await function(*args, **kwargs)
            for aspect in reversed(self.aspects):
                result = await aspect.after(ctx, metadata, result)
            ctx.events.append(
                {"kind": metadata["kind"], "function": function.__name__, "allowed": True}
            )
            return result
        except Exception as exc:
            ctx.events.append(
                {
                    "kind": metadata["kind"],
                    "function": function.__name__,
                    "allowed": False,
                    "reason": type(exc).__name__,
                }
            )
            for aspect in reversed(self.aspects):
                await aspect.error(ctx, metadata, exc)
            raise


secgraph = _SecGraphDecorators()
