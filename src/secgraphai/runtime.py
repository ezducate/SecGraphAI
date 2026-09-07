"""Runtime metadata, context, decorators, and policy aspects."""

from __future__ import annotations

import functools
import inspect
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar


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


current_context: ContextVar[SecurityContext] = ContextVar(
    "secgraph_security_context", default=SecurityContext()
)


class PolicyDenied(PermissionError):
    pass


class SecurityAspect:
    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None: ...
    async def after(self, ctx: SecurityContext, metadata: dict[str, Any], result: Any) -> Any:
        return result
    async def error(self, ctx: SecurityContext, metadata: dict[str, Any], exc: Exception) -> None: ...


class AuthorizationAspect(SecurityAspect):
    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        permission = metadata.get("permission")
        if permission and permission not in ctx.permissions:
            raise PolicyDenied(f"missing permission: {permission}")


class ApprovalAspect(SecurityAspect):
    async def before(self, ctx: SecurityContext, metadata: dict[str, Any]) -> None:
        if metadata.get("approval") and not ctx.approved:
            raise PolicyDenied("explicit approval required")


F = TypeVar("F", bound=Callable[..., Any])


class _SecGraphDecorators:
    def __init__(self) -> None:
        self.aspects: list[SecurityAspect] = [AuthorizationAspect(), ApprovalAspect()]

    def tool(self, *, permission: str | None = None, approval: bool = False,
             risk: str = "normal") -> Callable[[F], F]:
        metadata = {"kind": "tool", "permission": permission, "approval": approval, "risk": risk}
        return self._decorate(metadata)

    def agent(self, **metadata: Any) -> Callable[[F], F]:
        return self._decorate({"kind": "agent", **metadata})

    def retriever(self, **metadata: Any) -> Callable[[F], F]:
        return self._decorate({"kind": "retriever", **metadata})

    def _decorate(self, metadata: dict[str, Any]) -> Callable[[F], F]:
        def decorator(function: F) -> F:
            setattr(function, "__secgraph__", metadata)
            if inspect.iscoroutinefunction(function):
                @functools.wraps(function)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    return await self._invoke(function, metadata, args, kwargs)
                setattr(async_wrapper, "__secgraph__", metadata)
                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(function)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = current_context.get()
                permission = metadata.get("permission")
                if permission and permission not in ctx.permissions:
                    raise PolicyDenied(f"missing permission: {permission}")
                if metadata.get("approval") and not ctx.approved:
                    raise PolicyDenied("explicit approval required")
                ctx.events.append({"kind": metadata["kind"], "function": function.__name__, "allowed": True})
                return function(*args, **kwargs)
            setattr(sync_wrapper, "__secgraph__", metadata)
            return sync_wrapper  # type: ignore[return-value]
        return decorator

    async def _invoke(self, function: Callable[..., Any], metadata: dict[str, Any],
                      args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        ctx = current_context.get()
        try:
            for aspect in self.aspects:
                await aspect.before(ctx, metadata)
            result = await function(*args, **kwargs)
            for aspect in reversed(self.aspects):
                result = await aspect.after(ctx, metadata, result)
            ctx.events.append({"kind": metadata["kind"], "function": function.__name__, "allowed": True})
            return result
        except Exception as exc:
            ctx.events.append({"kind": metadata["kind"], "function": function.__name__,
                               "allowed": False, "reason": type(exc).__name__})
            for aspect in reversed(self.aspects):
                await aspect.error(ctx, metadata, exc)
            raise


secgraph = _SecGraphDecorators()
