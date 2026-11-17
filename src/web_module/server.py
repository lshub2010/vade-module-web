"""Protocol adapter: ModuleApp + ToolSpec. No network logic lives here.

The only two jobs:
  1. turn each decorated function in `tools.py` into a `ToolSpec` (metadata from
     the decorator, JSON Schema from the signature by the SDK);
  2. translate `tools.ToolFailure` into `vade_sdk.ToolError` so a structured
     tool error keeps its C-04 code instead of becoming INTERNAL.

`tools.py` never imports the SDK; this file never opens a socket.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from . import tools as tools_module

__all__ = ["MODULE_ID", "MODULE_VERSION", "build_app", "main"]

MODULE_ID = "com.example.web"
MODULE_VERSION = "1.0.0"


def _adapt(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a pure tool so `ToolFailure` becomes `ToolError`."""
    from vade_sdk import ToolError

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_call(*args: Any, **kwargs: Any) -> Any:
            try:
                return await fn(*args, **kwargs)
            except tools_module.ToolFailure as exc:
                raise ToolError(exc.code, exc.message) from None

        return async_call

    @functools.wraps(fn)
    def sync_call(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except tools_module.ToolFailure as exc:
            raise ToolError(exc.code, exc.message) from None

    return sync_call


def build_app() -> Any:
    """Build the ModuleApp. Importing the SDK happens here, not at module import."""
    from vade_sdk import ModuleApp, ToolSpec

    app = ModuleApp(
        module_id=MODULE_ID,
        version=MODULE_VERSION,
        # Stateless and read-only: several instances may share the load.
        concurrency="pooled",
        display_name="Web 模块",
        priority=0,
        capabilities=["tools"],
    )
    for fn in tools_module.all_tools():
        meta = getattr(fn, "tool_meta", None)
        if meta is None:
            raise RuntimeError(f"{fn.__name__} is not decorated with @tool")
        app.add_tool(
            ToolSpec(
                name=meta["name"],
                fn=_adapt(fn),
                description=meta["description"],
                risk=meta["risk"],
                timeout_ms=meta["timeout_ms"],
                idempotent=meta["idempotent"],
            )
        )
    return app


def main(argv: list[str] | None = None) -> int:
    return build_app().run(argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
