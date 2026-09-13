"""Main developer entry point: @protect decorator and SafeAgent wrapper."""

from __future__ import annotations

import asyncio
import inspect
from functools import wraps
from typing import Any, Callable, TypeVar, Optional

from vibe_guard.core import EvaluationResult, SecurityException
from vibe_guard.detectors.pii import scan_output
from vibe_guard.detectors.prompt import scan_prompt
from vibe_guard.detectors.resources import check_path, check_url
from vibe_guard.telemetry import dispatch_webhook_alert, log_block

F = TypeVar("F", bound=Callable[..., Any])


def _extract_prompt_text(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    """Extract candidate prompt string from arguments."""
    for key in ("prompt", "user_input", "query", "text", "message", "input"):
        if key in kwargs and isinstance(kwargs[key], str):
            return kwargs[key]

    for arg in args:
        if isinstance(arg, str):
            return arg

    return None


def _extract_output_text(result: Any) -> str | None:
    """Extract string output from agent result representations."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for candidate in ("output", "content", "response", "result", "text", "message"):
            if candidate in result and isinstance(result[candidate], str):
                return result[candidate]
    if hasattr(result, "content") and isinstance(result.content, str):
        return result.content
    if hasattr(result, "text") and isinstance(result.text, str):
        return result.text
    return None


class SafeTool:
    """Wraps an agent tool function to check path traversal and SSRF arguments."""

    def __init__(
        self,
        func: Callable[..., Any],
        name: Optional[str] = None,
        *,
        block_resource_abuse: bool = True,
        raise_on_violation: bool = True,
        slack_webhook: Optional[str] = None,
    ) -> None:
        self.func = func
        self.name = name or getattr(func, "__name__", "tool")
        self.block_resource_abuse = block_resource_abuse
        self.raise_on_violation = raise_on_violation
        self.slack_webhook = slack_webhook
        self._is_async = inspect.iscoroutinefunction(func)
        self.__doc__ = getattr(func, "__doc__", None)
        self.__name__ = self.name

    def _inspect_args(self, *args: Any, **kwargs: Any) -> None:
        if not self.block_resource_abuse:
            return

        all_values = list(args) + list(kwargs.values())
        for val in all_values:
            if not isinstance(val, str):
                continue

            # Check Path Traversal
            path_res = check_path(val)
            if not path_res.is_safe:
                self._handle_violation(path_res)

            # Check SSRF
            if val.startswith("http://") or val.startswith("https://") or "://" in val:
                url_res = check_url(val)
                if not url_res.is_safe:
                    self._handle_violation(url_res)

    def _handle_violation(self, res: EvaluationResult) -> None:
        log_block(res, context_name=f"Tool:{self.name}")
        if self.slack_webhook:
            dispatch_webhook_alert(self.slack_webhook, res, {"tool": self.name})
        if self.raise_on_violation:
            raise SecurityException(res)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._inspect_args(*args, **kwargs)
        if self._is_async:
            return self._async_call(*args, **kwargs)
        return self.func(*args, **kwargs)

    async def _async_call(self, *args: Any, **kwargs: Any) -> Any:
        return await self.func(*args, **kwargs)

    def __getattr__(self, item: str) -> Any:
        return getattr(self.func, item)


def safe_tool(
    name: Optional[str] = None,
    *,
    block_resource_abuse: bool = True,
    raise_on_violation: bool = True,
    slack_webhook: Optional[str] = None,
) -> Callable[[F], SafeTool]:
    """Decorator to enforce path & SSRF security checks on individual tools."""

    def decorator(fn: F) -> SafeTool:
        return SafeTool(
            func=fn,
            name=name,
            block_resource_abuse=block_resource_abuse,
            raise_on_violation=raise_on_violation,
            slack_webhook=slack_webhook,
        )

    return decorator


def protect(
    block_injection: bool = True,
    block_resource_abuse: bool = True,
    mask_secrets: bool = True,
    slack_webhook: Optional[str] = None,
    endpoint: Optional[str] = None,
    raise_on_violation: bool = True,
) -> Callable[[F], F]:
    """Function decorator to protect any sync or async agent function."""

    def decorator(func: F) -> F:
        webhook_target = slack_webhook or endpoint

        def _evaluate_input(*args: Any, **kwargs: Any) -> None:
            if not block_injection:
                return
            prompt = _extract_prompt_text(args, kwargs)
            if prompt:
                res = scan_prompt(prompt)
                if not res.is_safe:
                    log_block(res, context_name=getattr(func, "__name__", "function"))
                    if webhook_target:
                        dispatch_webhook_alert(webhook_target, res, {"function": getattr(func, "__name__", "")})
                    if raise_on_violation:
                        raise SecurityException(res)

        def _evaluate_output(raw_out: Any) -> Any:
            text = _extract_output_text(raw_out)
            if not text:
                return raw_out

            res = scan_output(text, mask=mask_secrets)
            if not res.is_safe:
                log_block(res, context_name=getattr(func, "__name__", "function"))
                if webhook_target:
                    dispatch_webhook_alert(webhook_target, res, {"function": getattr(func, "__name__", "")})
                if raise_on_violation and res.violation_type == "SECRET_LEAK":
                    raise SecurityException(res)

                if mask_secrets and isinstance(raw_out, str):
                    return res.cleaned_text
            return raw_out

        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                _evaluate_input(*args, **kwargs)
                res = await func(*args, **kwargs)
                return _evaluate_output(res)

            return async_wrapper  # type: ignore[return-value]
        else:
            @wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                _evaluate_input(*args, **kwargs)
                res = func(*args, **kwargs)
                return _evaluate_output(res)

            return sync_wrapper  # type: ignore[return-value]

    return decorator


class SafeAgent:
    """Universal In-Process Security Wrapper for AI Agents."""

    def __init__(
        self,
        agent: Any,
        *,
        block_injection: bool = True,
        block_resource_abuse: bool = True,
        mask_secrets: bool = True,
        slack_webhook: Optional[str] = None,
        endpoint: Optional[str] = None,
        raise_on_violation: bool = True,
    ) -> None:
        self._agent = agent
        self.block_injection = block_injection
        self.block_resource_abuse = block_resource_abuse
        self.mask_secrets = mask_secrets
        self.webhook_url = slack_webhook or endpoint
        self.raise_on_violation = raise_on_violation

        # Auto-wrap tools in agent.tools if present
        self._auto_wrap_tools()

    def _auto_wrap_tools(self) -> None:
        if hasattr(self._agent, "tools") and isinstance(self._agent.tools, list):
            wrapped_tools = []
            for tool in self._agent.tools:
                if isinstance(tool, SafeTool):
                    wrapped_tools.append(tool)
                elif callable(tool):
                    tool_name = getattr(tool, "name", getattr(tool, "__name__", "tool"))
                    wrapped_tools.append(
                        SafeTool(
                            tool,
                            name=tool_name,
                            block_resource_abuse=self.block_resource_abuse,
                            raise_on_violation=self.raise_on_violation,
                            slack_webhook=self.webhook_url,
                        )
                    )
                else:
                    wrapped_tools.append(tool)
            self._agent.tools = wrapped_tools

    def _check_input(self, *args: Any, **kwargs: Any) -> None:
        if not self.block_injection:
            return
        prompt = _extract_prompt_text(args, kwargs)
        if prompt:
            res = scan_prompt(prompt)
            if not res.is_safe:
                log_block(res, context_name="SafeAgent")
                if self.webhook_url:
                    dispatch_webhook_alert(self.webhook_url, res)
                if self.raise_on_violation:
                    raise SecurityException(res)

    def _check_output(self, raw_out: Any) -> Any:
        text = _extract_output_text(raw_out)
        if not text:
            return raw_out

        res = scan_output(text, mask=self.mask_secrets)
        if not res.is_safe:
            log_block(res, context_name="SafeAgent")
            if self.webhook_url:
                dispatch_webhook_alert(self.webhook_url, res)
            if self.raise_on_violation and res.violation_type == "SECRET_LEAK":
                raise SecurityException(res)

            if self.mask_secrets and isinstance(raw_out, str):
                return res.cleaned_text
        return raw_out

    def run(self, *args: Any, **kwargs: Any) -> Any:
        self._check_input(*args, **kwargs)
        if hasattr(self._agent, "run") and callable(self._agent.run):
            out = self._agent.run(*args, **kwargs)
        elif callable(self._agent):
            out = self._agent(*args, **kwargs)
        elif hasattr(self._agent, "invoke") and callable(self._agent.invoke):
            out = self._agent.invoke(*args, **kwargs)
        else:
            raise TypeError(f"Target agent {type(self._agent)} does not provide run(), invoke(), or __call__")
        return self._check_output(out)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        self._check_input(*args, **kwargs)
        if hasattr(self._agent, "invoke") and callable(self._agent.invoke):
            out = self._agent.invoke(*args, **kwargs)
        elif hasattr(self._agent, "run") and callable(self._agent.run):
            out = self._agent.run(*args, **kwargs)
        elif callable(self._agent):
            out = self._agent(*args, **kwargs)
        else:
            raise TypeError(f"Target agent {type(self._agent)} does not provide invoke(), run(), or __call__")
        return self._check_output(out)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        self._check_input(*args, **kwargs)
        if hasattr(self._agent, "arun") and callable(self._agent.arun):
            out = await self._agent.arun(*args, **kwargs)
        elif hasattr(self._agent, "ainvoke") and callable(self._agent.ainvoke):
            out = await self._agent.ainvoke(*args, **kwargs)
        elif inspect.iscoroutinefunction(self._agent):
            out = await self._agent(*args, **kwargs)
        elif callable(self._agent):
            loop = asyncio.get_running_loop()
            out = await loop.run_in_executor(None, lambda: self._agent(*args, **kwargs))
        else:
            raise TypeError(f"Target agent {type(self._agent)} does not support async execution")
        return self._check_output(out)

    async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:
        return await self.arun(*args, **kwargs)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._agent, item)
