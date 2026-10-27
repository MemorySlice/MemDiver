"""Approval gate of the agent chat: READ tools pass, WRITE tools wait for the analyst.

Implements :class:`contracts.PermissionGate`. The tool access map (``read|write|never``)
is injected by the API layer (from ``mcp_server.tool_policy``); this module imports
neither ``api`` nor ``mcp_server``.

Concurrency: the gate is bound to the event loop running when ``decide`` is first
awaited; ``resolve`` and ``close`` must be called from that same loop (the chat's WS
handler does). It is not thread-safe.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Callable, Dict, Mapping, Optional, Set

from .contracts import (
    APPROVAL_SCOPES,
    TOOL_PREFIX,
    ChatEvent,
    Decision,
    Emit,
)

_NOT_MEMDIVER = "only MemDiver tools are available in this chat"
#: Access-map value for a WRITE tool whose approval may only be granted per call
#: (it executes caller-supplied code or chooses an executable).
WRITE_ONCE = "write_once"
_NEVER = "this tool is never available in the chat; start captures from the Capture UI"


class ApprovalGate:
    """Per-chat permission gate with once/chat-scoped approvals."""

    def __init__(self, tool_access: Mapping[str, str], emit: Emit, *,
                 id_factory: Optional[Callable[[], str]] = None,
                 approval_timeout: Optional[float] = None) -> None:
        self._access = dict(tool_access)
        self._emit = emit
        self._new_id = id_factory or (lambda: uuid.uuid4().hex)
        self._timeout = approval_timeout
        self._pending: Dict[str, "asyncio.Future[Decision]"] = {}
        self._pending_tool: Dict[str, str] = {}
        self._chat_approved: Set[str] = set()
        self._closed = False

    async def decide(self, tool_name: str, tool_input: Mapping[str, Any]) -> Decision:
        if not tool_name.startswith(TOOL_PREFIX):
            return Decision(False, _NOT_MEMDIVER)
        tool = tool_name[len(TOOL_PREFIX):]
        access = self._access.get(tool, "write")  # unknown MemDiver tool: fail closed
        if access == "read":
            return Decision(True)
        if access == "never":
            return Decision(False, _NEVER)
        if self._closed:
            return Decision(False, "chat closed")
        if tool in self._chat_approved and not self._once_only(tool):
            return Decision(True)
        return await self._ask(tool, tool_input, access)

    def _once_only(self, tool: str) -> bool:
        """Tools that run caller-supplied code / pick an executable: never chat-scoped."""
        return self._access.get(tool) == WRITE_ONCE

    def _scopes_for(self, tool: str) -> list:
        return [APPROVAL_SCOPES[0]] if self._once_only(tool) else list(APPROVAL_SCOPES)

    async def _ask(self, tool: str, tool_input: Mapping[str, Any], access: str) -> Decision:
        request_id = self._new_id()
        future: "asyncio.Future[Decision]" = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        self._pending_tool[request_id] = tool
        await self._emit(ChatEvent("approval_request", {
            "id": request_id, "tool": tool, "input": dict(tool_input),
            "access": "write" if access == WRITE_ONCE else access,
            "scopes": self._scopes_for(tool)}))
        try:
            return await asyncio.wait_for(future, self._timeout)
        except asyncio.TimeoutError:
            self._settle(request_id, Decision(False, "approval timed out"))
            await self._emit(ChatEvent("approval_resolved", {
                "id": request_id, "allowed": False, "message": "approval timed out"}))
            return Decision(False, "approval timed out")
        finally:
            self._pending.pop(request_id, None)
            self._pending_tool.pop(request_id, None)

    def _settle(self, request_id: str, decision: Decision) -> bool:
        future = self._pending.get(request_id)
        if future is None or future.done():
            return False
        future.set_result(decision)
        return True

    def resolve(self, request_id: str, allow: bool, message: str = "",
                scope: str = "once") -> bool:
        """Answer a pending request; False for an unknown/already-answered id."""
        tool = self._pending_tool.get(request_id)
        if tool is None or not self._settle(request_id, Decision(bool(allow), message)):
            return False
        if allow and scope == "chat" and not self._once_only(tool):
            self._chat_approved.add(tool)
        self._schedule_event(ChatEvent("approval_resolved", {
            "id": request_id, "allowed": bool(allow), "message": message}))
        return True

    def cancel_pending(self, message: str = "interrupted") -> int:
        """Deny every pending approval (the analyst interrupted the turn); returns how many.

        Without this an interrupted turn leaves a live Allow/Deny card whose answer would
        be refused as an unknown id.
        """
        cancelled = 0
        for request_id in list(self._pending):
            if self._settle(request_id, Decision(False, message)):
                cancelled += 1
                self._schedule_event(ChatEvent("approval_resolved", {
                    "id": request_id, "allowed": False, "message": message}))
        return cancelled

    def _schedule_event(self, event: ChatEvent) -> None:
        async def _send() -> None:
            try:
                await self._emit(event)
            except Exception:  # noqa: BLE001 - a failed notification must not crash
                pass

        asyncio.get_running_loop().create_task(_send())

    async def close(self) -> None:
        """Deny every pending approval; later write calls are denied too."""
        self._closed = True
        for request_id in list(self._pending):
            self._settle(request_id, Decision(False, "chat closed"))
