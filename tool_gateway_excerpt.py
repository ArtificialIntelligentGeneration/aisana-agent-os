"""Sanitized Aisana excerpt: tool gateway and workspace guardrails."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class FunctionCall:
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class FunctionResponse:
    name: str
    result: str


class PolicyEngine(Protocol):
    def has_permission(self, agent_id: str, action: str, resource: str) -> bool:
        ...

    def check_computer_use_policy(self, command: str) -> bool:
        ...


class ExecutionDB(Protocol):
    def create_execution_log(self, session_id: str, kind: str, message: str, data: dict[str, Any] | None = None) -> None:
        ...


class ToolGateway:
    """Single choke point between agents and host tools."""

    def __init__(
        self,
        db: ExecutionDB,
        policy_engine: PolicyEngine,
        session_id: str,
        agent_id: str,
        workspace_path: str,
        mcp_bridge: Any | None = None,
    ) -> None:
        self.db = db
        self.policy_engine = policy_engine
        self.session_id = session_id
        self.agent_id = agent_id
        self.workspace_path = workspace_path
        self.mcp_bridge = mcp_bridge
        self.handlers: dict[str, Callable[[dict[str, Any]], str]] = {
            "read_file": self._handle_read_file,
            "write_file": self._handle_write_file,
            "run_terminal_command": self._handle_run_terminal_command,
        }

    def execute_tool(self, call: FunctionCall) -> FunctionResponse:
        self.db.create_execution_log(self.session_id, "tool_call", call.name, {"args": call.args})

        resource = f"tool:{call.name}"
        if not self.policy_engine.has_permission(self.agent_id, "execute", resource):
            result = f"Error: agent lacks permission to execute {call.name}."
            self.db.create_execution_log(self.session_id, "tool_response", call.name, {"result": result})
            return FunctionResponse(name=call.name, result=result)

        try:
            if call.name.startswith("mcp__"):
                result = self._handle_mcp_tool(call.name, call.args)
            elif call.name in self.handlers:
                result = self.handlers[call.name](call.args)
            else:
                result = f"Unknown tool: {call.name}"
        except Exception as exc:
            result = f"Error executing {call.name}: {exc}"

        self.db.create_execution_log(self.session_id, "tool_response", call.name, {"result": result})
        return FunctionResponse(name=call.name, result=result)

    def _resolve_path(self, filepath: str) -> str:
        workspace = os.path.realpath(os.path.abspath(self.workspace_path))
        requested = filepath if os.path.isabs(filepath) else os.path.join(workspace, filepath)
        target = os.path.realpath(os.path.abspath(requested))

        inside_workspace = target == workspace or target.startswith(workspace + os.sep)
        if inside_workspace:
            return target

        has_escape = self.policy_engine.has_permission(self.agent_id, "access", "fs:escape_sandbox")
        has_specific = self.policy_engine.has_permission(self.agent_id, "access", f"fs:access:{target}")
        if not (has_escape or has_specific):
            raise PermissionError(f"Access denied: {filepath} is outside the workspace sandbox.")

        return target

    def _handle_read_file(self, args: dict[str, Any]) -> str:
        full_path = self._resolve_path(str(args.get("filepath", "")))
        with open(full_path, encoding="utf-8") as handle:
            return handle.read()

    def _handle_write_file(self, args: dict[str, Any]) -> str:
        full_path = self._resolve_path(str(args.get("filepath", "")))
        content = str(args.get("content", ""))
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return f"Wrote {len(content)} bytes to {full_path}"

    def _handle_run_terminal_command(self, args: dict[str, Any]) -> str:
        command = str(args.get("command", ""))
        if not self.policy_engine.check_computer_use_policy(command):
            return "Error: command blocked by computer-use policy."
        return "Command accepted for sandboxed execution."

    def _handle_mcp_tool(self, name: str, args: dict[str, Any]) -> str:
        if self.mcp_bridge is None:
            return "Error: MCP bridge is not initialized."

        parts = name.split("__")
        if len(parts) < 3:
            return f"Error: invalid MCP tool name: {name}"

        server_name = parts[1]
        tool_name = "__".join(parts[2:])
        result = self.mcp_bridge.call_tool(server_name, tool_name, args)
        return str(result)
