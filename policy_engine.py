"""Sanitized Aisana excerpt: role policy and host safety checks."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Permission:
    action: str
    resource: str


@dataclass(frozen=True)
class Role:
    id: str
    parent_role_id: str | None = None
    daily_cost_cap: float | None = None


@dataclass(frozen=True)
class AuditLog:
    agent_id: str
    role_id: str | None
    action: str
    resource: str
    status: str
    details_json: str


class PolicyStore(Protocol):
    def role_ids_for_agent(self, agent_id: str) -> list[str]:
        ...

    def roles_by_id(self, role_ids: list[str]) -> list[Role]:
        ...

    def permissions_for_roles(self, role_ids: list[str]) -> list[tuple[Permission, str]]:
        ...

    def daily_cost_for_agent(self, agent_id: str) -> float:
        ...

    def append_audit_log(self, log: AuditLog) -> None:
        ...


class ComputerUsePolicy:
    """Blocks commands and paths that should not be touched by local agents."""

    FORBIDDEN_COMMANDS = {
        "systemctl",
        "sysctl",
        "defaults",
        "reg",
        "regedit",
        "chown",
        "chmod",
        "ufw",
        "iptables",
        "firewall-cmd",
        "sc",
        "launchctl",
    }

    FORBIDDEN_PATHS = [
        "/etc",
        "/var/run",
        "/var/lib",
        "/usr/local/etc",
        "/Library/Preferences",
        "C:\\Windows",
        "C:\\Program Files",
        "C:/Windows",
        "C:/Program Files",
    ]

    @classmethod
    def is_command_safe(cls, command: str) -> bool:
        if not command:
            return True

        for token in re.split(r"\s+", command):
            clean_token = token.strip(";'\"|&`")
            if clean_token in cls.FORBIDDEN_COMMANDS:
                return False

        for forbidden_path in cls.FORBIDDEN_PATHS:
            escaped = re.escape(forbidden_path)
            pattern = r"(?:^|[\s'\"=|])" + escaped + r"(?:$|[/\s'\"|\\])"
            if re.search(pattern, command):
                return False

        return True


class PolicyEngine:
    def __init__(self, store: PolicyStore) -> None:
        self.store = store
        self._permission_cache: dict[tuple[str, str, str], tuple[bool, float]] = {}
        self._cache_ttl = 60.0

    def check_computer_use_policy(self, command: str) -> bool:
        return ComputerUsePolicy.is_command_safe(command)

    def check_cost_cap(self, agent_id: str) -> bool:
        role_ids = self._role_tree_for_agent(agent_id)
        caps = [role.daily_cost_cap for role in self.store.roles_by_id(role_ids) if role.daily_cost_cap]
        if not caps:
            return True
        return self.store.daily_cost_for_agent(agent_id) < max(caps)

    def has_permission(self, agent_id: str, action: str, resource: str) -> bool:
        cache_key = (agent_id, action, resource)
        now = time.time()
        cached = self._permission_cache.get(cache_key)
        if cached and now < cached[1]:
            return cached[0]

        role_ids = self._role_tree_for_agent(agent_id)
        if not role_ids:
            self._audit(agent_id, None, action, resource, "denied", "no_roles")
            self._permission_cache[cache_key] = (False, now + self._cache_ttl)
            return False

        matched_role = None
        for permission, role_id in self.store.permissions_for_roles(role_ids):
            if self._matches(permission, action, resource):
                matched_role = role_id
                break

        allowed = matched_role is not None
        self._audit(
            agent_id,
            matched_role,
            action,
            resource,
            "allowed" if allowed else "denied",
            "matched_policy" if allowed else "no_matching_policy",
        )
        self._permission_cache[cache_key] = (allowed, now + self._cache_ttl)
        return allowed

    def _role_tree_for_agent(self, agent_id: str) -> list[str]:
        role_ids = set(self.store.role_ids_for_agent(agent_id))
        pending = list(role_ids)

        while pending:
            parents = [role.parent_role_id for role in self.store.roles_by_id(pending)]
            pending = [role_id for role_id in parents if role_id and role_id not in role_ids]
            role_ids.update(pending)

        return list(role_ids)

    def _matches(self, permission: Permission, action: str, resource: str) -> bool:
        action_match = permission.action == "*" or permission.action == action
        if not action_match:
            return False

        if permission.resource == "*":
            return True
        if permission.resource.endswith("*"):
            return resource.startswith(permission.resource[:-1])
        return permission.resource == resource

    def _audit(
        self,
        agent_id: str,
        role_id: str | None,
        action: str,
        resource: str,
        status: str,
        reason: str,
    ) -> None:
        self.store.append_audit_log(
            AuditLog(
                agent_id=agent_id,
                role_id=role_id,
                action=action,
                resource=resource,
                status=status,
                details_json=json.dumps({"reason": reason}),
            )
        )
