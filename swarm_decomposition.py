"""Sanitized Aisana excerpt: decomposition and subtask reassignment."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


@dataclass
class Task:
    id: str
    title: str
    description: str
    status: str
    parent_task_id: str | None = None
    assignee_agent_id: str | None = None


class TaskStore(Protocol):
    def create_task(self, title: str, description: str, status: str, parent_task_id: str | None = None) -> str:
        ...

    def get_task(self, task_id: str) -> Task | None:
        ...

    def update_task(self, task: Task) -> None:
        ...


async def decompose_task_into_subtasks(
    parent_task_id: str,
    subtask_definitions: list[dict[str, Any]],
    store: TaskStore,
) -> list[Task]:
    """Create concrete subtasks from an LLM/planner-produced task breakdown."""

    created_tasks: list[Task] = []

    for definition in subtask_definitions:
        title = str(definition.get("title") or "").strip()
        description = str(definition.get("description") or "").strip()

        if not title or not description:
            logger.warning("Skipping invalid subtask definition: %s", definition)
            continue

        task_id = store.create_task(
            title=title,
            description=description,
            status="backlog",
            parent_task_id=parent_task_id,
        )
        task = store.get_task(task_id)
        if task:
            created_tasks.append(task)

    logger.info("Decomposed %s into %s subtasks", parent_task_id, len(created_tasks))
    return created_tasks


def reassign_failed_subtask(
    task_id: str,
    failed_agent_id: str,
    available_agent_ids: list[str],
    store: TaskStore,
) -> str | None:
    """Move a failed subtask away from an unavailable agent."""

    task = store.get_task(task_id)
    if not task:
        logger.error("Task %s not found", task_id)
        return None

    if task.assignee_agent_id != failed_agent_id:
        logger.warning(
            "Task %s is assigned to %s, not failed agent %s",
            task_id,
            task.assignee_agent_id,
            failed_agent_id,
        )
        return None

    candidates = [agent_id for agent_id in available_agent_ids if agent_id != failed_agent_id]
    if not candidates:
        logger.error("No available agents to reassign task %s", task_id)
        return None

    new_agent_id = candidates[0]
    task.assignee_agent_id = new_agent_id
    task.status = "ready_for_agent"
    store.update_task(task)

    logger.info("Reassigned task %s from %s to %s", task_id, failed_agent_id, new_agent_id)
    return new_agent_id
