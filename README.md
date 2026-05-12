# Aisana Agent OS Showcase

Aisana is a local-first Personal Agent OS MVP: a project/task workspace where AI agents act as organization members with roles, skills, permissions, execution sessions, logs, human questions, approvals, artifacts, and memory.

This public showcase is a sanitized excerpt from the local development tree. It keeps the control-plane ideas and representative code while excluding `.env`, test databases, runtime workspaces, logs, local MCP configs, and provider credentials.

## Architecture

```text
Next.js dashboard
  -> FastAPI product backend
    -> Postgres product database
    -> Redis queue/cache
    -> Local runner
      -> runtime compiler
      -> model provider adapter
      -> Tool Gateway
        -> skills
        -> MCP/tools
        -> terminal allowlist
        -> filesystem scopes
```

## Core Rule

```text
Agent -> Skill -> Tool Gateway -> Tool/MCP/API
```

Agents never call host tools directly. Tool access goes through policy checks, workspace scoping, audit logs, and explicit approval gates for risky operations.

## Included Files

- [`policy_engine.py`](./policy_engine.py) - role/permission checks, inherited roles, cost-cap checks, and host computer-use restrictions.
- [`tool_gateway_excerpt.py`](./tool_gateway_excerpt.py) - representative tool dispatch, workspace path resolution, MCP routing, and permission enforcement.
- [`swarm_decomposition.py`](./swarm_decomposition.py) - task decomposition and failed-subtask reassignment helpers.

## What Is Omitted

- real `.env` files and provider keys;
- local SQLite/Postgres data;
- execution logs and generated workspaces;
- local MCP server config;
- private product notes.
