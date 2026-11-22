# Using Harnis from IDEs and coding tools

There are two ways in from a developer's machine, plus the HTTP API that both use.

| Route | Use it for |
|---|---|
| `harnis` command | Hand a task to Harnis from any terminal, including the one inside VS Code. |
| MCP server (`harnis-mcp`) | Let a coding tool (Claude Code, VS Code agent mode, Cursor and other MCP clients) hand tasks to Harnis. |
| HTTP API | Build your own integration: create a session, send a task, read the conversation, listen for events (`/docs` on your Harnis address). |

Harnis suits delegated tasks (give it a job, review the result). It does not do inline completion or autocomplete, and there is no IDE extension.

## What this does and does not control

Everything that runs inside a Harnis session is controlled: Harnis's tools, its sandbox, reviewer approvals, budgets and the audit log, and agents never hold model provider keys.

An agent or tool that has its own model key or its own shell is **not** controlled by Harnis, even if it also calls Harnis. The MCP server is a governed route to the agents, not enforcement. To make Harnis the only route, enforce it outside Harnis:

- keep model provider keys only in Harnis, and give staff and tools Harnis tokens instead;
- block direct access to model providers from workstations and servers, except from Harnis;
- use your tools' managed settings so people cannot add their own provider keys.

Harnis is not a model gateway: it has no endpoint that another agent's model calls could be pointed at.

## The `harnis` command

```bash
export HARNIS_API=https://harnis.example.com
export HARNIS_TOKEN=hrn_...            # a token or API key with the user and reviewer roles
harnis --workspace . "add a slugify() helper with tests"
```

It uploads a copy of the project (skipping `.git`, virtualenvs, `node_modules`, `.env*` files and large files), the agent works in that isolated copy, and every write or command stops for your y/N with the diff or command shown. At the end you see the full diff against your local files and decide whether to apply it. Nothing touches your real files before that, and once applied, VS Code's Source Control view shows the changes like any other edit.

## The MCP server

```bash
pip install "harnis[mcp]"
```

It runs on your machine over stdio and offers five tools:

| Tool | What it does |
|---|---|
| `harnis_start_task` | Upload the project to a new session and give the agents a task. |
| `harnis_task_status` | Where a session stands: running, waiting for a human approval, done, or stopped (with the handover summary). |
| `harnis_send_message` | Send a follow-up in the same session. |
| `harnis_get_changes` | Show the files the agents changed, as diffs against your local project. Writes nothing. |
| `harnis_apply_changes` | Write the changes into your project. Only after `harnis_get_changes`, and it refuses any file you edited since you looked. |

**There is no approve or deny tool, on purpose.** Approvals belong to people, in the Harnis console or the `harnis` command. A coding agent that could approve its own work would defeat the point of the review. Give the MCP server a token with only the `user` role, so that even a misbehaving client could not approve anything. When a task is waiting, the tool says so and points to the console.

Settings (environment variables): `HARNIS_API` (your Harnis address), `HARNIS_TOKEN` (required), `HARNIS_WORKSPACE` (the project folder; default: the folder the server starts in; set it explicitly).

### Claude Code

```bash
claude mcp add --env HARNIS_API=https://harnis.example.com --env HARNIS_TOKEN=hrn_... \
  --env HARNIS_WORKSPACE=/path/to/project --transport stdio harnis -- harnis-mcp
```

Everything after `--` is the command that runs the server. Put at least one other option between the last `--env` and the server name, as above.

### VS Code (agent mode)

In `.vscode/mcp.json`, with the token asked for once and stored by VS Code:

```json
{
  "servers": {
    "harnis": {
      "type": "stdio",
      "command": "harnis-mcp",
      "env": {
        "HARNIS_API": "https://harnis.example.com",
        "HARNIS_TOKEN": "${input:harnis-token}",
        "HARNIS_WORKSPACE": "${workspaceFolder}"
      }
    }
  },
  "inputs": [
    { "type": "promptString", "id": "harnis-token", "description": "Harnis token", "password": true }
  ]
}
```

### Cursor and other MCP clients

Register a stdio server with the command `harnis-mcp` (or `python -m harnis.mcp_server`) and the same three environment variables; see your tool's documentation for where that is configured.

## Keep in mind

- The project is uploaded to Harnis. Files over 200 kB, binary files, `.env*` files and the usual folders (`.git`, `node_modules`, virtualenvs) are skipped, and at most 200 files are sent. Do not rely on that to keep secrets out: check what your folder holds.
- The coding tool still has its own permission prompts for calling a tool. They are separate from Harnis's reviewer approvals, so a change can need both.
- The MCP server needs the `mcp` Python package (MIT-licensed), installed by the `mcp` extra.
