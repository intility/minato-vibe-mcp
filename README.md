# minato-vibe-mcp

MCP server for creating and editing apps on the [minato-vibe](https://github.com/intility/minato-vibe) Kubernetes platform.

It is a **thin wrapper around the official [`github-mcp-server`](https://github.com/github/github-mcp-server)**: every GitHub operation is delegated to `github-mcp-server` (spawned as a subprocess), and this server only adds the platform-specific knowledge — which templates exist, the naming rules, the URL pattern, and the platform conventions.

## Tools

| Tool | What it does |
|---|---|
| `list_templates` | Returns the two golden-path templates (`react-vibe-template`, `react-go-template`) with stack info and the GitHub manual-create URL for each. |
| `create_app(name, template?, private?, description?)` | Creates `intility/<name>` from the chosen template. Defaults to `react-vibe-template`, public. Returns the repo URL and the expected app URL. |
| `read_file(repo, path, ref?)` | Reads a file from `intility/<repo>`. Base64 content is decoded for you. |
| `list_files(repo, path?, ref?)` | Lists a directory in `intility/<repo>`. |
| `write_file(repo, path, content, message, branch?)` | **Stages** a write. Returns a unified diff and a confirmation token. Does NOT commit. |
| `confirm_write(token)` | Commits a write previously staged by `write_file`. Single-use, expires 5 minutes after staging. |
| `list_pending_writes` | Shows staged writes that haven't been confirmed yet. |

## Writes are two-step (the security model)

To protect against prompt injection ([the lethal trifecta](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)), the MCP never lets the model commit a file in one step. The flow is always:

1. Model calls `write_file(...)` → MCP returns a diff and a confirmation token.
2. The chat client shows the diff to **you, the human**.
3. You approve. The model calls `confirm_write(token)` → MCP commits.

The token is single-use, expires after 5 minutes, and lives only in the MCP's memory. A model that's been prompt-injected into writing malicious code still has to surface the diff to you first — and you can deny the confirm call.

This is defense-in-depth, not a guarantee. If you reflexively approve every diff, the protection is gone. Read the diff.

## Prerequisites

- Docker (used to run `github-mcp-server` as a subprocess).
- A GitHub personal access token with `repo` scope, exported as `GITHUB_TOKEN`.

If you'd rather use a native `github-mcp-server` binary instead of Docker, set `GITHUB_MCP_COMMAND=/path/to/github-mcp-server`.

## Install

```sh
git clone https://github.com/intility/minato-vibe-mcp
cd minato-vibe-mcp
pip install -e .
```

## Register with your chat client

### Claude Code

```sh
claude mcp add minato-vibe \
  --env GITHUB_TOKEN=$GITHUB_TOKEN \
  -- minato-vibe-mcp
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "minato-vibe": {
      "command": "minato-vibe-mcp",
      "env": {
        "GITHUB_TOKEN": "ghp_..."
      }
    }
  }
}
```

## How it works

```
Your chat client
    │  MCP stdio
    ▼
minato-vibe-mcp                ← this project
    │  MCP stdio (internal)
    ▼
github-mcp-server (Docker)
    │
    ▼
api.github.com
```

The wrapper spawns `github-mcp-server` on startup, keeps the session open for the life of the process, and forwards tool calls to it after injecting `owner=intility` and other platform defaults.

The one exception is `create_app`: GitHub's "create from template" endpoint (`POST /repos/{owner}/{repo}/generate`) is not exposed by `github-mcp-server`, so this server calls it directly using the same `GITHUB_TOKEN`. Everything else goes through the wrapper.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GITHUB_TOKEN` (or `GITHUB_PERSONAL_ACCESS_TOKEN`) | yes | — | PAT with `repo` scope. Passed to `github-mcp-server`. |
| `GITHUB_MCP_IMAGE` | no | `ghcr.io/github/github-mcp-server:latest` | Pin a specific image. |
| `GITHUB_MCP_COMMAND` | no | — | Path to a native `github-mcp-server` binary. If set, Docker is not used. |

## Known limitations (v0.1)

- No deploy-status tool: after `write_file` to `main`, watch via GitHub Actions or `kubectl get application -n argocd`.
- No pod-logs tool.
- No PR / branch mode for writes — commits go straight to the chosen branch (`main` by default), matching the platform's push-to-deploy model.
- A confused model can commit broken code; the platform's per-app isolation limits the blast radius. Recovery is `git revert` via GitHub.
