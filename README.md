# minato-vibe-mcp

A multi-tenant MCP server for creating and editing apps on the [minato-vibe](https://github.com/intility/minato-vibe) Kubernetes platform.

Each user authenticates with their own GitHub personal access token, which doubles as the Bearer token for the MCP. All operations run as that GitHub user — commits, repo creation, everything — so attribution and authorization are correct out of the box.

## Tools

| Tool | What it does |
|---|---|
| `whoami` | Returns the GitHub identity of the authenticated user. |
| `list_templates` | Returns the two golden-path templates (`react-vibe-template`, `react-go-template`). |
| `create_app(name, template?, description?)` | Creates `intility/<name>` from the chosen template **as a private repo**, running as the authenticated user. The MCP never creates public repos. |
| `repo_overview(repo, ref?)` | **Call first when starting work on a repo.** One round-trip returns the file tree + README + manifests. Replaces 10+ exploration calls. |
| `get_template_conventions(template)` | **Call before writing significant code.** Returns the template's non-obvious lint rules and common pitfalls (strict-mode TS, Biome rules, React compiler rules, Go stdlib-only). Pre-empts most first-round CI failures. |
| `read_file(repo, path, ref?)` | Single file read. For multiple files, prefer `read_files`. |
| `read_files(repo, paths, ref?)` | Multi-file read in parallel — one round-trip instead of N. |
| `list_files(repo, path?, ref?)` | List a directory. |
| `write_file(repo, path, content, message, branch?)` | **Stages** a write. Runs cheap static checks (no-op detection, JSON/YAML/TOML/Python syntax). Returns a diff + confirmation token; does NOT commit. |
| `confirm_write(token)` | Commits a single staged write — opens its own PR. |
| `confirm_writes(tokens, message?)` | **Batch**: land multiple staged writes in ONE PR. Use when several files belong to one logical change. |
| `get_app_status(repo)` | Latest commit, pinned images, latest build run, open release-please PR, drift between main and deployed image — in one call. |
| `get_build_log(repo, run_id, failed_only?)` | Failed jobs' log tails for a workflow run. Defaults to failed-only. |
| `dispatch_workflow(repo, workflow?, ref?)` | Trigger `build-image.yml` (or any workflow) via `workflow_dispatch`. Useful when the release-please→build chain misfires. |
| `list_pending_writes` | The user's pending writes. |

## Platform-managed paths are off-limits

`read_file`, `list_files`, `write_file`, and `confirm_write` all refuse paths under:

- `.github/` — CI workflows, dependabot, CODEOWNERS. A malicious workflow could exfiltrate secrets on next build.
- `deploy/` — Kubernetes manifests. A malicious NetworkPolicy or RBAC change could escalate privileges or expose internals.

`list_files` filters these out of root listings too, so the model doesn't even see they exist. Edit these through a normal PR with human review if you need to.

## Writes are two-step

To protect against prompt injection (the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)), the MCP never lets the model commit in a single step:

1. Model calls `write_file(...)` → MCP returns a diff and a confirmation token.
2. Chat client shows the diff to **you, the human**.
3. You approve. Model calls `confirm_write(token)` → MCP lands the change.

The token is single-use, expires after 5 minutes, lives only in MCP memory, and is scoped to the authenticated user (another user's token can't confirm your pending writes).

This is defense-in-depth, not magic. If you reflexively approve every diff, the protection collapses. Read the diff.

### What `confirm_write` does on a protected branch

Direct pushes to `main` (and `master`/`trunk`) are blocked by the platform's org-level ruleset, so `confirm_write` takes the PR path:

1. Creates a `vibe/<timestamp>-<random>` branch from the target branch's HEAD.
2. Commits the file there with the user's message as the commit subject.
3. Opens a PR with the same title, body cites the authenticating user.
4. Tries a direct squash-merge. If org rules block it (required checks, reviews), enables auto-merge instead so it lands when gates pass.

After merge, release-please opens a release PR for `feat:`/`fix:` commits and auto-merges it; `build-image` fires on the tag, opens an auto-merging pin PR, and Argo CD reconciles. End-to-end push-to-live is a few minutes (vs. the old ~50s push-to-main flow).

For non-protected branches (anything not in `{main, master, trunk}`), `confirm_write` commits directly — no PR.

### PAT permissions

Fine-grained PAT needs:

- Contents: read & write
- Metadata: read
- Pull requests: read & write *(new in 0.4 — needed for the branch+PR flow)*
- Administration: write *(only if you'll use `create_app` to generate repos from templates)*

## How a user authenticates

1. Create a **fine-grained PAT** at <https://github.com/settings/tokens?type=beta>:
   - Resource owner: `intility`
   - Repository access: pick the repos you want the MCP to touch (or "All repositories" if you want new apps you create to be auto-included).
   - Repository permissions: **Contents: read & write**, **Metadata: read**, **Administration: write** (the last is needed to create new repos from templates).
2. Paste the token into your chat client as the Bearer credential for this MCP.

GitHub's own scoping is the outer lock: even if the model is fully prompt-injected, it cannot reach repos outside what you ticked.

## Configure in a chat client

### Claude Desktop / Claude Code (custom headers)

```json
{
  "mcpServers": {
    "minato-vibe": {
      "url": "https://minato-vibe-mcp.aa349-1l5zl3.intility.dev/mcp",
      "headers": {
        "Authorization": "Bearer github_pat_xxx"
      }
    }
  }
}
```

### ChatGPT, Claude.ai web

These clients require full OAuth flow per the MCP spec. v0.3 supports Bearer tokens only; OAuth is a future version. Use Claude Desktop or Claude Code for now.

## Run locally

```sh
pip install -e .
MINATO_VIBE_MCP_PORT=8000 minato-vibe-mcp
# listens on http://127.0.0.1:8000/mcp
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MINATO_VIBE_MCP_HOST` | `0.0.0.0` | Bind address. |
| `MINATO_VIBE_MCP_PORT` | `8000` | Listen port. |
| `MINATO_VIBE_MCP_URL` | `http://localhost:8000` | Public URL of the MCP (used as the OAuth resource id in the protected-resource metadata). Set to the public ingress URL when deployed. |

## Architecture

```
   Chat client (Claude Desktop / Code / etc.)
            │  MCP over Streamable HTTP
            │  Authorization: Bearer <user's GitHub PAT>
            ▼
   minato-vibe-mcp  (this server, single replica)
            │
            └──► api.github.com  (as the authenticated user)
```

No subprocess wrapper, no shared credentials, no Postgres. Per-user pending writes in memory (lost on restart; users just re-stage).

## Known gaps (v0.3)

- No OAuth flow yet — Bearer PAT only. Limits which chat clients work out of the box.
- No deploy-status tool (`get_deploy_status` was descoped; check GitHub Actions or `kubectl get application -n argocd` for now).
- Pending writes are in-memory; restart wipes them.
- A confused model can still commit broken code *to repos the user's token allows*. Recovery is `git revert` on GitHub.
