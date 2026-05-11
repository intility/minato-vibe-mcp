from __future__ import annotations

import asyncio
import difflib
import os
import re
import secrets
import time
from dataclasses import dataclass

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from .auth import GitHubPATVerifier
from .catalog import TEMPLATES, get_template
from .github_api import GitHubClient, decode_file_content

OWNER = "intility"
PLATFORM_REPO = "minato-vibe"
APP_URL_BASE = os.environ.get("MINATO_VIBE_APP_URL_BASE", "vibe.intility.dev")
PENDING_WRITE_TTL_SECONDS = 300

# Path prefixes the MCP refuses to read, write, or list. These are
# platform-managed (CI workflows, k8s manifests) — vibecoding them would
# let a prompt-injected model escalate to secret exfiltration via CI,
# privilege changes via RBAC, or break the deploy loop. Edit them through
# a normal PR with human review.
BLOCKED_PATH_PREFIXES = (".github", "deploy")

DNS_1123 = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


def _normalize_path(path: str) -> str:
    p = path.strip()
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/").lower()


def _is_blocked_path(path: str) -> bool:
    p = _normalize_path(path)
    for prefix in BLOCKED_PATH_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            return True
    return False


def _ensure_not_blocked(path: str) -> None:
    if _is_blocked_path(path):
        raise PermissionError(
            f"path '{path}' is in the platform-managed area "
            f"({', '.join(BLOCKED_PATH_PREFIXES)}/). The MCP refuses to "
            "read, write, or list these — they affect CI, deployment, and "
            "security boundaries and shouldn't be vibe-coded. Edit them "
            "through a normal PR if you really need to."
        )


# Module-level httpx client. The streamable-http transport's auth path runs
# before any MCP session lifespan, so we can't use lifespan to manage this.
# A single AsyncClient lives for the process lifetime; httpx handles pooling.
_HTTP = httpx.AsyncClient(timeout=30.0)


@dataclass
class PendingWrite:
    repo: str
    path: str
    content: str
    message: str
    branch: str
    sha: str | None
    created_at: float


# Pending writes are scoped per user (keyed by GitHub login). A user can't
# see or confirm another user's pending writes even if they guess the token.
_pending_writes: dict[str, dict[str, PendingWrite]] = {}


def _gc_pending_writes() -> None:
    now = time.time()
    for user, by_token in list(_pending_writes.items()):
        expired = [
            t for t, p in by_token.items()
            if now - p.created_at > PENDING_WRITE_TTL_SECONDS
        ]
        for t in expired:
            del by_token[t]
        if not by_token:
            del _pending_writes[user]


def _make_diff(before: str | None, after: str, path: str) -> str:
    try:
        before_lines = (before or "").splitlines(keepends=True)
        after_lines = after.splitlines(keepends=True)
        diff = "".join(
            difflib.unified_diff(
                before_lines,
                after_lines,
                fromfile="/dev/null" if before is None else f"a/{path}",
                tofile=f"b/{path}",
                n=3,
            )
        )
        return diff or "(no textual changes)"
    except Exception as e:
        return f"(could not compute diff: {e})"


def _current_user() -> tuple[GitHubClient, str]:
    """Resolve the authenticated user from the request context. Returns
    (GitHub API client bound to their token, GitHub login)."""
    access = get_access_token()
    if access is None:
        raise PermissionError(
            "Not authenticated. The MCP requires a GitHub personal access "
            "token as a Bearer token."
        )
    return GitHubClient(access.token, _HTTP), access.client_id


def _resource_url() -> str:
    """The public URL of this MCP server, used as the OAuth resource id.
    Override with MINATO_VIBE_MCP_URL when running behind a different hostname."""
    return os.environ.get(
        "MINATO_VIBE_MCP_URL", "http://localhost:8000"
    )


# The verifier needs the http client; we construct it after lifespan starts.
# FastMCP requires the verifier at construction time, so we use a thin
# indirection that picks up the shared client lazily.
_VERIFIER = GitHubPATVerifier(_HTTP)


mcp: FastMCP = FastMCP(
    "minato-vibe-mcp",
    instructions=(
        "Tools for creating and editing apps on the minato-vibe Kubernetes "
        "platform. Each user authenticates with their own GitHub personal "
        "access token, which is also the Bearer token for the MCP. All "
        "operations run as the authenticated GitHub user.\n\n"
        "EXPLORATION — when starting on a repo, call `repo_overview(repo)` "
        "FIRST. It returns the full file tree plus README and common "
        "manifests (package.json, pyproject.toml, go.mod, justfile, "
        "Dockerfile) in a single round-trip. This replaces 10+ "
        "list_files/read_file calls. For multiple specific files, use "
        "`read_files(repo, paths)` to fetch them in parallel — not a loop "
        "of read_file calls.\n\n"
        "CREATION — `list_templates` + `create_app` to scaffold a new app.\n\n"
        "EDITING — `write_file` then `confirm_write` to land a change. "
        "Writes to `main` go through a PR that auto-merges; "
        "release-please then drives the release + build + deploy. End to "
        "end push-to-live is a few minutes.\n\n"
        "WRITES ARE TWO-STEP: `write_file` stages a change and returns a "
        "diff + confirmation token but does NOT commit. The human must "
        "approve, then `confirm_write(token)` commits. Always show the diff "
        "and wait for explicit user approval. This is the security boundary "
        "that protects against prompt injection."
    ),
    token_verifier=_VERIFIER,
    auth=AuthSettings(
        issuer_url=_resource_url(),  # type: ignore[arg-type]
        resource_server_url=_resource_url(),  # type: ignore[arg-type]
    ),
    host=os.environ.get("MINATO_VIBE_MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("MINATO_VIBE_MCP_PORT", "8000")),
    stateless_http=True,
)


def _validate_name(name: str) -> None:
    if len(name) > 63:
        raise ValueError(f"name must be ≤63 chars (got {len(name)})")
    if not DNS_1123.match(name):
        raise ValueError(
            f"'{name}' is not a valid DNS-1123 label. Use lowercase letters, "
            "digits, and hyphens; start with a letter; no trailing hyphen."
        )


@mcp.tool()
def list_templates() -> dict:
    """List the available golden-path templates for the minato-vibe platform."""
    return {"templates": TEMPLATES, "owner": OWNER, "app_url_base": APP_URL_BASE}


@mcp.tool()
async def whoami() -> dict:
    """Return the GitHub identity associated with the current Bearer token."""
    gh, login = _current_user()
    user = await gh.whoami()
    return {
        "login": login,
        "name": user.get("name"),
        "html_url": user.get("html_url"),
    }


@mcp.tool()
async def create_app(
    name: str,
    template: str = "react-vibe-template",
    description: str | None = None,
) -> dict:
    """Create a new private platform app from a template.

    The repo is created under `intility/<name>` as PRIVATE. There is no
    option to make it public — the MCP refuses to ever create a public
    repo, because vibe-coded apps may contain code or data that should
    not leak. If you genuinely need a public repo, flip its visibility
    on GitHub after creation (the model can't do that through this MCP).

    On the first push (triggered automatically by template generation),
    `template-init.yml` substitutes placeholders, registers the app at
    intility/minato-vibe/apps/<name>.yaml, and self-deletes. The app
    reaches its URL in ~50 seconds.

    Runs as the authenticated GitHub user; the user must be a member of
    the `intility` org with permission to create repos.
    """
    _validate_name(name)
    tmpl = get_template(template)
    if tmpl is None:
        valid = ", ".join(t["name"] for t in TEMPLATES)
        raise ValueError(f"unknown template '{template}'. valid: {valid}")

    gh, _ = _current_user()
    await gh.generate_from_template(
        template_owner=tmpl["template_owner"],
        template_repo=tmpl["template_repo"],
        owner=OWNER,
        name=name,
        private=True,  # hardcoded; never user-controllable
        description=description,
    )
    return {
        "repo": f"{OWNER}/{name}",
        "repo_url": f"https://github.com/{OWNER}/{name}",
        "expected_app_url": f"https://{name}.{APP_URL_BASE}",
        "template": template,
        "next": (
            f"template-init.yml will run on the new repo, substitute "
            f"placeholders, and write apps/{name}.yaml back to "
            f"intility/minato-vibe. The app should be live at "
            f"https://{name}.{APP_URL_BASE} in ~50 seconds."
        ),
    }


@mcp.tool()
async def read_file(repo: str, path: str, ref: str | None = None) -> dict:
    """Read a file from a platform app's repo (under intility/).

    The MCP refuses paths under `.github/` and `deploy/` — those are
    platform-managed (CI, k8s manifests) and not vibe-codable.
    """
    _ensure_not_blocked(path)
    gh, _ = _current_user()
    data = await gh.get_contents(OWNER, repo, path, ref)
    if isinstance(data, dict):
        decoded = decode_file_content(data)
        if decoded is not None:
            return {
                "path": data.get("path"),
                "sha": data.get("sha"),
                "size": data.get("size"),
                "content": decoded,
                "encoding": "utf-8",
            }
        return {"raw": data}
    return {"raw": data}


@mcp.tool()
async def list_files(repo: str, path: str = "", ref: str | None = None) -> dict:
    """List files in a directory of a platform app's repo (under intility/).

    The MCP refuses to list inside `.github/` or `deploy/`, and filters
    those entries out of root listings — they're platform-managed and
    intentionally hidden from vibe-coding.
    """
    if path:
        _ensure_not_blocked(path)
    gh, _ = _current_user()
    data = await gh.get_contents(OWNER, repo, path, ref)
    if isinstance(data, list):
        return {
            "entries": [
                {
                    "name": e.get("name"),
                    "path": e.get("path"),
                    "type": e.get("type"),
                    "size": e.get("size"),
                    "sha": e.get("sha"),
                }
                for e in data
                if not _is_blocked_path(e.get("path") or "")
            ]
        }
    return {"raw": data}


# Files to fetch alongside the tree in repo_overview. Most apps will have a
# subset; we fetch whichever exist at the root in parallel.
_OVERVIEW_KEY_FILES = (
    "README.md",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "justfile",
    "Dockerfile",
)


@mcp.tool()
async def repo_overview(repo: str, ref: str = "main") -> dict:
    """One-shot orientation for a platform app's repo. CALL THIS FIRST when
    you're starting work on a repo you haven't seen — it returns the full
    file tree plus README and common manifest files (package.json,
    pyproject.toml, go.mod, justfile, Dockerfile if they exist) in a single
    network round-trip. Saves you 10+ list_files / read_file calls.

    Use `list_files` and `read_file` for targeted lookups after this.
    Blocked paths (`.github/`, `deploy/`) are filtered from the tree.
    """
    gh, _ = _current_user()

    tree = await gh.get_tree(OWNER, repo, ref, recursive=True)

    entries = [
        {
            "path": e["path"],
            "type": e["type"],
            "size": e.get("size"),
        }
        for e in tree.get("tree", [])
        if not _is_blocked_path(e.get("path") or "")
    ]

    # Find which of the well-known manifest files exist at the repo root.
    root_blobs = {
        e["path"] for e in entries
        if e["type"] == "blob" and "/" not in e["path"]
    }
    to_fetch = [name for name in _OVERVIEW_KEY_FILES if name in root_blobs]

    async def _fetch_one(path: str) -> tuple[str, str | None]:
        try:
            data = await gh.get_contents(OWNER, repo, path, ref=ref)
            if isinstance(data, dict):
                return path, decode_file_content(data)
        except Exception:
            pass
        return path, None

    results = await asyncio.gather(*(_fetch_one(p) for p in to_fetch))
    key_files = {p: c for p, c in results if c is not None}

    return {
        "repo": f"{OWNER}/{repo}",
        "ref": ref,
        "tree": entries,
        "truncated": tree.get("truncated", False),
        "key_files": key_files,
    }


@mcp.tool()
async def read_files(
    repo: str, paths: list[str], ref: str | None = None
) -> dict:
    """Read multiple files from a platform app's repo in parallel. Use this
    instead of multiple `read_file` calls — one chat-client→MCP round-trip
    instead of N, and the GitHub fetches happen concurrently.

    Refuses any path under `.github/` or `deploy/`.
    """
    for p in paths:
        _ensure_not_blocked(p)
    gh, _ = _current_user()

    async def _fetch_one(path: str) -> tuple[str, dict]:
        try:
            data = await gh.get_contents(OWNER, repo, path, ref)
            if isinstance(data, dict):
                content = decode_file_content(data)
                return path, {
                    "content": content,
                    "sha": data.get("sha"),
                    "size": data.get("size"),
                    "encoding": "utf-8" if content is not None else data.get("encoding"),
                }
            return path, {"error": "path is a directory, not a file"}
        except httpx.HTTPStatusError as e:
            return path, {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            return path, {"error": str(e)}

    results = await asyncio.gather(*(_fetch_one(p) for p in paths))
    return {"files": dict(results)}


@mcp.tool()
async def write_file(
    repo: str,
    path: str,
    content: str,
    message: str,
    branch: str = "main",
) -> dict:
    """STEP 1 OF 2: stage a file write and return a diff for the user.

    Does NOT commit. Returns a unified diff against the current file
    (or "/dev/null" if the file is new) plus a confirmation token. Show
    the diff to the user and wait for their explicit approval, then call
    `confirm_write(token)`.

    The token is single-use, valid for 5 minutes, and scoped to the
    authenticated user. Writes to `main` trigger the platform deploy loop.

    Paths under `.github/` and `deploy/` are refused — those are
    platform-managed (CI, k8s) and not vibe-codable.
    """
    _ensure_not_blocked(path)
    _gc_pending_writes()
    gh, login = _current_user()

    # Fetch current file (if any) for diff and sha.
    before: str | None = None
    sha: str | None = None
    try:
        current = await gh.get_contents(OWNER, repo, path, ref=branch)
        if isinstance(current, dict):
            sha = current.get("sha")
            before = decode_file_content(current)
    except httpx.HTTPStatusError as e:
        if e.response.status_code != 404:
            raise

    diff = _make_diff(before, content, path)
    token = secrets.token_urlsafe(12)
    _pending_writes.setdefault(login, {})[token] = PendingWrite(
        repo=repo,
        path=path,
        content=content,
        message=message,
        branch=branch,
        sha=sha,
        created_at=time.time(),
    )
    return {
        "status": "awaiting_confirmation",
        "confirmation_token": token,
        "expires_in_seconds": PENDING_WRITE_TTL_SECONDS,
        "target": f"{OWNER}/{repo}@{branch}:{path}",
        "commit_message": message,
        "diff": diff,
        "is_new_file": before is None,
        "next": (
            "Show the diff to the user. Only after they explicitly approve, "
            f"call confirm_write(token='{token}'). Do not auto-confirm."
        ),
    }


# Branches that have org-level branch protection (no direct push, PR required).
# Writes targeting these go through a vibe/<id> branch + auto-merging PR; writes
# to other branches commit directly.
PROTECTED_BRANCHES = frozenset({"main", "master", "trunk"})


@mcp.tool()
async def confirm_write(token: str) -> dict:
    """STEP 2 OF 2: commit a write previously staged by `write_file`.

    Only call after the user has seen the diff and explicitly approved.
    Single-use; expires 5 minutes after staging; scoped to the authenticated
    user (you can't confirm another user's pending writes).

    Writes targeting a protected branch (main/master/trunk) take the
    PR-based path required by the platform's stricter deploy model:
    commit lands on a vibe/<id> branch, a PR is opened with the user's
    message as title, and the MCP tries to squash-merge it. If org rules
    block the direct merge (required checks, reviews, etc.), the MCP
    enables auto-merge so it lands as soon as gates pass. End-to-end
    push-to-live is a few minutes (release-please + pin PR cycle).
    """
    _gc_pending_writes()
    gh, login = _current_user()

    user_pending = _pending_writes.get(login, {})
    pending = user_pending.pop(token, None)
    if pending is None:
        raise ValueError(
            "Unknown or expired confirmation token. Call write_file again "
            "to stage the change and get a fresh token."
        )
    _ensure_not_blocked(pending.path)

    if pending.branch not in PROTECTED_BRANCHES:
        # Unprotected branch — direct commit.
        result = await gh.put_contents(
            owner=OWNER,
            repo=pending.repo,
            path=pending.path,
            content=pending.content,
            message=pending.message,
            branch=pending.branch,
            sha=pending.sha,
        )
        return {
            "status": "committed",
            "target": f"{OWNER}/{pending.repo}@{pending.branch}:{pending.path}",
            "commit": {
                "sha": (result.get("commit") or {}).get("sha"),
                "html_url": (result.get("commit") or {}).get("html_url"),
            },
            "content_sha": (result.get("content") or {}).get("sha"),
        }

    # Protected branch — branch + commit + PR + merge dance.
    base_ref = await gh.get_ref(OWNER, pending.repo, f"heads/{pending.branch}")
    base_sha = base_ref["object"]["sha"]

    branch_name = f"vibe/{int(time.time())}-{secrets.token_hex(3)}"
    await gh.create_ref(
        OWNER, pending.repo, f"refs/heads/{branch_name}", base_sha
    )

    commit_result = await gh.put_contents(
        owner=OWNER,
        repo=pending.repo,
        path=pending.path,
        content=pending.content,
        message=pending.message,
        branch=branch_name,
        sha=pending.sha,
    )

    pr = await gh.create_pull_request(
        owner=OWNER,
        repo=pending.repo,
        head=branch_name,
        base=pending.branch,
        title=pending.message,
        body=(
            f"Vibe-coded via minato-vibe-mcp.\n\n"
            f"Approved by @{login} via `confirm_write`. "
            f"File: `{pending.path}`."
        ),
    )

    # Try direct squash merge. If org rules block it (required checks etc.),
    # fall back to enabling auto-merge so it lands when gates pass.
    merge_status, _ = await gh.merge_pull_request(
        OWNER, pending.repo, pr["number"], "squash"
    )
    merge_state: str
    if merge_status == 200:
        merge_state = "merged"
    else:
        try:
            await gh.enable_auto_merge(pr["node_id"], "SQUASH")
            merge_state = "auto_merge_enabled"
        except Exception:
            merge_state = "pr_open_needs_manual_merge"

    return {
        "status": merge_state,
        "target": f"{OWNER}/{pending.repo}@{pending.branch}:{pending.path}",
        "pr_url": pr["html_url"],
        "pr_number": pr["number"],
        "branch": branch_name,
        "commit_sha": (commit_result.get("commit") or {}).get("sha"),
        "next": (
            "release-please will open a release PR for any feat:/fix: "
            "commits and auto-merge it; build-image then fires on the "
            "tag, opens an auto-merging pin PR, and Argo CD reconciles. "
            "Few minutes end-to-end."
        ),
    }


@mcp.tool()
async def list_pending_writes() -> dict:
    """List the authenticated user's staged writes that haven't been confirmed."""
    _gc_pending_writes()
    _, login = _current_user()
    now = time.time()
    user_pending = _pending_writes.get(login, {})
    return {
        "pending": [
            {
                "confirmation_token": t,
                "target": f"{OWNER}/{p.repo}@{p.branch}:{p.path}",
                "commit_message": p.message,
                "age_seconds": int(now - p.created_at),
                "expires_in_seconds": max(
                    0, PENDING_WRITE_TTL_SECONDS - int(now - p.created_at)
                ),
            }
            for t, p in user_pending.items()
        ]
    }


def main() -> None:
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
