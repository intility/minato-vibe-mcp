from __future__ import annotations

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

DNS_1123 = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


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
        "Use `list_templates` + `create_app` to scaffold a new app, and "
        "`read_file`/`list_files`/`write_file`/`confirm_write` to vibecode "
        "against an existing one. Writes to `main` deploy automatically in "
        "~50s via the platform's GitOps loop.\n\n"
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
    private: bool = False,
    description: str | None = None,
) -> dict:
    """Create a new platform app from a template.

    The repo is created under `intility/<name>`. On the first push (triggered
    automatically by template generation), `template-init.yml` substitutes
    placeholders, registers the app at intility/minato-vibe/apps/<name>.yaml,
    and self-deletes. The app reaches its URL in ~50 seconds.

    Runs as the authenticated GitHub user; the user must be a member of the
    `intility` org with permission to create repos.
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
        private=private,
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
    """Read a file from a platform app's repo (under intility/)."""
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
    """List files in a directory of a platform app's repo (under intility/)."""
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
            ]
        }
    return {"raw": data}


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
    """
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


@mcp.tool()
async def confirm_write(token: str) -> dict:
    """STEP 2 OF 2: commit a write previously staged by `write_file`.

    Only call after the user has seen the diff and explicitly approved.
    Single-use; expires 5 minutes after staging; scoped to the authenticated
    user (you can't confirm another user's pending writes).
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
