from __future__ import annotations

import base64
import difflib
import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import Context, FastMCP

from .catalog import TEMPLATES, get_template

OWNER = "intility"
PLATFORM_REPO = "minato-vibe"
APP_URL_BASE = "aa349-1l5zl3.intility.dev"
GITHUB_MCP_IMAGE_DEFAULT = "ghcr.io/github/github-mcp-server:latest"
PENDING_WRITE_TTL_SECONDS = 300

DNS_1123 = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


@dataclass
class AppContext:
    gh: ClientSession
    token: str


@dataclass
class PendingWrite:
    repo: str
    path: str
    content: str
    message: str
    branch: str
    created_at: float


_pending_writes: dict[str, PendingWrite] = {}


def _gc_pending_writes() -> None:
    now = time.time()
    expired = [
        t
        for t, p in _pending_writes.items()
        if now - p.created_at > PENDING_WRITE_TTL_SECONDS
    ]
    for t in expired:
        del _pending_writes[t]


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
    except Exception as e:  # binary content, etc.
        return f"(could not compute diff: {e})"


def _github_mcp_params(token: str) -> StdioServerParameters:
    """Build params to spawn github-mcp-server.

    Defaults to Docker; opt out by setting GITHUB_MCP_COMMAND to a native binary
    path (e.g. /usr/local/bin/github-mcp-server). When using the native binary,
    we pass `stdio` as the only arg.
    """
    custom_command = os.environ.get("GITHUB_MCP_COMMAND")
    if custom_command:
        return StdioServerParameters(
            command=custom_command,
            args=["stdio"],
            env={"GITHUB_PERSONAL_ACCESS_TOKEN": token},
        )
    image = os.environ.get("GITHUB_MCP_IMAGE", GITHUB_MCP_IMAGE_DEFAULT)
    return StdioServerParameters(
        command="docker",
        args=[
            "run",
            "-i",
            "--rm",
            "-e",
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            image,
        ],
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": token},
    )


@asynccontextmanager
async def lifespan(_server: FastMCP) -> AsyncIterator[AppContext]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get(
        "GITHUB_PERSONAL_ACCESS_TOKEN"
    )
    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN (or GITHUB_PERSONAL_ACCESS_TOKEN) must be set in the "
            "environment. The token needs `repo` scope."
        )

    params = _github_mcp_params(token)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield AppContext(gh=session, token=token)


mcp = FastMCP(
    "minato-vibe-mcp",
    instructions=(
        "Tools for creating and editing apps on the minato-vibe Kubernetes "
        "platform. Use `list_templates` + `create_app` to scaffold a new "
        "app, and `read_file`/`list_files`/`write_file`/`confirm_write` to "
        "vibecode against an existing one. All operations target the "
        "`intility` org. Writes to `main` deploy automatically in ~50s via "
        "the platform's GitOps loop.\n\n"
        "WRITES ARE TWO-STEP: `write_file` returns a diff + a confirmation "
        "token but does NOT commit. The user must approve, then call "
        "`confirm_write(token)` to actually commit. Always show the diff to "
        "the user and wait for explicit approval before confirming. This "
        "is the security boundary that protects against prompt injection."
    ),
    lifespan=lifespan,
)


def _ctx(ctx: Context) -> AppContext:
    return ctx.request_context.lifespan_context  # type: ignore[return-value]


def _validate_name(name: str) -> None:
    if len(name) > 63:
        raise ValueError(f"name must be ≤63 chars (got {len(name)})")
    if not DNS_1123.match(name):
        raise ValueError(
            f"'{name}' is not a valid DNS-1123 label. Use lowercase letters, "
            "digits, and hyphens; start with a letter; no trailing hyphen."
        )


def _unwrap(result) -> str:
    if result.isError:
        msg = "; ".join(getattr(b, "text", str(b)) for b in result.content)
        raise RuntimeError(f"github-mcp-server: {msg}")
    for block in result.content:
        if hasattr(block, "text"):
            return block.text
    return ""


def _maybe_json(text: str):
    s = text.lstrip()
    if s.startswith(("{", "[")):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return text


@mcp.tool()
def list_templates() -> dict:
    """List the available golden-path templates for the minato-vibe platform.

    Returns each template's `name` (use this as the `template` arg to
    `create_app`), `stack`, `use_when` guidance, and a `prefilled_url` for the
    GitHub manual-create flow if the user prefers to click through.
    """
    return {"templates": TEMPLATES, "owner": OWNER, "app_url_base": APP_URL_BASE}


@mcp.tool()
async def create_app(
    ctx: Context,
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

    `template` must be one of the names returned by `list_templates`.
    """
    _validate_name(name)
    tmpl = get_template(template)
    if tmpl is None:
        valid = ", ".join(t["name"] for t in TEMPLATES)
        raise ValueError(f"unknown template '{template}'. valid: {valid}")

    # github-mcp-server doesn't expose POST /repos/{owner}/{repo}/generate, so
    # call it directly. This is the only direct GitHub API call we make; every
    # other operation goes through github-mcp-server.
    payload: dict = {
        "owner": OWNER,
        "name": name,
        "private": private,
        "include_all_branches": False,
    }
    if description:
        payload["description"] = description

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(
            f"https://api.github.com/repos/{OWNER}/{template}/generate",
            json=payload,
            headers={
                "Authorization": f"Bearer {_ctx(ctx).token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    if r.status_code not in (201, 202):
        raise RuntimeError(
            f"GitHub returned {r.status_code} creating repo from template: "
            f"{r.text}"
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
async def read_file(
    ctx: Context, repo: str, path: str, ref: str | None = None
) -> dict:
    """Read a file from a platform app's repo (under intility/).

    Returns the file's content (decoded if base64) and `sha`. The `sha` is not
    required for subsequent `write_file` calls — github-mcp-server handles that
    round-trip internally.
    """
    args: dict = {"owner": OWNER, "repo": repo, "path": path}
    if ref:
        args["ref"] = ref
    result = await _ctx(ctx).gh.call_tool("get_file_contents", args)
    text = _unwrap(result)
    data = _maybe_json(text)
    if isinstance(data, dict) and data.get("encoding") == "base64" and "content" in data:
        try:
            data["content"] = base64.b64decode(data["content"]).decode("utf-8")
            data["encoding"] = "utf-8"
        except (UnicodeDecodeError, ValueError):
            pass
    return {"result": data}


@mcp.tool()
async def list_files(
    ctx: Context, repo: str, path: str = "", ref: str | None = None
) -> dict:
    """List files in a directory of a platform app's repo (under intility/).

    Pass `path=""` for the repo root. `ref` defaults to the repo's default
    branch.
    """
    args: dict = {"owner": OWNER, "repo": repo, "path": path}
    if ref:
        args["ref"] = ref
    result = await _ctx(ctx).gh.call_tool("get_file_contents", args)
    text = _unwrap(result)
    return {"result": _maybe_json(text)}


async def _read_current_for_diff(
    ctx: Context, repo: str, path: str, branch: str
) -> str | None:
    """Best-effort read of the current file so we can show a diff. Returns
    None if the file doesn't exist or can't be decoded as text."""
    args: dict = {"owner": OWNER, "repo": repo, "path": path, "ref": branch}
    try:
        result = await _ctx(ctx).gh.call_tool("get_file_contents", args)
    except Exception:
        return None
    if result.isError:
        return None
    text = _unwrap(result)
    data = _maybe_json(text)
    if isinstance(data, dict):
        encoding = data.get("encoding")
        content = data.get("content")
        if encoding == "base64" and isinstance(content, str):
            try:
                return base64.b64decode(content).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                return None
        if isinstance(content, str):
            return content
    return None


@mcp.tool()
async def write_file(
    ctx: Context,
    repo: str,
    path: str,
    content: str,
    message: str,
    branch: str = "main",
) -> dict:
    """STEP 1 OF 2: stage a file write and return a diff for the user to review.

    This does NOT commit. It returns a unified diff against the current file
    (or "/dev/null" if the file is new), plus a confirmation token. Show the
    diff to the user. Once they explicitly approve, call `confirm_write(token)`
    to actually commit.

    The token is valid for 5 minutes. After it expires, call `write_file`
    again. The token can only be used once.

    Writing to `main` (the default) triggers the platform deploy loop:
    `build-image.yml` builds and pushes `ghcr.io/intility/<repo>:sha-...`,
    rewrites the kustomization `newTag`, and Argo CD reconciles the pod.
    Steady-state ~50s to live.
    """
    _gc_pending_writes()

    before = await _read_current_for_diff(ctx, repo, path, branch)
    diff = _make_diff(before, content, path)
    token = secrets.token_urlsafe(12)
    _pending_writes[token] = PendingWrite(
        repo=repo,
        path=path,
        content=content,
        message=message,
        branch=branch,
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
async def confirm_write(ctx: Context, token: str) -> dict:
    """STEP 2 OF 2: commit a write previously staged by `write_file`.

    Only call this AFTER the user has seen the diff returned by `write_file`
    and explicitly approved the change. The token is single-use and expires
    5 minutes after `write_file` was called.
    """
    _gc_pending_writes()

    pending = _pending_writes.pop(token, None)
    if pending is None:
        raise ValueError(
            "Unknown or expired confirmation token. Call write_file again "
            "to stage the change and get a fresh token."
        )

    args: dict = {
        "owner": OWNER,
        "repo": pending.repo,
        "path": pending.path,
        "content": pending.content,
        "message": pending.message,
        "branch": pending.branch,
    }
    result = await _ctx(ctx).gh.call_tool("create_or_update_file", args)
    text = _unwrap(result)
    return {
        "status": "committed",
        "target": f"{OWNER}/{pending.repo}@{pending.branch}:{pending.path}",
        "result": _maybe_json(text),
    }


@mcp.tool()
def list_pending_writes() -> dict:
    """List staged writes that haven't been confirmed yet.

    Useful when a `write_file` token has been lost track of, or to audit
    what's in flight. Pending writes auto-expire after 5 minutes.
    """
    _gc_pending_writes()
    now = time.time()
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
            for t, p in _pending_writes.items()
        ]
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
