from __future__ import annotations

import base64
import json
import os
import re
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

DNS_1123 = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


@dataclass
class AppContext:
    gh: ClientSession
    token: str


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
        "platform. Use `list_templates` to see what's available, `create_app` "
        "to scaffold a new one from a template, and `read_file`/`write_file`/"
        "`list_files` to vibecode against an existing app. All operations "
        "target the `intility` org. Writes to `main` deploy automatically in "
        "~50 seconds via the platform's GitOps loop."
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


@mcp.tool()
async def write_file(
    ctx: Context,
    repo: str,
    path: str,
    content: str,
    message: str,
    branch: str = "main",
) -> dict:
    """Write a file to a platform app's repo and commit.

    A push to `main` triggers the platform deploy loop: `build-image.yml`
    builds and pushes `ghcr.io/intility/<repo>:sha-...`, rewrites the
    kustomization `newTag`, and Argo CD reconciles the pod. Steady-state ~50s
    to live.

    No PR mode — the platform's whole pitch is push-to-deploy. If the user
    wants a review step, they should open a PR through GitHub directly.
    """
    args: dict = {
        "owner": OWNER,
        "repo": repo,
        "path": path,
        "content": content,
        "message": message,
        "branch": branch,
    }
    result = await _ctx(ctx).gh.call_tool("create_or_update_file", args)
    text = _unwrap(result)
    return {"result": _maybe_json(text)}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
