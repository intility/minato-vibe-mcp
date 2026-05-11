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
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .auth import GitHubPATVerifier
from .catalog import TEMPLATES, get_template
from .conventions import CONVENTIONS, get_conventions, list_template_names
from .github_api import GitHubClient, decode_file_content
from .oauth import build_oauth_provider
from .validation import validate_content

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
    (GitHub API client bound to their upstream GitHub token, GitHub login).

    Handles both shapes: OAuth-issued MCP tokens (where access.token is OUR
    token and we look up the upstream GitHub token internally) and raw PATs
    (where access.token IS the GitHub token)."""
    access = get_access_token()
    if access is None:
        raise PermissionError(
            "Not authenticated. Connect via OAuth or pass a GitHub PAT as "
            "the Bearer token."
        )
    if _OAUTH_PROVIDER is not None:
        upstream = _OAUTH_PROVIDER.lookup_github_token(access.token)
        if upstream is not None:
            gh_token, login = upstream
            return GitHubClient(gh_token, _HTTP), login
    # PAT fallback: the bearer IS the GitHub token.
    return GitHubClient(access.token, _HTTP), access.client_id


def _base_url() -> str:
    """The public base URL of this MCP. Hosts /.well-known endpoints and
    /authorize, /token, /register. Override with MINATO_VIBE_MCP_URL."""
    return os.environ.get(
        "MINATO_VIBE_MCP_URL", "http://localhost:8000"
    ).rstrip("/")


def _mcp_resource_url() -> str:
    """The canonical URI of the MCP HTTP endpoint itself — what the chat
    client uses as the OAuth resource indicator. MUST end in /mcp."""
    return f"{_base_url()}/mcp"


# OAuth wiring. If GITHUB_OAUTH_CLIENT_ID/SECRET are set, the MCP runs as a
# full OAuth 2.1 Authorization Server with GitHub as the upstream IdP — chat
# clients use the standard login popup. If those env vars are unset, we fall
# back to the simpler "user pastes a GitHub PAT as Bearer token" path. Either
# way, OAuth-issued MCP tokens AND raw GitHub PATs both work end-to-end —
# tokens are routed through one provider that handles both shapes.
_OAUTH_PROVIDER = build_oauth_provider(_HTTP, _base_url())

if _OAUTH_PROVIDER is not None:
    _AUTH_SETTINGS = AuthSettings(
        issuer_url=_base_url(),  # type: ignore[arg-type]
        resource_server_url=_mcp_resource_url(),  # type: ignore[arg-type]
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["repo", "read:org"],
            default_scopes=["repo", "read:org"],
        ),
    )
    _MCP_AUTH_KWARGS: dict = {
        "auth_server_provider": _OAUTH_PROVIDER,
        "auth": _AUTH_SETTINGS,
    }
else:
    _MCP_AUTH_KWARGS = {
        "token_verifier": GitHubPATVerifier(_HTTP),
        "auth": AuthSettings(
            issuer_url=_base_url(),  # type: ignore[arg-type]
            resource_server_url=_mcp_resource_url(),  # type: ignore[arg-type]
        ),
    }


mcp: FastMCP = FastMCP(
    "minato-vibe-mcp",
    instructions=(
        "Tools for creating and editing apps on the minato-vibe Kubernetes "
        "platform. Each user authenticates with their own GitHub personal "
        "access token, which is also the Bearer token for the MCP. All "
        "operations run as the authenticated GitHub user.\n\n"
        "EXPLORATION — when starting on a repo, call `repo_overview(repo)` "
        "FIRST. It returns the full file tree plus README and common "
        "manifests in a single round-trip, replacing 10+ list_files/"
        "read_file calls. For multiple specific files, use "
        "`read_files(repo, paths)` to fetch them in parallel. Before "
        "writing significant code, call `get_template_conventions(template)` "
        "to learn the project's non-obvious lint rules (strict-mode TS, "
        "Biome warnings, React compiler rules, Go stdlib-only conventions) "
        "so the first PR doesn't fail CI.\n\n"
        "STATUS — `get_app_status(repo)` returns latest commit, pinned "
        "images, latest build run, open release-please PR, and drift in "
        "one call. If a build failed, `get_build_log(repo, run_id)` "
        "returns just the failed jobs' log tails. To force a rebuild, "
        "`dispatch_workflow(repo)` triggers `build-image.yml`.\n\n"
        "CREATION — `list_templates` + `create_app` to scaffold a new app.\n\n"
        "EDITING — stage each change with `write_file`, then commit. "
        "For a SINGLE file: `confirm_write(token)`. For MULTIPLE files "
        "that belong to ONE logical change (a feature, a refactor): stage "
        "each with `write_file`, then land them all in ONE PR with "
        "`confirm_writes([token1, token2, ...], message)`. Each "
        "`confirm_write` opens a separate PR which triggers a separate "
        "release-please + build + deploy cycle — batch when you can.\n\n"
        "Writes to `main` go through a PR that auto-merges; "
        "release-please then drives the release + build + deploy. End to "
        "end push-to-live is a few minutes.\n\n"
        "WRITES ARE TWO-STEP: `write_file` stages a change and returns a "
        "diff + confirmation token but does NOT commit. The human must "
        "approve, then `confirm_write` or `confirm_writes` commits. "
        "Always show diffs and wait for explicit user approval before "
        "confirming. This is the security boundary that protects against "
        "prompt injection."
    ),
    host=os.environ.get("MINATO_VIBE_MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("MINATO_VIBE_MCP_PORT", "8000")),
    stateless_http=True,
    **_MCP_AUTH_KWARGS,
)


# GitHub OAuth return URL. GitHub redirects here with `?code=...&state=...`
# after the user authorizes. We swap the GitHub code for a GitHub token,
# mint our own auth code, and redirect the user back to the chat client's
# redirect_uri. Only registered when the OAuth provider is configured.
if _OAUTH_PROVIDER is not None:

    @mcp.custom_route("/oauth/callback", methods=["GET"])
    async def github_callback(request: Request) -> Response:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")
        if error:
            return HTMLResponse(
                f"<h1>GitHub authorization failed</h1><p>{error}</p>",
                status_code=400,
            )
        if not code or not state:
            return HTMLResponse(
                "<h1>Missing code or state</h1>",
                status_code=400,
            )
        try:
            redirect_url = await _OAUTH_PROVIDER.handle_github_callback(
                code=code, state=state
            )
        except Exception as e:
            return HTMLResponse(
                f"<h1>Authorization callback failed</h1><pre>{e}</pre>",
                status_code=400,
            )
        return RedirectResponse(redirect_url, status_code=302)


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
        "first_deploy_eta_minutes": "5-10",
        "subsequent_deploy_eta_seconds": "~50 (steady-state, once release-please is warm)",
        "next": (
            f"template-init.yml runs on the new repo, substitutes "
            f"placeholders, writes apps/{name}.yaml back to "
            f"intility/minato-vibe, and dispatches the first build. "
            f"First deploy takes 5-10 minutes (template-init + initial "
            f"release-please cycle + image build + pin PR + Argo CD "
            f"reconcile). Steady-state deploys after that are ~50s. "
            f"Use `get_app_status(name='{name}')` to watch progress; "
            f"final URL: https://{name}.{APP_URL_BASE}."
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

    # Cheap pre-stage validation: no-op detection + JSON/YAML/TOML/Python
    # syntax. Catches the obvious mistakes without running the real lint
    # pipeline. Real lint/typecheck still happens in CI.
    validation_errors = validate_content(path, content, before)
    if validation_errors:
        return {
            "status": "validation_failed",
            "target": f"{OWNER}/{repo}@{branch}:{path}",
            "errors": validation_errors,
            "next": (
                "Fix the issues above and call write_file again with "
                "corrected content. Nothing was staged."
            ),
        }

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
async def confirm_writes(
    tokens: list[str], message: str | None = None
) -> dict:
    """STEP 2 OF 2 (BATCH): land MULTIPLE staged writes in a SINGLE PR.

    Use this instead of calling `confirm_write` once per file when several
    `write_file` stagings belong to the same logical change. The platform's
    deploy model means each PR triggers a release-please cycle and a build;
    consolidating N file changes into one PR saves N-1 of those cycles.

    All tokens must:
      - Belong to the authenticated user
      - Target the same repo and the same branch
      - Be unexpired

    On a protected branch (main/master/trunk), the batch lands as one PR
    (one commit per file, squash-merged). On other branches, each file is
    committed directly to the target branch in sequence (no PR).

    `message`: PR/commit title. If omitted, the first staged write's
    message is used.
    """
    if not tokens:
        raise ValueError("tokens must not be empty")

    _gc_pending_writes()
    gh, login = _current_user()
    user_pending = _pending_writes.get(login, {})

    # Resolve tokens but don't pop yet — we want to fail atomically if any
    # token is invalid, leaving the rest staged.
    pendings: list = []
    for t in tokens:
        p = user_pending.get(t)
        if p is None:
            raise ValueError(
                f"Unknown or expired confirmation token: {t!r}. "
                "Re-stage with write_file."
            )
        pendings.append((t, p))

    # All-same-repo + all-same-branch invariant
    repo = pendings[0][1].repo
    branch = pendings[0][1].branch
    for _, p in pendings[1:]:
        if p.repo != repo:
            raise ValueError(
                f"All tokens must target the same repo. Got {repo} and {p.repo}."
            )
        if p.branch != branch:
            raise ValueError(
                f"All tokens must target the same branch. Got {branch} and {p.branch}."
            )
    for _, p in pendings:
        _ensure_not_blocked(p.path)

    title = message or pendings[0][1].message

    if branch not in PROTECTED_BRANCHES:
        # Direct commit each file to the target branch. No PR.
        commits = []
        for _, p in pendings:
            result = await gh.put_contents(
                owner=OWNER,
                repo=p.repo,
                path=p.path,
                content=p.content,
                message=p.message,
                branch=p.branch,
                sha=p.sha,
            )
            commits.append({
                "path": p.path,
                "sha": (result.get("commit") or {}).get("sha"),
            })
        # Only pop on success.
        for t, _ in pendings:
            user_pending.pop(t, None)
        return {
            "status": "committed",
            "target": f"{OWNER}/{repo}@{branch}",
            "commits": commits,
        }

    # Protected branch: one branch, N commits, one PR.
    base_ref = await gh.get_ref(OWNER, repo, f"heads/{branch}")
    base_sha = base_ref["object"]["sha"]
    branch_name = f"vibe/{int(time.time())}-{secrets.token_hex(3)}"
    await gh.create_ref(OWNER, repo, f"refs/heads/{branch_name}", base_sha)

    commits = []
    for _, p in pendings:
        result = await gh.put_contents(
            owner=OWNER,
            repo=repo,
            path=p.path,
            content=p.content,
            message=p.message,
            branch=branch_name,
            sha=p.sha,
        )
        commits.append({
            "path": p.path,
            "sha": (result.get("commit") or {}).get("sha"),
        })

    paths_listed = "\n".join(f"- `{p.path}`" for _, p in pendings)
    pr = await gh.create_pull_request(
        owner=OWNER,
        repo=repo,
        head=branch_name,
        base=branch,
        title=title,
        body=(
            f"Vibe-coded via minato-vibe-mcp.\n\n"
            f"Approved by @{login} via `confirm_writes`.\n\n"
            f"Files in this PR ({len(pendings)}):\n{paths_listed}"
        ),
    )

    merge_status, _ = await gh.merge_pull_request(
        OWNER, repo, pr["number"], "squash"
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

    # Only pop on success.
    for t, _ in pendings:
        user_pending.pop(t, None)

    return {
        "status": merge_state,
        "target": f"{OWNER}/{repo}@{branch}",
        "pr_url": pr["html_url"],
        "pr_number": pr["number"],
        "branch": branch_name,
        "commits": commits,
        "files_changed": len(pendings),
    }


def _parse_kustomization_images(content: str) -> list[dict]:
    """Pull `images:` entries (name/newName/newTag) from a kustomization.yaml.
    Cheap line-based parse — avoids a YAML dep for a known-shape file."""
    images: list[dict] = []
    cur: dict | None = None
    in_images = False
    for raw in content.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("images:"):
            in_images = True
            continue
        if not in_images:
            continue
        # End of images: section = a non-indented key
        if line and not line.startswith((" ", "\t")) and stripped.endswith(":"):
            break
        if stripped.startswith("- name:"):
            if cur:
                images.append(cur)
            cur = {"name": stripped.split(":", 1)[1].strip()}
        elif stripped.startswith("newName:") and cur is not None:
            cur["newName"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("newTag:") and cur is not None:
            cur["newTag"] = stripped.split(":", 1)[1].strip()
    if cur:
        images.append(cur)
    return images


@mcp.tool()
async def get_app_status(repo: str) -> dict:
    """One-shot status of a deployed platform app. Fetches in parallel:
    latest commit on main, pinned image(s) in deploy/base/kustomization.yaml,
    latest build-image run, any open release-please PR. Reports drift if the
    pinned image is behind main.

    Use this instead of poking around with list_files/read_file just to
    answer "is my change live yet?"
    """
    gh, _ = _current_user()

    async def _safe_kust():
        try:
            data = await gh.get_contents(
                OWNER, repo, "deploy/base/kustomization.yaml", ref="main"
            )
            return data
        except Exception:
            return None

    async def _safe_runs():
        try:
            return await gh.list_workflow_runs(
                OWNER, repo, "build-image.yml", per_page=5
            )
        except Exception:
            return None

    async def _safe_prs():
        try:
            return await gh.list_pull_requests(OWNER, repo, state="open")
        except Exception:
            return []

    async def _safe_branch():
        try:
            return await gh.get_branch(OWNER, repo, "main")
        except Exception:
            return None

    branch, kust_data, runs, prs = await asyncio.gather(
        _safe_branch(), _safe_kust(), _safe_runs(), _safe_prs()
    )

    latest_sha = (branch or {}).get("commit", {}).get("sha")
    latest_sha_short = latest_sha[:7] if latest_sha else None

    pinned_images: list[dict] = []
    if isinstance(kust_data, dict):
        text = decode_file_content(kust_data) or ""
        pinned_images = _parse_kustomization_images(text)

    latest_run = None
    if runs and runs.get("workflow_runs"):
        r0 = runs["workflow_runs"][0]
        latest_run = {
            "id": r0.get("id"),
            "status": r0.get("status"),
            "conclusion": r0.get("conclusion"),
            "head_sha": r0.get("head_sha"),
            "head_branch": r0.get("head_branch"),
            "url": r0.get("html_url"),
            "created_at": r0.get("created_at"),
        }

    release_pending = False
    release_pr_url = None
    for p in prs or []:
        head_ref = (p.get("head") or {}).get("ref") or ""
        title = p.get("title") or ""
        if head_ref.startswith("release-please--") or title.startswith("chore(main): release"):
            release_pending = True
            release_pr_url = p.get("html_url")
            break

    drift = None
    pinned_short = None
    for img in pinned_images:
        tag = img.get("newTag", "")
        if tag.startswith("sha-"):
            pinned_short = tag.removeprefix("sha-")
            break
    if pinned_short and latest_sha_short and pinned_short != latest_sha_short:
        try:
            cmp = await gh.compare_commits(OWNER, repo, pinned_short, latest_sha_short)
            ahead = cmp.get("ahead_by", 0)
            drift = f"main is ahead of pinned image by {ahead} commit(s)"
        except Exception:
            drift = "pinned image is not at main HEAD"

    return {
        "repo": f"{OWNER}/{repo}",
        "expected_url": f"https://{repo}.{APP_URL_BASE}",
        "latest_main_commit": latest_sha,
        "pinned_images": pinned_images,
        "latest_build_run": latest_run,
        "release_please_pending": release_pending,
        "release_please_pr_url": release_pr_url,
        "drift": drift,
    }


@mcp.tool()
async def get_build_log(
    repo: str, run_id: int, failed_only: bool = True
) -> dict:
    """Fetch logs from a workflow run. With `failed_only=True` (default),
    returns only the jobs that failed and tail of each job's log — useful
    when CI failed and the model needs to know what to fix without grabbing
    600 lines of actions/checkout noise.

    The `run_id` is the `id` field from `get_app_status`'s `latest_build_run`
    or any workflow run URL.
    """
    gh, _ = _current_user()
    jobs_payload = await gh.list_run_jobs(OWNER, repo, run_id)
    jobs = jobs_payload.get("jobs", [])

    out: list[dict] = []
    for job in jobs:
        if failed_only and job.get("conclusion") not in {"failure", "cancelled", "timed_out"}:
            continue
        try:
            log_text = await gh.get_job_log(OWNER, repo, job["id"])
        except Exception as e:
            log_text = f"(failed to fetch log: {e})"
        # Pull failed steps from the job's `steps` array for context.
        failed_steps = [
            s.get("name") for s in (job.get("steps") or [])
            if s.get("conclusion") in {"failure", "cancelled", "timed_out"}
        ]
        # Trim the log to its tail to keep response size sane.
        excerpt = log_text[-8000:] if log_text and len(log_text) > 8000 else log_text
        out.append({
            "job_id": job.get("id"),
            "job_name": job.get("name"),
            "conclusion": job.get("conclusion"),
            "failed_steps": failed_steps,
            "url": job.get("html_url"),
            "log_tail": excerpt,
        })

    return {
        "run_id": run_id,
        "filtered_to_failed": failed_only,
        "jobs": out,
    }


@mcp.tool()
async def dispatch_workflow(
    repo: str, workflow: str = "build-image.yml", ref: str = "main"
) -> dict:
    """Trigger a workflow_dispatch on a given workflow file. Useful when the
    release-please → build-image chain misfires (GitHub suppresses workflow
    triggers from events authored by GITHUB_TOKEN), or any time you want to
    force a rebuild without pushing a commit.

    `workflow` is the filename under `.github/workflows/`. Default is
    `build-image.yml`. Returns immediately; poll `get_app_status` for the
    new run.
    """
    gh, _ = _current_user()
    await gh.dispatch_workflow(OWNER, repo, workflow, ref)
    return {
        "status": "dispatched",
        "repo": f"{OWNER}/{repo}",
        "workflow": workflow,
        "ref": ref,
        "next": (
            "GitHub queues the run asynchronously. Call get_app_status in "
            "10-30s to see the new latest_build_run."
        ),
    }


@mcp.tool()
def get_template_conventions(template: str) -> dict:
    """Returns the curated non-obvious lint rules, idioms, and common
    pitfalls for a given template. Read this BEFORE writing significant
    code in a repo of that template — it pre-empts the most common CI
    failures (strict-mode TypeScript, Biome warnings, React compiler
    rules, Go stdlib-only conventions, etc.).

    Valid template names: react-vibe-template, react-go-template,
    gohtmx-vibe-template, html-vibe-template.
    """
    conventions = get_conventions(template)
    if conventions is None:
        return {
            "error": f"unknown template '{template}'",
            "valid_templates": list_template_names(),
        }
    return {"template": template, **conventions}


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
