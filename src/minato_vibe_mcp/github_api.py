"""Thin async wrapper around the GitHub REST API endpoints we use.

One instance per authenticated user; the token is captured at construction
time and never logged. All methods raise httpx.HTTPStatusError on non-2xx.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

API_BASE = "https://api.github.com"
DEFAULT_ACCEPT = "application/vnd.github+json"
API_VERSION = "2022-11-28"


class GitHubClient:
    def __init__(self, token: str, http: httpx.AsyncClient):
        self._token = token
        self._http = http

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": DEFAULT_ACCEPT,
            "X-GitHub-Api-Version": API_VERSION,
        }

    async def whoami(self) -> dict[str, Any]:
        r = await self._http.get(f"{API_BASE}/user", headers=self._headers)
        r.raise_for_status()
        return r.json()

    async def get_contents(
        self, owner: str, repo: str, path: str, ref: str | None = None
    ) -> Any:
        """Returns dict for a file, list of dicts for a directory."""
        params = {"ref": ref} if ref else None
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/contents/{path}",
            headers=self._headers,
            params=params,
        )
        r.raise_for_status()
        return r.json()

    async def put_contents(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, Any]:
        """Create or update a file at `path`. `content` is plain text;
        we base64-encode for the API. Pass `sha` for updates (omit for create)."""
        body: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            body["sha"] = sha
        r = await self._http.put(
            f"{API_BASE}/repos/{owner}/{repo}/contents/{path}",
            headers=self._headers,
            json=body,
        )
        r.raise_for_status()
        return r.json()

    async def get_branch(
        self, owner: str, repo: str, branch: str
    ) -> dict[str, Any]:
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/branches/{branch}",
            headers=self._headers,
        )
        r.raise_for_status()
        return r.json()

    async def compare_commits(
        self, owner: str, repo: str, base: str, head: str
    ) -> dict[str, Any]:
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/compare/{base}...{head}",
            headers=self._headers,
        )
        r.raise_for_status()
        return r.json()

    async def list_pull_requests(
        self, owner: str, repo: str, state: str = "open"
    ) -> list[dict[str, Any]]:
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/pulls",
            headers=self._headers,
            params={"state": state, "per_page": "30"},
        )
        r.raise_for_status()
        return r.json()

    async def list_workflow_runs(
        self,
        owner: str,
        repo: str,
        workflow_file: str,
        per_page: int = 5,
    ) -> dict[str, Any]:
        """List recent runs of a workflow file (e.g. 'build-image.yml')."""
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_file}/runs",
            headers=self._headers,
            params={"per_page": str(per_page)},
        )
        r.raise_for_status()
        return r.json()

    async def list_run_jobs(
        self, owner: str, repo: str, run_id: int
    ) -> dict[str, Any]:
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/actions/runs/{run_id}/jobs",
            headers=self._headers,
        )
        r.raise_for_status()
        return r.json()

    async def get_job_log(self, owner: str, repo: str, job_id: int) -> str:
        """Returns the full plain-text log for a job. Can be large."""
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/actions/jobs/{job_id}/logs",
            headers=self._headers,
            follow_redirects=True,
        )
        r.raise_for_status()
        return r.text

    async def dispatch_workflow(
        self, owner: str, repo: str, workflow_file: str, ref: str = "main"
    ) -> None:
        """Trigger a workflow_dispatch event. Returns nothing on success
        (GitHub returns 204 No Content)."""
        r = await self._http.post(
            f"{API_BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches",
            headers=self._headers,
            json={"ref": ref},
        )
        r.raise_for_status()

    async def get_tree(
        self, owner: str, repo: str, tree_ish: str = "main", recursive: bool = True
    ) -> dict[str, Any]:
        """Get a git tree. `tree_ish` can be a branch name or tree SHA.
        With recursive=True, returns the entire tree in one call (may be
        truncated if the repo is very large; `truncated` field signals)."""
        params = {"recursive": "1"} if recursive else None
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/git/trees/{tree_ish}",
            headers=self._headers,
            params=params,
        )
        r.raise_for_status()
        return r.json()

    async def get_ref(self, owner: str, repo: str, ref: str) -> dict[str, Any]:
        """Get a git ref (e.g. `heads/main`). Returns object with `.object.sha`."""
        r = await self._http.get(
            f"{API_BASE}/repos/{owner}/{repo}/git/ref/{ref}",
            headers=self._headers,
        )
        r.raise_for_status()
        return r.json()

    async def create_ref(
        self, owner: str, repo: str, ref: str, sha: str
    ) -> dict[str, Any]:
        """Create a ref. `ref` must be the full ref name (e.g. `refs/heads/foo`)."""
        r = await self._http.post(
            f"{API_BASE}/repos/{owner}/{repo}/git/refs",
            headers=self._headers,
            json={"ref": ref, "sha": sha},
        )
        r.raise_for_status()
        return r.json()

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        head: str,
        base: str,
        title: str,
        body: str = "",
    ) -> dict[str, Any]:
        r = await self._http.post(
            f"{API_BASE}/repos/{owner}/{repo}/pulls",
            headers=self._headers,
            json={"head": head, "base": base, "title": title, "body": body},
        )
        r.raise_for_status()
        return r.json()

    async def merge_pull_request(
        self,
        owner: str,
        repo: str,
        number: int,
        merge_method: str = "squash",
    ) -> tuple[int, dict[str, Any] | None]:
        """Returns (status_code, body). Does NOT raise on 4xx; caller decides."""
        r = await self._http.put(
            f"{API_BASE}/repos/{owner}/{repo}/pulls/{number}/merge",
            headers=self._headers,
            json={"merge_method": merge_method},
        )
        body = None
        if r.content:
            try:
                body = r.json()
            except ValueError:
                pass
        return r.status_code, body

    async def enable_auto_merge(
        self, pr_node_id: str, merge_method: str = "SQUASH"
    ) -> dict[str, Any]:
        """Enable auto-merge via GraphQL. `pr_node_id` is the GraphQL node ID
        from the PR create response (`node_id` field)."""
        query = (
            "mutation($prId: ID!, $method: PullRequestMergeMethod!) {"
            "  enablePullRequestAutoMerge("
            "    input: {pullRequestId: $prId, mergeMethod: $method}"
            "  ) { pullRequest { number } }"
            "}"
        )
        r = await self._http.post(
            "https://api.github.com/graphql",
            headers=self._headers,
            json={
                "query": query,
                "variables": {"prId": pr_node_id, "method": merge_method},
            },
        )
        r.raise_for_status()
        data = r.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {data['errors']}")
        return data

    async def generate_from_template(
        self,
        template_owner: str,
        template_repo: str,
        owner: str,
        name: str,
        private: bool = True,
        description: str | None = None,
        include_all_branches: bool = False,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "owner": owner,
            "name": name,
            "private": private,
            "include_all_branches": include_all_branches,
        }
        if description:
            body["description"] = description
        r = await self._http.post(
            f"{API_BASE}/repos/{template_owner}/{template_repo}/generate",
            headers=self._headers,
            json=body,
        )
        r.raise_for_status()
        return r.json()


def decode_file_content(payload: dict[str, Any]) -> str | None:
    """Decode the `content` field of a get_contents file response.
    Returns None if the file isn't base64 text."""
    if payload.get("encoding") != "base64":
        return None
    raw = payload.get("content")
    if not isinstance(raw, str):
        return None
    try:
        return base64.b64decode(raw).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None
