"""Bearer-token verifier that treats the token as a GitHub PAT.

We validate by calling GET /user with the token and caching the result for
5 minutes. The GitHub login is stored in the AccessToken's `client_id` so
tools can use it to scope per-user state.

In v0.3 there's no separate authorization server — the user generates a PAT
at github.com/settings/tokens and pastes it into their chat client. Future
versions can swap this for a full OAuth flow without changing the call sites.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
from mcp.server.auth.provider import AccessToken, TokenVerifier

VALIDATION_CACHE_TTL_SECONDS = 300


@dataclass
class _CachedValidation:
    login: str
    cached_at: float


class GitHubPATVerifier(TokenVerifier):
    """Verifies a Bearer token by checking it is a valid GitHub PAT."""

    def __init__(self, http: httpx.AsyncClient):
        self._http = http
        self._cache: dict[str, _CachedValidation] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None

        now = time.time()
        cached = self._cache.get(token)
        if cached and now - cached.cached_at < VALIDATION_CACHE_TTL_SECONDS:
            return _access_token(token, cached.login)

        try:
            r = await self._http.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=10.0,
            )
        except httpx.HTTPError:
            return None
        if r.status_code != 200:
            return None
        login = r.json().get("login")
        if not isinstance(login, str):
            return None

        self._cache[token] = _CachedValidation(login=login, cached_at=now)
        return _access_token(token, login)


def _access_token(token: str, login: str) -> AccessToken:
    return AccessToken(
        token=token,
        client_id=login,  # GitHub login; used to scope per-user state
        scopes=[],
        expires_at=None,
        resource=None,
    )
