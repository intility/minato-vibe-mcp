"""GitHub-as-upstream OAuth proxy for the minato-vibe MCP.

The MCP is itself an OAuth 2.1 Authorization Server. Chat clients (Claude
Desktop, Claude.ai, ChatGPT) discover us via `/.well-known/oauth-
authorization-server`, register themselves via DCR, and run a standard
OAuth dance with us. We delegate the actual user authentication to GitHub
via a GitHub OAuth App, get back a GitHub user token, then issue our OWN
MCP token to the chat client and remember the mapping.

When a tool call comes in with the MCP token, we look up the upstream
GitHub token and use it to call api.github.com.

Storage is in-memory: single-replica is fine for v1; if the pod restarts,
users re-auth. The state types are small (a few hundred bytes each).
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"

# Scopes we ask GitHub for. `repo` covers Contents + Pull Requests + create
# repos under orgs the user belongs to. `read:org` for membership checks.
DEFAULT_GITHUB_SCOPES = ["repo", "read:org"]

AUTH_CODE_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = 3600 * 24 * 30  # 30 days; GH tokens don't expire by default
REFRESH_TOKEN_TTL_SECONDS = 3600 * 24 * 90


@dataclass
class _GitHubAuthState:
    """Pending /authorize → GitHub → /oauth/callback round-trip state."""

    chat_client_id: str
    chat_redirect_uri: AnyUrl
    chat_redirect_uri_provided_explicitly: bool
    chat_state: str | None
    code_challenge: str
    scopes: list[str]
    created_at: float


@dataclass
class _OurAuthCode:
    """An authorization code we issued to the chat client after GitHub
    accepted the user."""

    code: str
    chat_client_id: str
    chat_redirect_uri: AnyUrl
    chat_redirect_uri_provided_explicitly: bool
    code_challenge: str
    scopes: list[str]
    expires_at: float
    github_token: str
    github_login: str


@dataclass
class _OurAccessToken:
    token: str
    chat_client_id: str
    scopes: list[str]
    expires_at: int
    github_token: str
    github_login: str


@dataclass
class _OurRefreshToken:
    token: str
    chat_client_id: str
    scopes: list[str]
    expires_at: int
    github_token: str
    github_login: str


class GitHubOAuthProxy(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """Implements the MCP authorization server contract; delegates upstream
    authentication to GitHub."""

    def __init__(
        self,
        github_client_id: str,
        github_client_secret: str,
        mcp_base_url: str,
        http: httpx.AsyncClient,
        scopes: list[str] | None = None,
    ) -> None:
        self._gh_client_id = github_client_id
        self._gh_client_secret = github_client_secret
        self._mcp_base_url = mcp_base_url.rstrip("/")
        self._http = http
        self._scopes = scopes or DEFAULT_GITHUB_SCOPES

        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending: dict[str, _GitHubAuthState] = {}
        self._auth_codes: dict[str, _OurAuthCode] = {}
        self._access_tokens: dict[str, _OurAccessToken] = {}
        self._refresh_tokens: dict[str, _OurRefreshToken] = {}

    # ----- helpers ---------------------------------------------------------

    @property
    def callback_url(self) -> str:
        return f"{self._mcp_base_url}/oauth/callback"

    def lookup_github_token(self, mcp_token: str) -> tuple[str, str] | None:
        """If `mcp_token` was issued by us, return (github_token, login).
        Otherwise None — caller can treat the token as a GitHub PAT."""
        tok = self._access_tokens.get(mcp_token)
        if tok is None:
            return None
        if tok.expires_at and tok.expires_at < time.time():
            return None
        return tok.github_token, tok.github_login

    def _gc(self) -> None:
        now = time.time()
        for store, ttl in (
            (self._pending, 3600.0),
            (self._auth_codes, AUTH_CODE_TTL_SECONDS),
        ):
            expired = [
                k for k, v in store.items()
                if now - getattr(v, "created_at", getattr(v, "expires_at", now)) > ttl
            ]
            for k in expired:
                store.pop(k, None)
        for k, t in list(self._access_tokens.items()):
            if t.expires_at and t.expires_at < now:
                self._access_tokens.pop(k, None)
        for k, t in list(self._refresh_tokens.items()):
            if t.expires_at and t.expires_at < now:
                self._refresh_tokens.pop(k, None)

    # ----- OAuthAuthorizationServerProvider protocol ----------------------

    async def get_client(
        self, client_id: str
    ) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(
        self, client_info: OAuthClientInformationFull
    ) -> None:
        # The SDK assigns client_id before calling us; just store.
        if client_info.client_id is None:
            client_info.client_id = secrets.token_urlsafe(16)
        self._clients[client_info.client_id] = client_info

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Called when a chat client hits /authorize. We don't authorize
        directly; we redirect to GitHub. When GitHub redirects back to
        /oauth/callback we'll complete the flow."""
        self._gc()
        state_id = secrets.token_urlsafe(24)
        self._pending[state_id] = _GitHubAuthState(
            chat_client_id=client.client_id or "",
            chat_redirect_uri=params.redirect_uri,
            chat_redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            chat_state=params.state,
            code_challenge=params.code_challenge,
            scopes=params.scopes or self._scopes,
            created_at=time.time(),
        )
        gh_query = urlencode({
            "client_id": self._gh_client_id,
            "redirect_uri": self.callback_url,
            "scope": " ".join(self._scopes),
            "state": state_id,
            "allow_signup": "false",
        })
        return f"{GITHUB_AUTHORIZE_URL}?{gh_query}"

    async def handle_github_callback(
        self, code: str, state: str
    ) -> str:
        """Called from our custom /oauth/callback route. Exchanges GitHub's
        code for a GitHub access token, issues OUR authorization code, and
        returns the chat-client redirect URL to send the user to."""
        pending = self._pending.pop(state, None)
        if pending is None:
            raise ValueError("Unknown or expired state parameter")

        # Exchange GitHub code for GitHub token.
        r = await self._http.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": self._gh_client_id,
                "client_secret": self._gh_client_secret,
                "code": code,
                "redirect_uri": self.callback_url,
            },
            timeout=15.0,
        )
        r.raise_for_status()
        body = r.json()
        gh_token = body.get("access_token")
        if not isinstance(gh_token, str):
            raise ValueError(
                f"GitHub did not return an access_token: {body!r}"
            )

        # Validate by fetching /user and capture the login for later.
        u = await self._http.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10.0,
        )
        u.raise_for_status()
        login = u.json().get("login")
        if not isinstance(login, str):
            raise ValueError("GitHub /user did not return a login")

        # Issue our authorization code, store everything we need to mint
        # tokens later, and redirect the chat client back.
        our_code = secrets.token_urlsafe(24)
        self._auth_codes[our_code] = _OurAuthCode(
            code=our_code,
            chat_client_id=pending.chat_client_id,
            chat_redirect_uri=pending.chat_redirect_uri,
            chat_redirect_uri_provided_explicitly=pending.chat_redirect_uri_provided_explicitly,
            code_challenge=pending.code_challenge,
            scopes=pending.scopes,
            expires_at=time.time() + AUTH_CODE_TTL_SECONDS,
            github_token=gh_token,
            github_login=login,
        )

        # Build the chat-client redirect with our code and the chat client's
        # original state echoed back.
        return construct_redirect_uri(
            str(pending.chat_redirect_uri),
            code=our_code,
            state=pending.chat_state,
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        self._gc()
        rec = self._auth_codes.get(authorization_code)
        if rec is None or rec.chat_client_id != client.client_id:
            return None
        if rec.expires_at < time.time():
            return None
        return AuthorizationCode(
            code=rec.code,
            scopes=rec.scopes,
            expires_at=rec.expires_at,
            client_id=rec.chat_client_id,
            code_challenge=rec.code_challenge,
            redirect_uri=rec.chat_redirect_uri,
            redirect_uri_provided_explicitly=rec.chat_redirect_uri_provided_explicitly,
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        rec = self._auth_codes.pop(authorization_code.code, None)
        if rec is None:
            raise ValueError("Authorization code already used or expired")

        access_str = secrets.token_urlsafe(32)
        refresh_str = secrets.token_urlsafe(32)
        now = int(time.time())

        self._access_tokens[access_str] = _OurAccessToken(
            token=access_str,
            chat_client_id=client.client_id or "",
            scopes=rec.scopes,
            expires_at=now + ACCESS_TOKEN_TTL_SECONDS,
            github_token=rec.github_token,
            github_login=rec.github_login,
        )
        self._refresh_tokens[refresh_str] = _OurRefreshToken(
            token=refresh_str,
            chat_client_id=client.client_id or "",
            scopes=rec.scopes,
            expires_at=now + REFRESH_TOKEN_TTL_SECONDS,
            github_token=rec.github_token,
            github_login=rec.github_login,
        )
        return OAuthToken(
            access_token=access_str,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(rec.scopes),
            refresh_token=refresh_str,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rec = self._refresh_tokens.get(refresh_token)
        if rec is None or rec.chat_client_id != client.client_id:
            return None
        if rec.expires_at < time.time():
            return None
        return RefreshToken(
            token=rec.token,
            client_id=rec.chat_client_id,
            scopes=rec.scopes,
            expires_at=rec.expires_at,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        rec = self._refresh_tokens.get(refresh_token.token)
        if rec is None:
            raise ValueError("Unknown refresh token")
        # Rotate the access token, keep the refresh token.
        access_str = secrets.token_urlsafe(32)
        now = int(time.time())
        self._access_tokens[access_str] = _OurAccessToken(
            token=access_str,
            chat_client_id=client.client_id or "",
            scopes=scopes or rec.scopes,
            expires_at=now + ACCESS_TOKEN_TTL_SECONDS,
            github_token=rec.github_token,
            github_login=rec.github_login,
        )
        return OAuthToken(
            access_token=access_str,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(scopes or rec.scopes),
            refresh_token=rec.token,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """SDK calls this for tokens we issued. We ALSO use this as the
        single gateway for token verification — if the token isn't in our
        OAuth store, fall back to validating it as a GitHub PAT so existing
        bearer-PAT users keep working."""
        self._gc()
        rec = self._access_tokens.get(token)
        if rec is not None:
            if rec.expires_at < time.time():
                return None
            return AccessToken(
                token=rec.token,
                client_id=rec.github_login,
                scopes=rec.scopes,
                expires_at=rec.expires_at,
            )

        # Fallback: PAT pass-through. Validate by calling /user; we don't
        # cache here because the bearer auth path validates frequently and
        # the underlying GitHubPATVerifier already caches that path.
        try:
            r = await self._http.get(
                GITHUB_USER_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
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
        return AccessToken(
            token=token,  # the PAT itself
            client_id=login,
            scopes=[],
        )

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        self._access_tokens.pop(token.token, None)
        self._refresh_tokens.pop(token.token, None)


def build_oauth_provider(
    http: httpx.AsyncClient,
    mcp_base_url: str,
) -> GitHubOAuthProxy | None:
    """Construct the provider from env if credentials are set. Returns None
    if OAuth isn't configured — the server then runs in PAT-only mode."""
    client_id = os.environ.get("GITHUB_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GITHUB_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        return None
    return GitHubOAuthProxy(
        github_client_id=client_id,
        github_client_secret=client_secret,
        mcp_base_url=mcp_base_url,
        http=http,
    )
