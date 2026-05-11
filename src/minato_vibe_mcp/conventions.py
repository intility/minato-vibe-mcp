"""Static catalog of non-obvious conventions per template.

The goal is to let the model pre-empt the first round of CI failures by
knowing about template-specific lint rules and idioms BEFORE it starts
writing. This is hand-curated; update when the platform team flags a new
common-failure pattern.

Keep entries focused on rules that will fail CI silently if the model is
unaware. Don't mirror everything in the template's CLAUDE.md — link to it.
"""

from __future__ import annotations

CONVENTIONS: dict[str, dict] = {
    "react-vibe-template": {
        "stack": "React 19 SPA + Vite + TypeScript 5.9 + Biome",
        "check_command": "just check",
        "lint_tools": ["biome", "tsc"],
        "non_obvious_rules": [
            "TypeScript strict mode + noUncheckedIndexedAccess: any array[idx] "
            "access yields T | undefined. Use array[idx] ?? fallback or guard "
            "before use; do NOT use non-null assertion (!) — Biome flags it.",
            "Biome formatter must be clean. CI runs `biome ci .` which fails "
            "on warnings, not just errors. Run `just check` locally first.",
            "React compiler is on. The 'set-state-in-effect' lint rule flags "
            "useState setters called inside useEffect; either extract via "
            "useCallback or inline a poll inside the effect.",
            "No client-side auth library (MSAL, oidc-client). Auth is the "
            "gateway's job; the API receives a pre-validated JWT.",
        ],
        "common_pitfalls": [
            "Forgetting `?? fallback` on typed-array indexing.",
            "Adding em dashes to text — convention is plain language only.",
            "Adding a SPA-side auth library.",
        ],
        "claude_md_path": "CLAUDE.md",
    },
    "react-go-template": {
        "stack": "React 19 SPA + Go 1.25 REST API + Postgres (CloudNativePG)",
        "check_command": "just check",
        "lint_tools": ["biome", "tsc", "gofmt", "go vet", "go build"],
        "non_obvious_rules": [
            "TypeScript strict mode + noUncheckedIndexedAccess: any array[idx] "
            "access yields T | undefined. Use array[idx] ?? fallback or guard "
            "before use; do NOT use non-null assertion (!) — Biome flags it.",
            "Biome formatter must be clean. CI runs `biome ci .` which fails "
            "on warnings, not just errors. Run `just check` locally first.",
            "React compiler is on. The 'set-state-in-effect' lint rule flags "
            "useState setters called inside useEffect; either extract via "
            "useCallback or inline a poll inside the effect.",
            "Go: stdlib only for HTTP routing — net/http ServeMux (1.22+ "
            "patterns). No chi/gorilla/echo/gin/fiber.",
            "Go: pgx/v5 + pgxpool for the DB. No ORM (gorm/ent/sqlc auto).",
            "API auth is DECODE-ONLY. The gateway validates the JWT; the API "
            "just reads claims. Do NOT add JWKS validation in api/internal/"
            "auth/ — it's an intentional simplification.",
            "Both containers listen on :8080 (web nginx, api Go). The HTTPRoute "
            "splits /api/* to api and everything else to web on the same host.",
        ],
        "common_pitfalls": [
            "Forgetting `?? fallback` on typed-array indexing.",
            "Adding a third-party Go HTTP router.",
            "Adding JWT signature validation in the API.",
            "Using `database/sql` instead of pgx.",
            "Listening on a port other than :8080.",
        ],
        "claude_md_path": "CLAUDE.md",
    },
    "gohtmx-vibe-template": {
        "stack": "Go 1.25 + stdlib net/http + html/template + HTMX + Bifrost CSS",
        "check_command": "just check",
        "lint_tools": ["gofmt", "go vet", "go build"],
        "non_obvious_rules": [
            "Stdlib only. No chi/echo/fiber/gin and no templ — html/template "
            "with HTMX is the convention.",
            "HTMX comes from vendored static assets. Don't pull it from a CDN.",
            "OTel SDK is wired; respect OTEL_* env vars and use the existing "
            "tracer rather than starting a new one.",
        ],
        "common_pitfalls": [
            "Reaching for a Go web framework.",
            "Switching to templ or a different templating engine.",
        ],
        "claude_md_path": "CLAUDE.md",
    },
    "html-vibe-template": {
        "stack": "Static site served by nginx-unprivileged (no JS framework)",
        "check_command": None,
        "lint_tools": [],
        "non_obvious_rules": [
            "It's static HTML/CSS/JS in public/. Don't introduce a bundler or "
            "framework — if you need one, switch templates.",
            "nginx listens on :8080 (unprivileged), not :80.",
        ],
        "common_pitfalls": [
            "Adding a build step or framework.",
        ],
        "claude_md_path": None,
    },
}


def get_conventions(template: str) -> dict | None:
    return CONVENTIONS.get(template)


def list_template_names() -> list[str]:
    return sorted(CONVENTIONS.keys())
