TEMPLATES = [
    {
        "name": "react-vibe-template",
        "stack": "React 19 SPA",
        "use_when": "Frontend-only app, auth at the gateway. Recommended starting point.",
        "template_owner": "intility",
        "template_repo": "react-vibe-template",
        "prefilled_url": (
            "https://github.com/new"
            "?owner=intility&template_name=react-vibe-template&template_owner=intility"
        ),
    },
    {
        "name": "react-go-template",
        "stack": "React 19 SPA + Go REST API + Postgres",
        "use_when": "Anything that needs a database and a typed API.",
        "template_owner": "intility",
        "template_repo": "react-go-template",
        "prefilled_url": (
            "https://github.com/new"
            "?owner=intility&template_name=react-go-template&template_owner=intility"
        ),
    },
]


def get_template(name: str) -> dict | None:
    return next((t for t in TEMPLATES if t["name"] == name), None)
