"""Cheap static checks run before a write is staged.

Goal: catch obvious mistakes ("you pasted broken JSON", "this content is
identical to what's already there") without spinning up a sandbox or running
the project's actual lint/test pipeline. False positives are bad here because
they block legitimate writes, so we only check things with high confidence:

  - No-op change (content matches the existing file).
  - JSON / YAML / TOML / Python syntax errors.

Type-checking (TypeScript, Go), linting (Biome, ESLint), formatting — all
require running the real toolchain and are NOT done here.
"""

from __future__ import annotations

import ast
import json
import tomllib  # stdlib in Python 3.11+

try:
    import yaml as _yaml  # type: ignore[import-untyped]
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def validate_content(
    path: str, content: str, current_content: str | None
) -> list[str]:
    """Run cheap static checks on a proposed file write.

    Returns a list of error messages; an empty list means the write looks
    fine to stage. Each message is one line, suitable for showing to a model
    as "fix this and try again."
    """
    errors: list[str] = []

    if current_content is not None and content == current_content:
        errors.append(
            "Content is identical to the current file on the target branch — "
            "this would produce an empty commit. If you intended a change, "
            "re-read the file and make sure your new content actually differs."
        )
        return errors  # No point checking syntax of unchanged content.

    lower = path.lower()
    if lower.endswith(".json"):
        try:
            json.loads(content)
        except json.JSONDecodeError as e:
            errors.append(
                f"Invalid JSON at line {e.lineno}, col {e.colno}: {e.msg}"
            )
    elif lower.endswith((".yaml", ".yml")):
        if _HAS_YAML:
            try:
                _yaml.safe_load(content)
            except _yaml.YAMLError as e:  # type: ignore[attr-defined]
                errors.append(f"Invalid YAML: {e}")
    elif lower.endswith(".toml"):
        try:
            tomllib.loads(content)
        except tomllib.TOMLDecodeError as e:
            errors.append(f"Invalid TOML: {e}")
    elif lower.endswith(".py"):
        try:
            ast.parse(content)
        except SyntaxError as e:
            line = e.lineno or "?"
            errors.append(
                f"Python syntax error at line {line}: {e.msg}"
            )

    return errors
