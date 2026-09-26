"""Jinja2 environment for agent prompt and submission templates.

Prompts and generic report templates live as ``.jinja`` files under
``templates/`` rather than as Python string literals, so they can be edited and
overridden without touching code.
"""

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).parent / "templates"


@lru_cache(maxsize=1)
def get_environment() -> Environment:
    """Return the shared Jinja2 environment (autoescaping off — text, not HTML)."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=False,
        keep_trailing_newline=True,
    )


def render_template(name: str, **context: object) -> str:
    """Render the template *name* with *context*."""
    return get_environment().get_template(name).render(**context)


def read_template_source(name: str) -> str:
    """Return the raw source text of the template *name*."""
    return (TEMPLATES_DIR / name).read_text(encoding="utf-8")
