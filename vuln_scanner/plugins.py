"""Plugin auto-discovery and registration.

Plugins are plain Python files that define one or more AbstractTool subclasses.
Discovery order (later entries override earlier on name collision):
  1. ``./plugins/`` relative to CWD
  2. ``~/.vuln-scanner/plugins/``
  3. Any extra dirs in ``PluginsConfig.dirs``

Each plugin file is imported as a module; all ``AbstractTool`` subclasses found
in it (concrete, not abstract) are registered into the provided registry dict.
"""

import importlib.util
import inspect
import logging
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING

from vuln_scanner.config.models import PluginsConfig

if TYPE_CHECKING:
    from vuln_scanner.tools.abstract import AbstractTool

log = logging.getLogger(__name__)

_BUILTIN_PLUGIN_DIRS: list[Path] = [
    Path("plugins"),
    Path("~/.vuln-scanner/plugins").expanduser(),
]


def _load_module(path: Path) -> ModuleType | None:
    """Import a .py file as a module; return None on failure."""
    try:
        spec = importlib.util.spec_from_file_location(f"_vuln_scanner_plugin_{path.stem}", str(path))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception as exc:
        log.warning("Plugin load error (%s): %s", path, exc)
        return None


def _collect_tools(mod: ModuleType) -> list[type["AbstractTool"]]:
    """Return concrete AbstractTool subclasses defined in *mod*."""
    from vuln_scanner.tools.abstract import AbstractTool

    tools: list[type[AbstractTool]] = []
    for _name, obj in inspect.getmembers(mod, inspect.isclass):
        if (
            obj is not AbstractTool
            and issubclass(obj, AbstractTool)
            and not inspect.isabstract(obj)
            and obj.__module__ == mod.__name__
        ):
            tools.append(obj)
    return tools


def load_plugins(
    config: PluginsConfig,
    registry: dict[str, type["AbstractTool"]],
) -> int:
    """Discover plugins and register tool classes into *registry*.

    Returns the number of tool classes registered.
    """
    if not config.enabled:
        log.debug("Plugin system disabled")
        return 0

    search_dirs: list[Path] = list(_BUILTIN_PLUGIN_DIRS)
    search_dirs.extend(Path(d).expanduser().resolve() for d in config.dirs)

    registered = 0
    for directory in search_dirs:
        if not directory.is_dir():
            continue
        for py_file in sorted(directory.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            mod = _load_module(py_file)
            if mod is None:
                continue
            for tool_cls in _collect_tools(mod):
                name = tool_cls.__name__
                if name in registry:
                    log.info("Plugin overrides existing tool: %s (%s)", name, py_file)
                else:
                    log.info("Plugin registered tool: %s (%s)", name, py_file)
                registry[name] = tool_cls
                registered += 1

    if registered:
        log.debug("Loaded %d tool class(es) from plugins", registered)
    return registered
