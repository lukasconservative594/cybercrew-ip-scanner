"""Fetcher plugins.

Importing this package registers every built-in fetcher. Third-party plugins
can register their own by importing :func:`register` from ``.base``.
"""

from __future__ import annotations

from .base import REGISTRY, Fetcher, available, create, default_ids, register

# Importing for the registration side effect; order here does not matter
# because fetchers declare their own run order.
from . import basic      # noqa: F401,E402
from . import mac        # noqa: F401,E402
from . import ports      # noqa: F401,E402
from . import netbios    # noqa: F401,E402
from . import web        # noqa: F401,E402

__all__ = [
    "REGISTRY", "Fetcher", "available", "create", "default_ids", "register",
]


def load_plugins(directory) -> list[str]:
    """Import every ``*.py`` in *directory* so it can register fetchers.

    Returns the module names that loaded successfully. Failures are ignored
    on purpose: one broken plugin must not stop the application starting.
    """
    import importlib.util
    from pathlib import Path

    loaded: list[str] = []
    folder = Path(directory)
    if not folder.is_dir():
        return loaded

    for path in sorted(folder.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"ccr_plugin_{path.stem}", path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded.append(path.stem)
        except Exception:
            continue
    return loaded
