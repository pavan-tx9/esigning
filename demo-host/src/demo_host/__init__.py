"""A stand-in EHR for exercising the e-signing service end to end. See ``app.py``."""

from __future__ import annotations

__all__ = ["create_app"]


def __getattr__(name: str) -> object:
    """``create_app`` is resolved lazily so importing this package costs nothing."""
    if name == "create_app":
        from demo_host.app import create_app as factory

        return factory
    raise AttributeError(name)
