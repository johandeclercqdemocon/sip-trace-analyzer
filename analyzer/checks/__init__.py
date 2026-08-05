"""Importing this package registers every check."""
from . import dialogs, media, routing, signalling  # noqa: F401
from .base import REGISTRY, Context, Finding, run_all  # noqa: F401
