"""
api/state.py
============
A tiny holder for process-wide runtime objects that are created at
startup (the trained Pipeline) but need to be read by route modules.

Routes import ``get_pipeline()`` rather than importing ``main`` directly,
which would create a circular import (main imports the routers). main
calls ``set_pipeline()`` once training finishes in its startup handler.
"""
from __future__ import annotations

from typing import Optional

_pipeline = None


def set_pipeline(pipeline) -> None:
    global _pipeline
    _pipeline = pipeline


def get_pipeline():
    """Returns the trained Pipeline, or None if startup hasn't finished."""
    return _pipeline
