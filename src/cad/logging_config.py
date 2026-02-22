"""Logging configuration for CAD."""

from __future__ import annotations

import logging
import os
import sys


def setup_logging(level: str | None = None) -> None:
    """Configure structured logging for CAD.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
               Falls back to CAD_LOG_LEVEL env var, then INFO.
    """
    log_level = level or os.environ.get("CAD_LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
