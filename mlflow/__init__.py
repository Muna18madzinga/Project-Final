"""
Lightweight stub of the mlflow package for local development.

This provides no-op implementations of the limited mlflow APIs used by the
adaptive security suite so that the application can run in environments where
mlflow wheels are unavailable (e.g. Python 3.13 without build toolchains).
"""

from __future__ import annotations

import contextlib
import logging
from typing import Dict, Iterable, Optional

logger = logging.getLogger("mlflow_stub")


def set_experiment(name: str) -> None:
    """Stubbed experiment selection."""
    logger.info("mlflow.set_experiment(%r) [stub]", name)


@contextlib.contextmanager
def start_run(*args, **kwargs):
    """Context manager that mimics mlflow.start_run."""
    logger.info("mlflow.start_run(args=%r, kwargs=%r) [stub-enter]", args, kwargs)
    try:
        yield None
    finally:
        logger.info("mlflow.start_run [stub-exit]")


def log_params(params: Dict[str, object]) -> None:
    """Record parameters (no-op)."""
    logger.info("mlflow.log_params(%r) [stub]", params)


def log_metric(key: str, value: float, step: Optional[int] = None) -> None:
    """Record a single metric (no-op)."""
    logger.info(
        "mlflow.log_metric(key=%r, value=%r, step=%r) [stub]", key, value, step
    )


def log_metrics(metrics: Dict[str, float], step: Optional[int] = None) -> None:
    """Record multiple metrics (no-op)."""
    logger.info(
        "mlflow.log_metrics(metrics=%r, step=%r) [stub]", metrics, step
    )


# Ensure ``import mlflow.pytorch`` works by exposing the submodule.
from . import pytorch as pytorch  # type: ignore  # noqa: E402,F401

__all__ = [
    "set_experiment",
    "start_run",
    "log_params",
    "log_metric",
    "log_metrics",
    "pytorch",
]
