"""
Stub mlflow.pytorch submodule used for local development without mlflow.
"""

import logging

logger = logging.getLogger("mlflow_stub.pytorch")


def log_model(model, artifact_path: str, *args, **kwargs) -> None:
    """Pretend to log a PyTorch model."""
    logger.info(
        "mlflow.pytorch.log_model(artifact_path=%r) [stub]", artifact_path
    )


__all__ = ["log_model"]
