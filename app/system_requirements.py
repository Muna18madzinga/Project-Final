"""
System requirements verification utilities for the Adaptive Security Suite.

Provides a lightweight checker that evaluates whether the host environment
meets the minimum software and hardware expectations documented for the
advanced adaptive security features.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import shutil
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:  # Torch is optional for some deployments but highly recommended.
    import torch
except Exception:  # pragma: no cover - we only care whether import succeeds.
    torch = None  # type: ignore[assignment]


def _bytes_to_gib(value: Optional[int]) -> Optional[float]:
    """Convert bytes to gibibytes (GiB) with two decimal precision."""
    if value is None:
        return None
    return round(value / (1024 ** 3), 2)


def _get_total_memory_bytes() -> Optional[int]:
    """Best-effort retrieval of total physical memory in bytes."""
    try:
        import psutil  # type: ignore

        return int(psutil.virtual_memory().total)  # pragma: no cover - simple passthrough
    except Exception:
        pass

    system = platform.system()

    if system == "Windows":
        try:
            class MemoryStatusEx(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatusEx()
            status.dwLength = ctypes.sizeof(MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
                return int(status.ullTotalPhys)
        except Exception:
            return None

    if system in {"Linux", "Darwin"}:
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")  # type: ignore[attr-defined]
            phys_pages = os.sysconf("SC_PHYS_PAGES")  # type: ignore[attr-defined]
            return int(page_size * phys_pages)
        except (AttributeError, ValueError, OSError):
            return None

    return None


@dataclass(frozen=True)
class RequirementStatus:
    """Normalized representation for individual requirement checks."""

    name: str
    required: str
    current: str
    status: bool
    critical: bool = True
    details: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        """Return a serialisable dictionary representation."""
        return asdict(self)


class SystemRequirementsChecker:
    """
    Evaluate host system readiness for advanced adaptive security features.

    The defaults align with the documented 2024-2025 deployment guidance:
    - Python 3.12+
    - At least 4 CPU cores
    - Minimum 8 GiB RAM
    - 10 GiB free disk space for models/logs
    - Optional GPU acceleration via CUDA (recommended but not mandatory)
    - Security-sensitive environment variables set by operators
    """

    def __init__(
        self,
        *,
        min_python: Tuple[int, int] = (3, 12),
        min_cpu_cores: int = 4,
        min_memory_gib: float = 8.0,
        min_disk_gib: float = 10.0,
        required_env_vars: Optional[Iterable[str]] = None,
        optional_env_vars: Optional[Iterable[str]] = None,
        required_paths: Optional[Iterable[Path]] = None,
        working_path: Optional[Path] = None,
    ) -> None:
        self.min_python = min_python
        self.min_cpu_cores = min_cpu_cores
        self.min_memory_gib = min_memory_gib
        self.min_disk_gib = min_disk_gib
        self.required_env_vars = list(required_env_vars or ("SECRET_KEY", "JWT_SECRET_KEY"))
        self.optional_env_vars = list(optional_env_vars or ("ENCRYPTION_KEY",))
        default_paths = [
            Path("models"),
            Path("data/suite_state"),
            Path("logs"),
        ]
        self.required_paths = [Path(p) for p in (required_paths or default_paths)]
        self.working_path = Path(working_path) if working_path else Path.cwd()

    # ----------------------------- Public API ----------------------------- #

    def collect(self, ensure_paths: bool = True) -> List[RequirementStatus]:
        """Collect individual requirement statuses."""
        statuses = [
            self._check_python_version(),
            self._check_cpu_cores(),
            self._check_memory(),
            self._check_disk_space(),
            self._check_gpu_acceleration(),
        ]

        statuses.append(self._check_env_vars(self.required_env_vars, True))
        statuses.append(self._check_env_vars(self.optional_env_vars, False))

        if ensure_paths:
            statuses.extend(self._check_required_paths())
        else:
            statuses.extend(self._check_required_paths(create_missing=False))

        return statuses

    def report(self, ensure_paths: bool = True) -> Dict[str, object]:
        """Return an aggregate report including overall readiness."""
        statuses = self.collect(ensure_paths=ensure_paths)
        all_critical_met = all(s.status or not s.critical for s in statuses)
        return {
            "checked_at": datetime.utcnow().isoformat(),
            "requirements": [s.as_dict() for s in statuses],
            "all_critical_met": all_critical_met,
        }

    def ensure_ready(self) -> Dict[str, object]:
        """
        Validate requirements and raise an error if critical ones fail.

        Returns the full report when successful.
        """
        report = self.report(ensure_paths=True)
        if not report["all_critical_met"]:
            missing = [
                r
                for r in report["requirements"]  # type: ignore[assignment]
                if r["critical"] and not r["status"]
            ]
            summary = ", ".join(
                f"{entry['name']} (required {entry['required']}, current {entry['current']})"
                for entry in missing
            )
            raise EnvironmentError(f"System requirements not met: {summary}")

        return report

    # --------------------------- Individual checks --------------------------- #

    def _check_python_version(self) -> RequirementStatus:
        required = f">= {self.min_python[0]}.{self.min_python[1]}"
        current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        status = sys.version_info >= self.min_python
        return RequirementStatus(
            name="python_version",
            required=required,
            current=current,
            status=status,
            critical=True,
            details=platform.python_build()[0] if hasattr(platform, "python_build") else None,
        )

    def _check_cpu_cores(self) -> RequirementStatus:
        cpu_cores = os.cpu_count() or 1
        status = cpu_cores >= self.min_cpu_cores
        return RequirementStatus(
            name="cpu_cores",
            required=f">= {self.min_cpu_cores}",
            current=str(cpu_cores),
            status=status,
            critical=True,
        )

    def _check_memory(self) -> RequirementStatus:
        total_bytes = _get_total_memory_bytes()
        total_gib = _bytes_to_gib(total_bytes)
        status = (total_gib or 0.0) >= self.min_memory_gib if total_gib is not None else False
        detail = (
            "Unable to determine system memory"
            if total_gib is None
            else f"Total RAM: {total_gib} GiB"
        )
        return RequirementStatus(
            name="memory_gib",
            required=f">= {self.min_memory_gib} GiB",
            current="unknown" if total_gib is None else f"{total_gib} GiB",
            status=status,
            critical=True,
            details=detail,
        )

    def _check_disk_space(self) -> RequirementStatus:
        path = self.working_path
        usage = shutil.disk_usage(path)
        free_gib = _bytes_to_gib(usage.free)
        status = free_gib >= self.min_disk_gib if free_gib is not None else False
        return RequirementStatus(
            name="disk_space_gib",
            required=f">= {self.min_disk_gib} GiB free",
            current=f"{free_gib} GiB free",
            status=status,
            critical=True,
            details=f"Checked at {path}",
        )

    def _check_gpu_acceleration(self) -> RequirementStatus:
        if torch is None:
            return RequirementStatus(
                name="gpu_acceleration",
                required="CUDA-capable GPU (recommended)",
                current="torch unavailable",
                status=False,
                critical=False,
                details="Install PyTorch with CUDA support for GPU acceleration",
            )

        available = bool(torch.cuda.is_available())  # pragma: no cover - environment dependent
        device_count = torch.cuda.device_count() if available else 0
        current = (
            f"{device_count} CUDA device(s)" if available else "No CUDA-capable GPU detected"
        )
        return RequirementStatus(
            name="gpu_acceleration",
            required="CUDA-capable GPU (recommended)",
            current=current,
            status=available,
            critical=False,
            details=None,
        )

    def _check_env_vars(self, env_vars: Iterable[str], critical: bool) -> RequirementStatus:
        env_vars = list(env_vars)
        missing = [var for var in env_vars if not os.getenv(var)]
        status = not missing
        return RequirementStatus(
            name="required_env_vars" if critical else "optional_env_vars",
            required=", ".join(env_vars),
            current=f"{len(env_vars) - len(missing)}/{len(env_vars)} set",
            status=status,
            critical=critical,
            details=None if status else f"Missing: {', '.join(missing)}",
        )

    def _check_required_paths(self, create_missing: bool = True) -> List[RequirementStatus]:
        statuses: List[RequirementStatus] = []
        for path in self.required_paths:
            resolved = (self.working_path / path).resolve()
            exists = resolved.exists()
            if not exists and create_missing:
                try:
                    resolved.mkdir(parents=True, exist_ok=True)
                    exists = True
                except Exception as exc:  # pragma: no cover - depends on FS permissions
                    logger.error("Failed to create required directory %s: %s", resolved, exc)
                    exists = False

            statuses.append(
                RequirementStatus(
                    name=f"path_{path.as_posix()}",
                    required="Directory must exist",
                    current=str(resolved),
                    status=exists,
                    critical=True,
                    details=None if exists else "Directory missing and could not be created",
                )
            )

        return statuses


def check_system_requirements(**kwargs: object) -> Dict[str, object]:
    """
    Convenience wrapper around :class:`SystemRequirementsChecker`.

    Example:
        report = check_system_requirements()
        if report["all_critical_met"]:
            ...
    """

    checker = SystemRequirementsChecker(**kwargs)
    return checker.report()

