"""Pluggable VPN backend abstraction.

Defines the :class:`VPNBackend` abstract base class that all backend
implementations must satisfy, and :class:`BackendFactory` which selects
the appropriate concrete backend based on profile settings and available
binaries.

Available backends:
    * :class:`~snxui.core.snx_rs_backend.SNXRsBackend` — snx-rs daemon
      (snx-rs / snxctl), uses CCC protocol natively, supports IPSec.
    * :class:`~snxui.core.snx_backend.SNXBinaryBackend` — /usr/bin/snx
      via pexpect PTY automation.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .types import ConnectionStatus, Profile, TwoFactorCallback


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class VPNBackend(ABC):
    """Abstract base class for VPN backend implementations.

    Concrete subclasses must implement :meth:`connect`, :meth:`disconnect`,
    :meth:`get_status`, and :meth:`get_cached_status`.
    """

    @abstractmethod
    def connect(
        self,
        profile: "Profile",
        password: str,
        status_callback: "Optional[Callable[[ConnectionStatus], None]]" = None,
        two_factor_callback: "Optional[TwoFactorCallback]" = None,
    ) -> bool:
        """Establish a VPN connection.

        Args:
            profile: Connection profile with server/user settings.
            password: Plaintext password (never logged).
            status_callback: Called on each status change (thread-safe required).
            two_factor_callback: Called when MFA code is needed; returns code
                or ``None`` to abort.

        Returns:
            ``True`` on successful connection, ``False`` otherwise.
        """

    @abstractmethod
    def disconnect(self) -> bool:
        """Terminate the active VPN connection.

        Returns:
            ``True`` if disconnection succeeded (or was already disconnected).
        """

    @abstractmethod
    def get_status(self) -> "ConnectionStatus":
        """Return current connection status, probing the system if needed."""

    @abstractmethod
    def get_cached_status(self) -> "Optional[ConnectionStatus]":
        """Return the last cached status without probing the system."""


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def detect_snx_rs() -> bool:
    """Return ``True`` if the snx-rs binaries (``snx-rs`` and ``snxctl``) are in PATH."""
    return shutil.which("snx-rs") is not None and shutil.which("snxctl") is not None


def detect_snx_binary() -> bool:
    """Return ``True`` if the Check Point SNX binary exists on this system."""
    search_paths: list[Path] = [
        Path("/usr/bin/snx"),
        Path("/usr/local/bin/snx"),
        Path.home() / "Downloads" / "snx",
        Path.home() / "snx",
    ]
    return any(p.exists() for p in search_paths)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class BackendFactory:
    """Create the appropriate :class:`VPNBackend` for a given profile.

    Selection logic (``profile.backend``):

    * ``"snx_rs"``  — always use :class:`~snxui.core.snx_rs_backend.SNXRsBackend`.
    * ``"snx"``     — always use :class:`~snxui.core.snx_backend.SNXBinaryBackend`.
    * ``"auto"``    — prefer snx-rs if ``snx-rs``/``snxctl`` are in PATH, else fall back to
      the SNX binary.
    """

    @staticmethod
    def create(profile: "Profile") -> VPNBackend:
        """Instantiate and return the backend for *profile*.

        Args:
            profile: The profile whose ``backend`` attribute drives selection.

        Returns:
            A ready-to-use :class:`VPNBackend` instance.

        Raises:
            RuntimeError: If the requested backend binary is not found.
        """
        backend_choice: str = getattr(profile, "backend", "auto")

        if backend_choice == "snx_rs":
            if not detect_snx_rs():
                raise RuntimeError(
                    "snx-rs backend requested but snx-rs/snxctl is not found in PATH. "
                    "Install snx-rs: https://github.com/ancwrd1/snx-rs"
                )
            from .snx_rs_backend import SNXRsBackend
            return SNXRsBackend()

        if backend_choice == "snx":
            from .snx_backend import SNXBinaryBackend
            return SNXBinaryBackend()

        # "auto" — prefer snx-rs
        if detect_snx_rs():
            from .snx_rs_backend import SNXRsBackend
            return SNXRsBackend()

        from .snx_backend import SNXBinaryBackend
        return SNXBinaryBackend()
