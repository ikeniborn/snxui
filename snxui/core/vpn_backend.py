"""Pluggable VPN backend abstraction.

Defines the :class:`VPNBackend` abstract base class that all backend
implementations must satisfy, and :class:`BackendFactory` which selects
the appropriate concrete backend based on profile settings.

Available backends:
    * :class:`~snxui.core.ssl_tunnel_backend.PythonSSLBackend` — pure
      Python CCC auth + SLIM SSL tunnel, no external binaries required.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
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
# Factory
# ---------------------------------------------------------------------------


class BackendFactory:
    """Create the appropriate :class:`VPNBackend` for a given profile.

    All profiles use :class:`~snxui.core.ssl_tunnel_backend.PythonSSLBackend`
    (pure Python CCC auth + SLIM SSL tunnel, no external binaries required).
    The ``profile.backend`` attribute is accepted for forward compatibility but
    any value maps to ``PythonSSLBackend``.
    """

    @staticmethod
    def create(profile: "Profile") -> VPNBackend:
        """Instantiate and return the backend for *profile*.

        Args:
            profile: The profile whose settings drive the connection.

        Returns:
            A ready-to-use :class:`VPNBackend` instance.
        """
        from .ssl_tunnel_backend import PythonSSLBackend
        return PythonSSLBackend()
