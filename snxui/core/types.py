"""Core data types for snxui.

Defines dataclasses and enumerations used across the entire application:
Profile, ConnectionStatus, ConnectionState.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Optional


class ConnectionState(Enum):
    """Enumeration of all possible VPN connection states."""

    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()
    ERROR = auto()


class TwoFactorMethod(Enum):
    """Supported two-factor authentication methods."""

    NONE = "none"
    TOTP = "totp"
    HOTP = "hotp"
    RSA_SECURID = "rsa"
    CHALLENGE_RESPONSE = "challenge"
    RADIUS = "radius"


# Type alias — здесь, чтобы ui и core могли импортировать без circular import
TwoFactorCallback = Callable[[str], Optional[str]]
# str — prompt_text от SNX; Optional[str] — код для ввода или None (отмена)


@dataclass
class Profile:
    """Represents a single SNX VPN connection profile.

    Each profile stores everything needed to establish a connection with a
    particular Check Point gateway.  Passwords are intentionally NOT stored
    here — they live in :class:`~snxui.core.credential_store.CredentialStore`.

    Attributes:
        id: Unique identifier (UUID4).  Auto-generated on creation.
        name: Human-readable display name (e.g. "Work VPN").
        server: Hostname or IP of the Check Point gateway.
        username: Login name sent to the gateway.
        ssl_port: HTTPS port used by SNX (default 443).
        ca_list: Path to CA certificate bundle or directory.
        certificate: Optional path to client certificate (PEM) for cert auth.
        reauth: Whether SNX should re-authenticate on reconnect automatically.
        save_password: If True, the password is persisted in the keyring.
        cipher: Override SNX cipher suite.  None means use SNX default.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    server: str = ""
    username: str = ""
    ssl_port: int = 443
    ca_list: str = "/etc/ssl/certs"
    certificate: Optional[str] = None
    reauth: bool = True
    save_password: bool = False
    cipher: Optional[str] = None
    two_factor_method: TwoFactorMethod = TwoFactorMethod.NONE
    save_totp_secret: bool = False


@dataclass
class ConnectionStatus:
    """Snapshot of the current VPN connection state.

    Attributes:
        state: Current :class:`ConnectionState`.
        profile: The :class:`Profile` that is/was active, or None.
        ip_address: Assigned tunnel IP address when connected.
        interface: Network interface name (typically ``tunsnx``).
        connected_at: Unix timestamp of when the connection was established.
        error_message: Human-readable error description when state is ERROR.
    """

    state: ConnectionState = ConnectionState.DISCONNECTED
    profile: Optional[Profile] = None
    ip_address: Optional[str] = None
    interface: Optional[str] = None
    connected_at: Optional[float] = None
    error_message: Optional[str] = None
