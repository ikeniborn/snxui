"""Core backend: types, profile management, credential storage, VPN automation."""

from .types import Profile, ConnectionStatus, ConnectionState
from .profile_manager import ProfileManager
from .credential_store import CredentialStore
from .vpn_backend import VPNBackend, BackendFactory

__all__ = [
    "Profile",
    "ConnectionStatus",
    "ConnectionState",
    "ProfileManager",
    "CredentialStore",
    "VPNBackend",
    "BackendFactory",
]
