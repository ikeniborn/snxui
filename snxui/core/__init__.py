"""Core backend: types, profile management, credential storage, SNX automation."""

from .types import Profile, ConnectionStatus, ConnectionState
from .profile_manager import ProfileManager
from .credential_store import CredentialStore
from .snx_backend import SNXBackend, SNXBinaryBackend
from .vpn_backend import VPNBackend, BackendFactory

__all__ = [
    "Profile",
    "ConnectionStatus",
    "ConnectionState",
    "ProfileManager",
    "CredentialStore",
    "SNXBackend",
    "SNXBinaryBackend",
    "VPNBackend",
    "BackendFactory",
]
