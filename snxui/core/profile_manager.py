"""Profile manager — CRUD operations for SNX VPN connection profiles.

Profiles are stored in JSON format at::

    $XDG_CONFIG_HOME/snxui/profiles.json
    (~/.config/snxui/profiles.json by default)

File format versioning is included so future schema migrations can be
applied automatically on load.

Thread-safety is achieved via a per-instance :class:`threading.Lock` for
in-process concurrency and :class:`filelock.FileLock` for cross-process
safety (e.g. if two GUI instances are open simultaneously).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from filelock import FileLock, Timeout

from .types import Profile, TunnelType, TwoFactorMethod

logger = logging.getLogger(__name__)

# Bump this constant whenever the JSON schema changes.
_FILE_FORMAT_VERSION = 9


def _xdg_config_home() -> Path:
    """Return the XDG_CONFIG_HOME directory, honouring the environment variable."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg:
        return Path(xdg)
    return Path.home() / ".config"


def _default_profiles_path() -> Path:
    """Return the default path to the profiles JSON file."""
    return _xdg_config_home() / "snxui" / "profiles.json"


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _profile_to_dict(profile: Profile) -> dict:
    """Convert a :class:`Profile` to a JSON-serialisable dictionary."""
    return {
        "id": profile.id,
        "name": profile.name,
        "server": profile.server,
        "username": profile.username,
        "domain": profile.domain,
        "ssl_port": profile.ssl_port,
        "ca_list": profile.ca_list,
        "certificate": profile.certificate,
        "reauth": profile.reauth,
        "save_password": profile.save_password,
        "cipher": profile.cipher,
        "two_factor_method": profile.two_factor_method.value,
        "save_totp_secret": profile.save_totp_secret,
        "combined_auth": profile.combined_auth,
        "portal_auth": profile.portal_auth,
        "ccc_only_auth": profile.ccc_only_auth,
        "tunnel_type": profile.tunnel_type.value,
        "esp_settings": profile.esp_settings,
        "ike_settings": profile.ike_settings,
        "backend": profile.backend,
        "login_type": profile.login_type,
        "transport_type": profile.transport_type,
        "ignore_server_cert": profile.ignore_server_cert,
    }


def _profile_from_dict(data: dict) -> Profile:
    """Reconstruct a :class:`Profile` from a raw dictionary.

    Unknown keys are silently ignored, which allows forward-compatible reads
    of newer file versions.
    """
    try:
        ssl_port = int(data.get("ssl_port", 443))
    except (TypeError, ValueError):
        logger.warning("Invalid ssl_port value %r in profile data — using default 443.", data.get("ssl_port"))
        ssl_port = 443

    # Validate 'id': must be a non-empty string.  JSON null ("id": null) or a
    # missing key would produce id=None/id="" which cannot be used as a JSON
    # object key (json.dump raises TypeError) and makes the profile impossible
    # to edit or delete through the normal UI flow.
    raw_id = data.get("id", "")
    if not isinstance(raw_id, str) or not raw_id:
        raw_id = str(uuid.uuid4())
        logger.warning(
            "Profile has invalid id (%r) — assigning new UUID %s.",
            data.get("id"),
            raw_id,
        )

    raw_2fa = data.get("two_factor_method", "none")
    try:
        two_factor_method = TwoFactorMethod(raw_2fa)
    except ValueError:
        logger.warning("Unknown 2FA method %r — defaulting to NONE.", raw_2fa)
        two_factor_method = TwoFactorMethod.NONE

    raw_tunnel = data.get("tunnel_type", "ssl")
    try:
        tunnel_type = TunnelType(raw_tunnel)
    except ValueError:
        logger.warning("Unknown tunnel type %r — defaulting to SSL.", raw_tunnel)
        tunnel_type = TunnelType.SSL

    return Profile(
        id=raw_id,
        name=data.get("name", ""),
        server=data.get("server", ""),
        username=data.get("username", ""),
        domain=data.get("domain") or None,
        ssl_port=ssl_port,
        ca_list=data.get("ca_list", "/etc/ssl/certs"),
        certificate=data.get("certificate"),
        reauth=bool(data.get("reauth", True)),
        save_password=bool(data.get("save_password", False)),
        cipher=data.get("cipher"),
        two_factor_method=two_factor_method,
        save_totp_secret=bool(data.get("save_totp_secret", False)),
        combined_auth=bool(data.get("combined_auth", False)),
        portal_auth=bool(data.get("portal_auth", False)),
        ccc_only_auth=bool(data.get("ccc_only_auth", False)),
        tunnel_type=tunnel_type,
        esp_settings=data.get("esp_settings") or None,
        ike_settings=data.get("ike_settings") or None,
        backend=data.get("backend", "auto"),
        login_type=data.get("login_type", ""),
        transport_type=data.get("transport_type", "auto"),
        ignore_server_cert=bool(data.get("ignore_server_cert", False)),
    )


# ---------------------------------------------------------------------------
# ProfileManager
# ---------------------------------------------------------------------------

class ProfileManager:
    """Manages persistence and retrieval of :class:`Profile` objects.

    Args:
        profiles_path: Override the default ``profiles.json`` location.
            Useful for testing.

    Example::

        pm = ProfileManager()
        profile = Profile(name="Work", server="vpn.example.com", username="alice")
        pm.create(profile)
        profiles = pm.list_all()
    """

    def __init__(self, profiles_path: Optional[Path] = None) -> None:
        self._path: Path = profiles_path or _default_profiles_path()
        self._lock_path: Path = self._path.with_suffix(".lock")
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _load_raw(self) -> dict:
        """Read and parse the JSON file.  Returns an empty document on first run."""
        if not self._path.exists():
            return {"version": _FILE_FORMAT_VERSION, "default_id": None, "profiles": {}}

        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read profiles file %s: %s", self._path, exc)
            return {"version": _FILE_FORMAT_VERSION, "default_id": None, "profiles": {}}

        # Guard against a corrupted file where the top-level value is not a
        # dict (e.g. the file contains a JSON array or a bare null).
        # Must be checked BEFORE _migrate(), which calls data.get().
        if not isinstance(data, dict):
            logger.error(
                "profiles.json has an invalid top-level structure (%r) — resetting.",
                type(data).__name__,
            )
            return {"version": _FILE_FORMAT_VERSION, "default_id": None, "profiles": {}}

        data = self._migrate(data)

        # Ensure 'profiles' is always a dict; null / list / string would
        # cause AttributeError in list_all(), get(), create(), etc.
        if not isinstance(data.get("profiles"), dict):
            logger.warning(
                "profiles.json: 'profiles' field is not a dict (%r) — resetting to empty.",
                type(data.get("profiles")).__name__,
            )
            data["profiles"] = {}

        # Ensure 'default_id' is either a string or None.
        if not isinstance(data.get("default_id"), (str, type(None))):
            data["default_id"] = None

        return data

    def _save_raw(self, data: dict) -> None:
        """Atomically write *data* to the JSON file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            tmp_path.replace(self._path)
        except OSError as exc:
            logger.error("Failed to save profiles to %s: %s", self._path, exc)
            raise
        finally:
            # Clean up the staging file if it still exists.  After a
            # successful replace() tmp_path no longer exists, so
            # unlink(missing_ok=True) is a silent no-op.  After a failed
            # replace() or a json.dump() error the partial file is removed
            # here so it cannot interfere with the next write attempt.
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                logger.debug("Failed to remove staging file %s.", tmp_path, exc_info=True)

    def _migrate(self, data: dict) -> dict:
        """Apply any necessary schema migrations to *data* in-place."""
        version = data.get("version", 0)
        if version < _FILE_FORMAT_VERSION:
            logger.info(
                "Migrating profiles.json from version %d to %d",
                version,
                _FILE_FORMAT_VERSION,
            )
        if version < 2:
            for profile_data in (data.get("profiles") or {}).values():
                profile_data.setdefault("two_factor_method", "none")
                profile_data.setdefault("save_totp_secret", False)
            data["version"] = 2
        if version < 3:
            for profile_data in (data.get("profiles") or {}).values():
                profile_data.setdefault("domain", None)
            data["version"] = 3
        if version < 4:
            for profile_data in (data.get("profiles") or {}).values():
                profile_data.setdefault("tunnel_type", "ssl")
                profile_data.setdefault("esp_settings", None)
                profile_data.setdefault("ike_settings", None)
            data["version"] = 4
        if version < 5:
            for profile_data in (data.get("profiles") or {}).values():
                profile_data.setdefault("combined_auth", False)
            data["version"] = 5
        if version < 6:
            for profile_data in (data.get("profiles") or {}).values():
                profile_data.setdefault("portal_auth", False)
            data["version"] = 6
        if version < 7:
            for profile_data in (data.get("profiles") or {}).values():
                # Existing profiles use the SNX binary — preserve behavior.
                profile_data.setdefault("backend", "snx")
                profile_data.setdefault("login_type", "")
                profile_data.setdefault("transport_type", "auto")
                profile_data.setdefault("ignore_server_cert", False)
            data["version"] = 7
        if version < 8:
            for profile_data in (data.get("profiles") or {}).values():
                profile_data.setdefault("ccc_only_auth", False)
            data["version"] = 8
        if version < 9:
            for profile_data in (data.get("profiles") or {}).values():
                # All profiles migrate to python_ssl — the only supported backend.
                profile_data["backend"] = "python_ssl"
                profile_data["transport_type"] = "auto"
                profile_data["ccc_only_auth"] = False
                profile_data["combined_auth"] = False
                profile_data["portal_auth"] = False
            data["version"] = 9
        return data

    def _with_file_lock(self, fn: Callable[[], Any]) -> Any:
        """Execute *fn* under both the threading Lock and a FileLock.

        This protects against concurrent access from multiple threads as well
        as multiple processes.  A 5-second timeout is used for the file lock
        to avoid blocking indefinitely.
        """
        with self._lock:
            try:
                # Ensure the config directory exists before FileLock tries to
                # create the lock file inside it.  On a fresh install the
                # directory does not yet exist; filelock calls open(lock_file,
                # 'a') which raises FileNotFoundError if the parent is absent.
                # _save_raw() also creates the directory, but only after the
                # lock is held — too late for read-only operations like
                # list_all() that never call _save_raw().
                self._path.parent.mkdir(parents=True, exist_ok=True)
                file_lock = FileLock(str(self._lock_path), timeout=5)
                with file_lock:
                    return fn()
            except Timeout:
                logger.error(
                    "Could not acquire file lock for %s within 5 seconds",
                    self._lock_path,
                )
                raise

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate(profile: Profile) -> None:
        """Raise :class:`ValueError` if *profile* has missing required fields.

        Args:
            profile: The profile to validate.

        Raises:
            ValueError: If ``server`` or ``username`` are empty.
        """
        if not profile.server.strip():
            raise ValueError("Profile 'server' must not be empty.")
        if not profile.username.strip():
            raise ValueError("Profile 'username' must not be empty.")
        if not 1 <= profile.ssl_port <= 65535:
            raise ValueError(
                f"Profile 'ssl_port' must be between 1 and 65535 (got {profile.ssl_port})."
            )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(self, profile: Profile) -> Profile:
        """Persist a new profile.

        Args:
            profile: Profile to store.  Its ``id`` field must be unique.

        Returns:
            The stored profile (same object).

        Raises:
            ValueError: If validation fails or the profile ID already exists.
        """
        self.validate(profile)

        def _do() -> Profile:
            data = self._load_raw()
            if profile.id in data["profiles"]:
                raise ValueError(f"Profile with id={profile.id!r} already exists.")
            data["profiles"][profile.id] = _profile_to_dict(profile)
            # First ever profile becomes the default automatically.
            if data.get("default_id") is None:
                data["default_id"] = profile.id
            self._save_raw(data)
            return profile

        return self._with_file_lock(_do)

    def get(self, profile_id: str) -> Optional[Profile]:
        """Retrieve a profile by its ID.

        Args:
            profile_id: UUID string of the desired profile.

        Returns:
            The matching :class:`Profile`, or ``None`` if not found.
        """

        def _do() -> Optional[Profile]:
            data = self._load_raw()
            raw = data["profiles"].get(profile_id)
            if raw is None:
                return None
            return _profile_from_dict(raw)

        return self._with_file_lock(_do)

    def list_all(self) -> list[Profile]:
        """Return all stored profiles in insertion order.

        Returns:
            List of :class:`Profile` objects (may be empty).
        """

        def _do() -> list[Profile]:
            data = self._load_raw()
            return [_profile_from_dict(v) for v in data["profiles"].values()]

        return self._with_file_lock(_do)

    def update(self, profile: Profile) -> Profile:
        """Overwrite an existing profile with new data.

        Args:
            profile: Updated profile.  The ``id`` field must match an existing
                record.

        Returns:
            The updated profile.

        Raises:
            ValueError: If validation fails or no profile with that ID exists.
            KeyError: If ``profile.id`` is not found.
        """
        self.validate(profile)

        def _do() -> Profile:
            data = self._load_raw()
            if profile.id not in data["profiles"]:
                raise KeyError(f"Profile with id={profile.id!r} not found.")
            data["profiles"][profile.id] = _profile_to_dict(profile)
            self._save_raw(data)
            return profile

        return self._with_file_lock(_do)

    def delete(self, profile_id: str) -> bool:
        """Remove a profile by ID.

        If the deleted profile was the default, the default is cleared (or
        reassigned to the first remaining profile when one exists).

        Args:
            profile_id: ID of the profile to remove.

        Returns:
            ``True`` if the profile was found and deleted, ``False`` otherwise.
        """

        def _do() -> bool:
            data = self._load_raw()
            if profile_id not in data["profiles"]:
                logger.warning("delete() called for unknown profile id=%r", profile_id)
                return False
            del data["profiles"][profile_id]
            # Re-assign default if needed.
            if data.get("default_id") == profile_id:
                remaining = list(data["profiles"].keys())
                data["default_id"] = remaining[0] if remaining else None
            self._save_raw(data)
            return True

        return self._with_file_lock(_do)

    # ------------------------------------------------------------------
    # Default profile
    # ------------------------------------------------------------------

    def get_default(self) -> Optional[Profile]:
        """Return the default profile, or ``None`` if none is set.

        Returns:
            The default :class:`Profile` or ``None``.
        """

        def _do() -> Optional[Profile]:
            data = self._load_raw()
            default_id = data.get("default_id")
            if not default_id:
                return None
            raw = data["profiles"].get(default_id)
            if raw is None:
                return None
            return _profile_from_dict(raw)

        return self._with_file_lock(_do)

    def set_default(self, profile_id: str) -> None:
        """Mark *profile_id* as the default profile.

        Args:
            profile_id: ID of the profile to set as default.

        Raises:
            KeyError: If no profile with that ID exists.
        """

        def _do() -> None:
            data = self._load_raw()
            if profile_id not in data["profiles"]:
                raise KeyError(f"Profile with id={profile_id!r} not found.")
            data["default_id"] = profile_id
            self._save_raw(data)

        self._with_file_lock(_do)
