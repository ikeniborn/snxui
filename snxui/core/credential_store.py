"""Credential storage — keyring/libsecret integration for SNX passwords.

Passwords are stored using the ``keyring`` library which transparently
delegates to the platform secret service:

* **GNOME / Ubuntu** — libsecret → GNOME Keyring (Secret Service D-Bus)
* **KDE Plasma** — KDE Wallet (via the same Secret Service D-Bus API)
* **Fallback** — plaintext in-memory store with a logged warning

The service name is ``"snxui"`` and each profile's password is keyed by
``"profile:{profile_id}"``.
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_SERVICE_NAME = "snxui"
_KEY_PREFIX = "profile:"
_TOTP_PREFIX = "totp:"


def _make_key(profile_id: str) -> str:
    """Return the keyring username/key for *profile_id*."""
    return f"{_KEY_PREFIX}{profile_id}"


def _make_totp_key(profile_id: str) -> str:
    """Return the keyring username/key for the TOTP secret of *profile_id*."""
    return f"{_TOTP_PREFIX}{profile_id}"


def wipe_string(secret: str) -> None:
    """Drop the local reference to a password string.

    Python strings are immutable objects managed by the GC.  There is no
    portable, version-stable way to zero a ``str``'s character buffer in
    CPython: ``id(obj)`` returns the address of the *PyObject header*
    (refcount + type pointer), NOT the character data, so writing to
    ``id(obj)`` corrupts the object header rather than the password bytes.

    Callers that require guaranteed memory wiping should use ``bytearray``
    instead of ``str`` and zero it explicitly::

        buf = bytearray(b"secret")
        # ... use buf ...
        for i in range(len(buf)):
            buf[i] = 0

    Args:
        secret: The string reference to release.
    """
    # The ``del`` here only removes the local name binding.  Whether CPython
    # reclaims the underlying buffer depends on whether any other reference
    # to the string object exists (interning, caller's scope, etc.).
    del secret


class CredentialStore:
    """Interface to the platform keyring for storing SNX passwords.

    When the keyring backend is unavailable (e.g. headless server, missing
    libsecret), the store degrades to a volatile in-memory cache with a
    logged warning rather than crashing the application.

    Usage::

        store = CredentialStore()
        if store.is_available():
            store.set_password(profile_id, password)
            pw = store.get_password(profile_id)
    """

    def __init__(self) -> None:
        self._probe_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._available: Optional[bool] = None
        # Volatile fallback: {profile_id: password}
        self._memory_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return ``True`` if a functional keyring backend is accessible.

        The result is cached after the first call.  A dummy write/read/delete
        cycle is performed to ensure the backend actually works end-to-end.

        Returns:
            ``True`` if the keyring is operational, ``False`` otherwise.
        """
        # Fast path — already determined, no lock needed (bool read is atomic in CPython).
        if self._available is not None:
            return self._available

        with self._probe_lock:
            # Double-checked: another thread may have completed the probe
            # between the fast-path check above and acquiring the lock.
            if self._available is not None:
                return self._available

            try:
                import keyring  # noqa: PLC0415

                keyring.set_password(_SERVICE_NAME, "__probe__", "1")
                try:
                    val = keyring.get_password(_SERVICE_NAME, "__probe__")
                    self._available = val == "1"
                finally:
                    # Always attempt cleanup so the probe entry is not left in
                    # the user's keyring if get_password or delete_password raises.
                    try:
                        keyring.delete_password(_SERVICE_NAME, "__probe__")
                    except Exception:  # noqa: BLE001
                        logger.debug("Keyring probe cleanup failed.", exc_info=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Keyring backend is not available: %s. "
                    "Passwords will be kept in volatile memory only.",
                    exc,
                )
                self._available = False

        return self._available

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_password(self, profile_id: str, password: str) -> bool:
        """Store *password* for the given profile.

        Args:
            profile_id: UUID of the profile whose password to store.
            password: The plaintext password to persist.

        Returns:
            ``True`` if the password was stored in the keyring, ``False`` if
            the fallback memory cache was used instead.
        """
        key = _make_key(profile_id)

        if self.is_available():
            try:
                import keyring  # noqa: PLC0415

                keyring.set_password(_SERVICE_NAME, key, password)
                logger.debug("Password stored in keyring for profile %s", profile_id)
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to write to keyring for profile %s: %s. "
                    "Using memory fallback.",
                    profile_id,
                    exc,
                )

        # Fallback: in-memory only (session-scoped).
        with self._cache_lock:
            self._memory_cache[profile_id] = password
        logger.warning(
            "Password for profile %s stored in volatile memory (not persisted).",
            profile_id,
        )
        return False

    def get_password(self, profile_id: str) -> Optional[str]:
        """Retrieve the stored password for *profile_id*.

        Args:
            profile_id: UUID of the profile whose password to retrieve.

        Returns:
            The stored password, or ``None`` if none is found.
        """
        key = _make_key(profile_id)

        if self.is_available():
            try:
                import keyring  # noqa: PLC0415

                password = keyring.get_password(_SERVICE_NAME, key)
                if password is not None:
                    logger.debug("Password retrieved from keyring for profile %s", profile_id)
                    return password
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to read from keyring for profile %s: %s",
                    profile_id,
                    exc,
                )

        # Try memory fallback.
        with self._cache_lock:
            cached = self._memory_cache.get(profile_id)
        if cached is not None:
            logger.debug("Password retrieved from memory cache for profile %s", profile_id)
        return cached

    def delete_password(self, profile_id: str) -> bool:
        """Remove the stored password for *profile_id*.

        Args:
            profile_id: UUID of the profile whose password to remove.

        Returns:
            ``True`` if a password was deleted, ``False`` if none was found.
        """
        key = _make_key(profile_id)
        deleted_from_keyring = False

        if self.is_available():
            try:
                import keyring  # noqa: PLC0415

                keyring.delete_password(_SERVICE_NAME, key)
                deleted_from_keyring = True
                logger.debug("Password deleted from keyring for profile %s", profile_id)
            except Exception as exc:  # noqa: BLE001
                # keyring.errors.PasswordDeleteError is a subclass of Exception and
                # indicates the password was not present — not a fatal error.
                # We catch all exceptions here to also handle backend failures.
                exc_type = type(exc).__name__
                if "PasswordDeleteError" in exc_type or "NotFound" in str(exc):
                    logger.debug(
                        "Password not found in keyring for profile %s (already deleted?).",
                        profile_id,
                    )
                else:
                    logger.warning(
                        "Failed to delete password from keyring for profile %s: %s",
                        profile_id,
                        exc,
                    )

        # Clear memory cache regardless.
        with self._cache_lock:
            cached = self._memory_cache.pop(profile_id, None)
        if cached is not None:
            wipe_string(cached)

        return deleted_from_keyring or (cached is not None)

    def set_totp_secret(self, profile_id: str, secret: str) -> bool:
        """Store the TOTP *secret* for the given profile.

        Args:
            profile_id: UUID of the profile whose TOTP secret to store.
            secret: The plaintext Base32 TOTP secret to persist.

        Returns:
            ``True`` if the secret was stored in the keyring, ``False`` if
            the fallback memory cache was used instead.
        """
        key = _make_totp_key(profile_id)

        if self.is_available():
            try:
                import keyring  # noqa: PLC0415

                keyring.set_password(_SERVICE_NAME, key, secret)
                logger.debug("TOTP secret stored in keyring for profile %s", profile_id)
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to write TOTP secret to keyring for profile %s: %s. "
                    "Using memory fallback.",
                    profile_id,
                    exc,
                )

        # Fallback: in-memory only (session-scoped).
        with self._cache_lock:
            self._memory_cache[key] = secret
        logger.warning(
            "TOTP secret for profile %s stored in volatile memory (not persisted).",
            profile_id,
        )
        return False

    def get_totp_secret(self, profile_id: str) -> Optional[str]:
        """Retrieve the stored TOTP secret for *profile_id*.

        Args:
            profile_id: UUID of the profile whose TOTP secret to retrieve.

        Returns:
            The stored Base32 secret, or ``None`` if none is found.
        """
        key = _make_totp_key(profile_id)

        if self.is_available():
            try:
                import keyring  # noqa: PLC0415

                secret = keyring.get_password(_SERVICE_NAME, key)
                if secret is not None:
                    logger.debug("TOTP secret retrieved from keyring for profile %s", profile_id)
                    return secret
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to read TOTP secret from keyring for profile %s: %s",
                    profile_id,
                    exc,
                )

        # Try memory fallback.
        with self._cache_lock:
            cached = self._memory_cache.get(key)
        if cached is not None:
            logger.debug("TOTP secret retrieved from memory cache for profile %s", profile_id)
        return cached

    def delete_totp_secret(self, profile_id: str) -> bool:
        """Remove the stored TOTP secret for *profile_id*.

        Args:
            profile_id: UUID of the profile whose TOTP secret to remove.

        Returns:
            ``True`` if a secret was deleted, ``False`` if none was found.
        """
        key = _make_totp_key(profile_id)
        deleted_from_keyring = False

        if self.is_available():
            try:
                import keyring  # noqa: PLC0415

                keyring.delete_password(_SERVICE_NAME, key)
                deleted_from_keyring = True
                logger.debug("TOTP secret deleted from keyring for profile %s", profile_id)
            except Exception as exc:  # noqa: BLE001
                exc_type = type(exc).__name__
                if "PasswordDeleteError" in exc_type or "NotFound" in str(exc):
                    logger.debug(
                        "TOTP secret not found in keyring for profile %s (already deleted?).",
                        profile_id,
                    )
                else:
                    logger.warning(
                        "Failed to delete TOTP secret from keyring for profile %s: %s",
                        profile_id,
                        exc,
                    )

        # Clear memory cache regardless.
        with self._cache_lock:
            cached = self._memory_cache.pop(key, None)
        if cached is not None:
            wipe_string(cached)

        return deleted_from_keyring or (cached is not None)

    def clear_all(self) -> None:
        """Wipe the in-memory cache (does not touch the keyring).

        Clears both password and TOTP secret entries.
        Call this on application exit or when switching users.
        """
        with self._cache_lock:
            for pw in self._memory_cache.values():
                wipe_string(pw)
            self._memory_cache.clear()
        logger.debug("In-memory credential cache cleared.")
