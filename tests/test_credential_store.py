"""Tests for snxui.core.credential_store.

The keyring library is mocked to avoid touching any real secret-service backend
(GNOME Keyring, KDE Wallet) during CI.  A separate test class verifies the
fallback behaviour when keyring is unavailable.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest

from snxui.core.credential_store import (
    CredentialStore,
    wipe_string,
    _SERVICE_NAME,
    _make_key,
    _make_totp_key,
)


# ---------------------------------------------------------------------------
# wipe_string helper
# ---------------------------------------------------------------------------


class TestWipeString:
    def test_wipe_does_not_raise(self) -> None:
        """wipe_string must never raise, even on edge cases."""
        wipe_string("hello")
        wipe_string("")
        wipe_string("a" * 1000)

    def test_wipe_accepts_unicode(self) -> None:
        wipe_string("пароль123")


# ---------------------------------------------------------------------------
# _make_key helper
# ---------------------------------------------------------------------------


class TestMakeKey:
    def test_prefix(self) -> None:
        assert _make_key("abc-123") == "profile:abc-123"


# ---------------------------------------------------------------------------
# CredentialStore with working keyring mock
# ---------------------------------------------------------------------------


@pytest.fixture()
def keyring_mock():
    """Patch the 'keyring' module inside credential_store with a functional mock."""
    mock = MagicMock()
    # Simulate a working keyring: probe read returns '1'
    mock.get_password.return_value = "1"
    mock.set_password.return_value = None
    mock.delete_password.return_value = None

    with patch.dict("sys.modules", {"keyring": mock, "keyring.errors": MagicMock()}):
        yield mock


@pytest.fixture()
def store_with_keyring(keyring_mock) -> CredentialStore:
    cs = CredentialStore()
    # Force is_available() to return True (probe succeeded with mock)
    cs._available = True
    return cs


class TestCredentialStoreKeyring:
    def test_is_available_true(self, store_with_keyring: CredentialStore) -> None:
        assert store_with_keyring.is_available() is True

    def test_set_password_calls_keyring(self, store_with_keyring: CredentialStore, keyring_mock) -> None:
        keyring_mock.set_password.reset_mock()
        result = store_with_keyring.set_password("pid-1", "secret")
        assert result is True
        keyring_mock.set_password.assert_called_once_with(
            _SERVICE_NAME, _make_key("pid-1"), "secret"
        )

    def test_get_password_returns_stored(self, store_with_keyring: CredentialStore, keyring_mock) -> None:
        keyring_mock.get_password.return_value = "mysecret"
        pw = store_with_keyring.get_password("pid-1")
        assert pw == "mysecret"

    def test_get_password_none_when_not_found(self, store_with_keyring: CredentialStore, keyring_mock) -> None:
        keyring_mock.get_password.return_value = None
        pw = store_with_keyring.get_password("pid-999")
        assert pw is None

    def test_delete_password_calls_keyring(self, store_with_keyring: CredentialStore, keyring_mock) -> None:
        result = store_with_keyring.delete_password("pid-1")
        keyring_mock.delete_password.assert_called_once_with(
            _SERVICE_NAME, _make_key("pid-1")
        )
        assert result is True

    def test_delete_calls_keyring_even_if_not_set(self, store_with_keyring: CredentialStore, keyring_mock) -> None:
        """delete_password forwards the call to keyring and returns True when keyring
        does not raise (keyring backends vary: some raise PasswordDeleteError if the
        key is absent, others silently succeed).  When no exception is raised and the
        profile is absent from the memory cache, deleted_from_keyring=True is the only
        signal available, so the method returns True."""
        keyring_mock.delete_password.side_effect = None  # reset
        keyring_mock.delete_password.return_value = None

        # Profile was never stored — not in memory cache.
        result = store_with_keyring.delete_password("pid-none-at-all")
        # keyring.delete_password did not raise → deleted_from_keyring=True.
        assert result is True


# ---------------------------------------------------------------------------
# CredentialStore with unavailable keyring (fallback to memory)
# ---------------------------------------------------------------------------


@pytest.fixture()
def store_no_keyring() -> CredentialStore:
    """Return a CredentialStore where keyring is explicitly unavailable."""
    cs = CredentialStore()
    cs._available = False  # skip probe
    return cs


class TestCredentialStoreFallback:
    def test_is_available_false(self, store_no_keyring: CredentialStore) -> None:
        assert store_no_keyring.is_available() is False

    def test_set_returns_false(self, store_no_keyring: CredentialStore) -> None:
        result = store_no_keyring.set_password("pid-1", "secret")
        assert result is False

    def test_get_from_memory(self, store_no_keyring: CredentialStore) -> None:
        store_no_keyring.set_password("pid-1", "secret")
        assert store_no_keyring.get_password("pid-1") == "secret"

    def test_delete_from_memory(self, store_no_keyring: CredentialStore) -> None:
        store_no_keyring.set_password("pid-1", "secret")
        result = store_no_keyring.delete_password("pid-1")
        assert result is True
        assert store_no_keyring.get_password("pid-1") is None

    def test_clear_all_wipes_cache(self, store_no_keyring: CredentialStore) -> None:
        store_no_keyring.set_password("pid-1", "s1")
        store_no_keyring.set_password("pid-2", "s2")
        store_no_keyring.clear_all()
        assert store_no_keyring.get_password("pid-1") is None
        assert store_no_keyring.get_password("pid-2") is None

    def test_get_nonexistent_returns_none(self, store_no_keyring: CredentialStore) -> None:
        assert store_no_keyring.get_password("no-such") is None


# ---------------------------------------------------------------------------
# is_available() probe logic
# ---------------------------------------------------------------------------


class TestIsAvailableProbe:
    def test_probe_success(self) -> None:
        mock = MagicMock()
        mock.get_password.return_value = "1"
        with patch.dict("sys.modules", {"keyring": mock, "keyring.errors": MagicMock()}):
            cs = CredentialStore()
            assert cs.is_available() is True

    def test_probe_failure_returns_false(self) -> None:
        mock = MagicMock()
        mock.set_password.side_effect = Exception("no daemon")
        with patch.dict("sys.modules", {"keyring": mock, "keyring.errors": MagicMock()}):
            cs = CredentialStore()
            assert cs.is_available() is False

    def test_probe_wrong_value_returns_false(self) -> None:
        mock = MagicMock()
        mock.get_password.return_value = "wrong"
        with patch.dict("sys.modules", {"keyring": mock, "keyring.errors": MagicMock()}):
            cs = CredentialStore()
            assert cs.is_available() is False

    def test_probe_cached(self) -> None:
        """is_available() must only probe once."""
        mock = MagicMock()
        mock.get_password.return_value = "1"
        with patch.dict("sys.modules", {"keyring": mock, "keyring.errors": MagicMock()}):
            cs = CredentialStore()
            cs.is_available()
            cs.is_available()
            # set_password called once (probe), not twice
            assert mock.set_password.call_count == 1

    def test_probe_key_cleaned_up_when_get_password_raises(self) -> None:
        """Probe entry must be deleted even when get_password raises.

        If get_password raises (e.g. network timeout, backend crash) the
        original code skipped delete_password, leaving ("snxui", "__probe__",
        "1") permanently in the user's keyring.  The fix wraps the read in
        try/finally to guarantee cleanup.
        """
        mock = MagicMock()
        mock.set_password.return_value = None
        mock.get_password.side_effect = Exception("backend connection lost")
        with patch.dict("sys.modules", {"keyring": mock, "keyring.errors": MagicMock()}):
            cs = CredentialStore()
            result = cs.is_available()
        # Backend was unavailable.
        assert result is False
        # delete_password must have been called to clean up the probe entry.
        mock.delete_password.assert_called_once_with(_SERVICE_NAME, "__probe__")


# ---------------------------------------------------------------------------
# TOTP secret — set/get/delete
# ---------------------------------------------------------------------------


class TestTOTPSecretFallback:
    """TOTP secret tests using in-memory fallback (keyring unavailable)."""

    @pytest.fixture()
    def store(self) -> CredentialStore:
        cs = CredentialStore()
        cs._available = False
        return cs

    def test_make_totp_key_prefix(self) -> None:
        assert _make_totp_key("abc-123") == "totp:abc-123"

    def test_set_get_totp_secret(self, store: CredentialStore) -> None:
        result = store.set_totp_secret("pid-1", "JBSWY3DPEHPK3PXP")
        assert result is False  # memory fallback
        secret = store.get_totp_secret("pid-1")
        assert secret == "JBSWY3DPEHPK3PXP"

    def test_get_nonexistent_totp_returns_none(self, store: CredentialStore) -> None:
        assert store.get_totp_secret("no-such") is None

    def test_delete_totp_secret(self, store: CredentialStore) -> None:
        store.set_totp_secret("pid-1", "JBSWY3DPEHPK3PXP")
        result = store.delete_totp_secret("pid-1")
        assert result is True
        assert store.get_totp_secret("pid-1") is None

    def test_delete_nonexistent_totp_returns_false(self, store: CredentialStore) -> None:
        result = store.delete_totp_secret("no-such")
        assert result is False

    def test_totp_key_independent_of_password_key(self, store: CredentialStore) -> None:
        """Same profile_id: password and TOTP secret must not overwrite each other."""
        store.set_password("pid-shared", "mypassword")
        store.set_totp_secret("pid-shared", "JBSWY3DPEHPK3PXP")

        assert store.get_password("pid-shared") == "mypassword"
        assert store.get_totp_secret("pid-shared") == "JBSWY3DPEHPK3PXP"

        # Deleting TOTP must not affect password
        store.delete_totp_secret("pid-shared")
        assert store.get_password("pid-shared") == "mypassword"
        assert store.get_totp_secret("pid-shared") is None

    def test_clear_all_wipes_totp_secrets(self, store: CredentialStore) -> None:
        store.set_totp_secret("pid-1", "SECRET1")
        store.set_password("pid-1", "pass1")
        store.clear_all()
        assert store.get_totp_secret("pid-1") is None
        assert store.get_password("pid-1") is None
