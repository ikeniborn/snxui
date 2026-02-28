"""Tests for snxui.ui.profiles_page.ProfilesPage.

GTK4/Libadwaita are mocked so these tests run without a display or GTK
installation.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from snxui.core.types import Profile


# ---------------------------------------------------------------------------
# Mock GTK before any snxui.ui.profiles_page import so conditional imports
# succeed.  Use setdefault so we don't overwrite mocks registered by other
# test modules (e.g. test_ui_app.py) that run in the same process.
# ---------------------------------------------------------------------------

_gi_mock = MagicMock()
_gtk_mock = MagicMock()
_adw_mock = MagicMock()

sys.modules.setdefault("gi", _gi_mock)
sys.modules.setdefault("gi.repository", _gtk_mock)
sys.modules.setdefault("gi.repository.Gtk", _gtk_mock)
sys.modules.setdefault("gi.repository.Adw", _adw_mock)
sys.modules.setdefault("gi.repository.GLib", _gtk_mock)
sys.modules.setdefault("gi.repository.Gio", _gtk_mock)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_page(
    profiles: list | None = None,
    credential_store: object = None,
):
    """Return a ProfilesPage with mocked ProfileManager and CredentialStore."""
    from snxui.ui.profiles_page import ProfilesPage

    mock_pm = MagicMock(name="ProfileManager")
    mock_pm.list_all.return_value = profiles or []
    mock_cs = credential_store if credential_store is not None else MagicMock(name="CredentialStore")

    page = ProfilesPage(profile_manager=mock_pm, credential_store=mock_cs)
    return page, mock_pm, mock_cs


def _capture_response_cb(mock_dialog: MagicMock):
    """Extract the callback registered via dialog.connect('response', cb)."""
    for c in mock_dialog.connect.call_args_list:
        if c[0][0] == "response":
            return c[0][1]
    return None


# ---------------------------------------------------------------------------
# TestDeleteCleansCredentials
# ---------------------------------------------------------------------------


class TestDeleteCleansCredentials:
    def test_delete_calls_delete_password(self) -> None:
        """delete_password must be called when the user confirms profile deletion.

        Before the fix, ProfilesPage had no reference to CredentialStore, so
        the keyring entry for a deleted profile was never removed.  The
        orphaned entry persisted indefinitely in GNOME Keyring / KDE Wallet.
        """
        profile = Profile(name="Work", server="vpn.example.com", username="alice")
        page, mock_pm, mock_cs = _make_page(profiles=[profile])

        mock_dialog = MagicMock(name="AlertDialog")
        with patch("snxui.ui.profiles_page.Adw") as mock_adw:
            mock_adw.AlertDialog.return_value = mock_dialog
            mock_adw.ResponseAppearance = MagicMock()
            page._on_delete(profile)

        response_cb = _capture_response_cb(mock_dialog)
        assert response_cb is not None, "dialog.connect('response', ...) was not called"

        # Simulate user clicking "Delete" in the confirmation dialog.
        response_cb(mock_dialog, "delete")

        mock_pm.delete.assert_called_once_with(profile.id)
        mock_cs.delete_password.assert_called_once_with(profile.id)

    def test_cancel_does_not_call_delete_password(self) -> None:
        """delete_password must NOT be called when the user cancels deletion."""
        profile = Profile(name="Work", server="vpn.example.com", username="alice")
        page, mock_pm, mock_cs = _make_page(profiles=[profile])

        mock_dialog = MagicMock(name="AlertDialog")
        with patch("snxui.ui.profiles_page.Adw") as mock_adw:
            mock_adw.AlertDialog.return_value = mock_dialog
            mock_adw.ResponseAppearance = MagicMock()
            page._on_delete(profile)

        response_cb = _capture_response_cb(mock_dialog)
        assert response_cb is not None

        # Simulate user clicking "Cancel".
        response_cb(mock_dialog, "cancel")

        mock_pm.delete.assert_not_called()
        mock_cs.delete_password.assert_not_called()

    def test_no_credential_store_does_not_crash(self) -> None:
        """ProfilesPage must work without a credential_store (backwards compat).

        credential_store is an optional parameter; omitting it must not raise
        when the user deletes a profile.
        """
        from snxui.ui.profiles_page import ProfilesPage

        profile = Profile(name="Work", server="vpn.example.com", username="alice")
        mock_pm = MagicMock(name="ProfileManager")
        mock_pm.list_all.return_value = [profile]

        page = ProfilesPage(profile_manager=mock_pm)  # no credential_store

        mock_dialog = MagicMock(name="AlertDialog")
        with patch("snxui.ui.profiles_page.Adw") as mock_adw:
            mock_adw.AlertDialog.return_value = mock_dialog
            mock_adw.ResponseAppearance = MagicMock()
            page._on_delete(profile)

        response_cb = _capture_response_cb(mock_dialog)
        assert response_cb is not None

        # Must not raise even when self._cs is None.
        response_cb(mock_dialog, "delete")
        mock_pm.delete.assert_called_once_with(profile.id)

    def test_delete_password_error_does_not_abort_refresh(self) -> None:
        """A keyring error during delete must not prevent the page from refreshing."""
        profile = Profile(name="Work", server="vpn.example.com", username="alice")
        mock_cs = MagicMock(name="CredentialStore")
        mock_cs.delete_password.side_effect = RuntimeError("keyring unavailable")
        page, mock_pm, _ = _make_page(profiles=[profile], credential_store=mock_cs)

        mock_dialog = MagicMock(name="AlertDialog")
        with patch("snxui.ui.profiles_page.Adw") as mock_adw:
            mock_adw.AlertDialog.return_value = mock_dialog
            mock_adw.ResponseAppearance = MagicMock()
            page._on_delete(profile)

        response_cb = _capture_response_cb(mock_dialog)
        assert response_cb is not None

        # Must not raise; refresh() (i.e. list_all) must still be called.
        response_cb(mock_dialog, "delete")
        mock_pm.list_all.assert_called()
