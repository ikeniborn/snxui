"""Tests for snxui.ui.dialogs — PasswordDialog, ProfileDialog, AboutDialog.

GTK4/Libadwaita are mocked so tests run without a display.
"""

from __future__ import annotations

import sys
import uuid
from unittest.mock import MagicMock, patch, call
import pytest


# ---------------------------------------------------------------------------
# Mock GTK modules before importing dialogs.
# ---------------------------------------------------------------------------

def _install_gtk_mocks() -> tuple:
    """Return (gtk_mock, adw_mock) after installing them into sys.modules."""
    gtk_mock = MagicMock(name="Gtk")
    adw_mock = MagicMock(name="Adw")
    gi_mock = MagicMock(name="gi")
    glib_mock = MagicMock(name="GLib")

    sys.modules.setdefault("gi", gi_mock)
    sys.modules.setdefault("gi.repository", gtk_mock)
    sys.modules.setdefault("gi.repository.Gtk", gtk_mock)
    sys.modules.setdefault("gi.repository.Adw", adw_mock)
    sys.modules.setdefault("gi.repository.GLib", glib_mock)
    sys.modules.setdefault("gi.repository.Gio", MagicMock())

    return gtk_mock, adw_mock


_GTK_MOCK, _ADW_MOCK = _install_gtk_mocks()


# ---------------------------------------------------------------------------
# PasswordDialog
# ---------------------------------------------------------------------------


class TestPasswordDialog:
    def _make_dialog(self, profile_name: str = "Work VPN") -> object:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            from snxui.ui.dialogs import PasswordDialog
            return PasswordDialog(profile_name=profile_name)

    def test_init_stores_profile_name(self) -> None:
        dlg = self._make_dialog("My VPN")
        assert dlg._profile_name == "My VPN"

    def test_show_creates_adw_dialog(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", _ADW_MOCK):
                with patch.object(dlg_mod, "Gtk", _GTK_MOCK):
                    dlg = self._make_dialog("Work VPN")
                    callback = MagicMock()
                    dlg.show(callback=callback)

        # Adw.Dialog should have been constructed.
        _ADW_MOCK.Dialog.assert_called()

    def test_show_raises_without_gtk(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", False):
            with pytest.raises(ImportError):
                from snxui.ui.dialogs import PasswordDialog
                PasswordDialog(profile_name="x").show(callback=MagicMock())

    def test_callback_receives_none_on_cancel(self) -> None:
        """Cancel button registered in show() calls callback(None, False) when clicked."""
        from snxui.ui import dialogs as dlg_mod

        received = []

        def callback(pw, save):
            received.append((pw, save))

        local_gtk = MagicMock(name="Gtk")
        local_adw = MagicMock(name="Adw")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import PasswordDialog
                    dlg = PasswordDialog(profile_name="Work VPN")
                    dlg.show(callback=callback)

        # Both cancel and connect buttons are Gtk.Button.return_value (same mock
        # since MagicMock always returns the same instance for a given attribute).
        # cancel_btn.connect("clicked", lambda) is the FIRST connect() call.
        btn_mock = local_gtk.Button.return_value
        cancel_lambda = btn_mock.connect.call_args_list[0][0][1]
        cancel_lambda(None)  # simulate click; _b argument is unused

        assert received == [(None, False)]

    def test_callback_receives_password_on_connect(self) -> None:
        """Connect button registered in show() calls callback with the typed password."""
        from snxui.ui import dialogs as dlg_mod

        received = []

        def callback(pw, save):
            received.append((pw, save))

        local_gtk = MagicMock(name="Gtk")
        local_adw = MagicMock(name="Adw")

        # Wire the widget mocks so get_text / get_active return specific values.
        local_adw.PasswordEntryRow.return_value.get_text.return_value = "secret"
        local_gtk.CheckButton.return_value.get_active.return_value = True

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import PasswordDialog
                    dlg = PasswordDialog(profile_name="Work VPN")
                    dlg.show(callback=callback)

        # connect_btn.connect("clicked", lambda) is the SECOND connect() call.
        btn_mock = local_gtk.Button.return_value
        connect_lambda = btn_mock.connect.call_args_list[1][0][1]
        connect_lambda(None)  # simulate click

        assert received == [("secret", True)]


# ---------------------------------------------------------------------------
# ProfileDialog
# ---------------------------------------------------------------------------


class TestProfileDialog:
    def test_init_stores_profile_and_callback(self) -> None:
        from snxui.ui import dialogs as dlg_mod
        from snxui.core.types import Profile

        callback = MagicMock()
        profile = Profile(name="Work", server="vpn.work.com", username="alice")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            from snxui.ui.dialogs import ProfileDialog
            dlg = ProfileDialog(profile=profile, callback=callback)

        assert dlg._profile is profile
        assert dlg._callback is callback

    def test_init_accepts_none_profile_for_new(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        callback = MagicMock()

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            from snxui.ui.dialogs import ProfileDialog
            dlg = ProfileDialog(profile=None, callback=callback)

        assert dlg._profile is None

    def test_show_raises_without_gtk(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", False):
            with pytest.raises(ImportError):
                from snxui.ui.dialogs import ProfileDialog
                ProfileDialog(profile=None, callback=MagicMock()).show()

    def test_show_creates_adw_dialog_for_new_profile(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        local_adw = MagicMock(name="Adw")
        local_gtk = MagicMock(name="Gtk")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import ProfileDialog
                    dlg = ProfileDialog(profile=None, callback=MagicMock())
                    dlg.show()

        local_adw.Window.assert_called()

    def test_show_prefills_fields_for_existing_profile(self) -> None:
        from snxui.ui import dialogs as dlg_mod
        from snxui.core.types import Profile

        profile = Profile(
            name="Work",
            server="vpn.work.com",
            username="alice",
            ssl_port=8443,
            ca_list="/etc/ssl/certs",
        )

        local_adw = MagicMock(name="Adw")
        local_gtk = MagicMock(name="Gtk")

        name_row = MagicMock()
        server_row = MagicMock()
        user_row = MagicMock()
        port_row = MagicMock()
        ca_row = MagicMock()
        cert_row = MagicMock()
        save_row = MagicMock()

        # EntryRow returns the mock row objects in sequence.
        local_adw.EntryRow.side_effect = [name_row, server_row, user_row, ca_row, cert_row]
        local_adw.SpinRow.new_with_range.return_value = port_row
        local_adw.SwitchRow.return_value = save_row

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import ProfileDialog
                    dlg = ProfileDialog(profile=profile, callback=MagicMock())
                    dlg.show()

        name_row.set_text.assert_called_with("Work")
        server_row.set_text.assert_called_with("vpn.work.com")
        user_row.set_text.assert_called_with("alice")

    def test_callback_called_with_none_on_cancel(self) -> None:
        """Cancel button registered in show() calls callback(None) when clicked."""
        from snxui.ui import dialogs as dlg_mod

        callback = MagicMock()

        local_gtk = MagicMock(name="Gtk")
        local_adw = MagicMock(name="Adw")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import ProfileDialog
                    dlg = ProfileDialog(profile=None, callback=callback)
                    dlg.show()

        # cancel_btn.connect("clicked", lambda) is the FIRST connect() call on
        # Gtk.Button.return_value.  Invoking it must call callback(None, None).
        btn_mock = local_gtk.Button.return_value
        cancel_lambda = btn_mock.connect.call_args_list[0][0][1]
        cancel_lambda(None)  # simulate click

        callback.assert_called_once_with(None, None)

    def test_save_reads_widgets_before_dialog_close(self) -> None:
        """_on_save must read all widget values before dialog.close().

        dialog.close() schedules widget destruction.  Reading widget text
        after close() is fragile and implementation-dependent.  This test
        simulates destruction by invalidating all mock return values inside
        the dialog.close() side-effect; if any value is read after close
        the Profile constructor raises AttributeError (None.strip()) and
        the assertion fails.
        """
        from snxui.ui import dialogs as dlg_mod

        received: list = []

        local_gtk = MagicMock(name="Gtk")
        local_adw = MagicMock(name="Adw")

        name_row = MagicMock()
        server_row = MagicMock()
        user_row = MagicMock()
        ca_row = MagicMock()
        cert_row = MagicMock()
        port_row = MagicMock()
        save_row = MagicMock()
        method_row = MagicMock()
        totp_row = MagicMock()
        save_totp_row = MagicMock()

        # Initial (pre-close) widget values.
        name_row.get_text.return_value = "Work VPN"
        server_row.get_text.return_value = "vpn.work.com"
        user_row.get_text.return_value = "alice"
        ca_row.get_text.return_value = ""
        cert_row.get_text.return_value = ""
        port_row.get_value.return_value = 8443.0
        save_row.get_active.return_value = True
        method_row.get_selected.return_value = 0  # "none" — first 2FA method
        totp_row.get_text.return_value = ""
        save_totp_row.get_active.return_value = False

        dialog_mock = MagicMock()
        local_adw.Window.return_value = dialog_mock

        def _invalidate_widgets():
            """Simulate widget destruction by returning None after close."""
            name_row.get_text.return_value = None
            ca_row.get_text.return_value = None
            cert_row.get_text.return_value = None
            port_row.get_value.return_value = None
            save_row.get_active.return_value = None

        dialog_mock.close.side_effect = _invalidate_widgets

        local_adw.EntryRow.side_effect = [name_row, server_row, user_row, ca_row, cert_row]
        local_adw.SpinRow.new_with_range.return_value = port_row
        # SwitchRow is called twice: save_password and save_totp_secret.
        local_adw.SwitchRow.side_effect = [save_row, save_totp_row]
        local_adw.ComboRow.return_value = method_row
        local_adw.PasswordEntryRow.return_value = totp_row

        def _capture_callback(profile, totp_secret):
            received.append(profile)

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import ProfileDialog
                    ProfileDialog(profile=None, callback=_capture_callback).show()

        # _on_save is the SECOND connect() call on Gtk.Button.return_value.
        btn_mock = local_gtk.Button.return_value
        on_save = btn_mock.connect.call_args_list[1][0][1]
        on_save(None)  # simulate Save button click

        assert len(received) == 1, "callback must be called exactly once"
        p = received[0]
        assert p.name == "Work VPN"
        assert p.server == "vpn.work.com"
        assert p.username == "alice"
        assert p.ssl_port == 8443
        assert p.save_password is True

    def _setup_validation_test(
        self, server: str, username: str
    ) -> "tuple[object, object, MagicMock]":
        """Return (on_save_fn, error_label_mock, callback_mock) for _on_save validation tests.

        Mocks are wired with *server* and *username* as the get_text() return
        values so callers can exercise the validation branch.
        """
        from snxui.ui import dialogs as dlg_mod

        callback = MagicMock()
        local_gtk = MagicMock(name="Gtk")
        local_adw = MagicMock(name="Adw")

        name_row = MagicMock()
        server_row = MagicMock()
        user_row = MagicMock()
        ca_row = MagicMock()
        cert_row = MagicMock()
        port_row = MagicMock()
        save_row = MagicMock()

        name_row.get_text.return_value = "Work VPN"
        server_row.get_text.return_value = server
        user_row.get_text.return_value = username
        ca_row.get_text.return_value = "/etc/ssl/certs"
        cert_row.get_text.return_value = ""
        port_row.get_value.return_value = 443.0
        save_row.get_active.return_value = False

        local_adw.EntryRow.side_effect = [name_row, server_row, user_row, ca_row, cert_row]
        local_adw.SpinRow.new_with_range.return_value = port_row
        local_adw.SwitchRow.return_value = save_row

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import ProfileDialog
                    ProfileDialog(profile=None, callback=callback).show()

        # Save button is the SECOND Gtk.Button connect() call.
        btn_mock = local_gtk.Button.return_value
        on_save = btn_mock.connect.call_args_list[1][0][1]
        # Gtk.Label(label="") is called once → always the same mock instance.
        error_label = local_gtk.Label.return_value
        return on_save, error_label, callback

    def test_save_shows_error_label_when_server_missing(self) -> None:
        """Validation: empty server string → error label visible, callback not called."""
        on_save, error_label, callback = self._setup_validation_test(
            server="", username="alice"
        )
        on_save(None)

        error_label.set_label.assert_called_with("Server hostname is required.")
        error_label.set_visible.assert_called_with(True)
        callback.assert_not_called()

    def test_save_shows_error_label_when_username_missing(self) -> None:
        """Validation: empty username string → error label visible, callback not called."""
        on_save, error_label, callback = self._setup_validation_test(
            server="vpn.work.com", username=""
        )
        on_save(None)

        error_label.set_label.assert_called_with("Username is required.")
        error_label.set_visible.assert_called_with(True)
        callback.assert_not_called()


# ---------------------------------------------------------------------------
# AboutDialog
# ---------------------------------------------------------------------------


class TestAboutDialog:
    def test_show_creates_adw_about_dialog(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        local_adw = MagicMock(name="Adw")
        local_gtk = MagicMock(name="Gtk")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import AboutDialog
                    AboutDialog().show()

        local_adw.AboutDialog.assert_called_once()

    def test_show_sets_application_name(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        local_adw = MagicMock(name="Adw")
        local_gtk = MagicMock(name="Gtk")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import AboutDialog
                    AboutDialog().show(parent=MagicMock())

        call_kwargs = local_adw.AboutDialog.call_args[1]
        assert call_kwargs.get("application_name") == "SNX VPN"

    def test_show_sets_version(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        local_adw = MagicMock(name="Adw")
        local_gtk = MagicMock(name="Gtk")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import AboutDialog
                    AboutDialog().show()

        from snxui import __version__
        call_kwargs = local_adw.AboutDialog.call_args[1]
        assert call_kwargs.get("version") == __version__

    def test_show_sets_github_urls(self) -> None:
        """AboutDialog.show() passes correct website and issue_url to Adw.AboutDialog."""
        from snxui.ui import dialogs as dlg_mod

        local_adw = MagicMock(name="Adw")
        local_gtk = MagicMock(name="Gtk")

        with patch.object(dlg_mod, "_GTK_AVAILABLE", True):
            with patch.object(dlg_mod, "Adw", local_adw):
                with patch.object(dlg_mod, "Gtk", local_gtk):
                    from snxui.ui.dialogs import AboutDialog
                    AboutDialog().show()

        call_kwargs = local_adw.AboutDialog.call_args[1]
        assert call_kwargs.get("website") == "https://github.com/ikeniborn/snxui"
        assert call_kwargs.get("issue_url") == "https://github.com/ikeniborn/snxui/issues"

    def test_show_does_nothing_without_gtk(self, caplog: pytest.LogCaptureFixture) -> None:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", False):
            from snxui.ui.dialogs import AboutDialog
            # Must not raise.
            AboutDialog().show()


# ---------------------------------------------------------------------------
# Module-level graceful import (no GTK available)
# ---------------------------------------------------------------------------


class TestGracefulImport:
    def test_password_dialog_init_raises_import_error_without_gtk(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", False):
            with pytest.raises(ImportError, match="GTK4"):
                from snxui.ui.dialogs import PasswordDialog
                PasswordDialog(profile_name="x")

    def test_profile_dialog_init_raises_import_error_without_gtk(self) -> None:
        from snxui.ui import dialogs as dlg_mod

        with patch.object(dlg_mod, "_GTK_AVAILABLE", False):
            with pytest.raises(ImportError, match="GTK4"):
                from snxui.ui.dialogs import ProfileDialog
                ProfileDialog(profile=None, callback=MagicMock())
