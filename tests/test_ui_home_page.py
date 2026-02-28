"""Tests for snxui.ui.home_page.HomePage — status updates, connect/disconnect logic.

All GTK4/Libadwaita widgets are mocked so tests run without a display.
"""

from __future__ import annotations

import sys
import threading
from unittest.mock import MagicMock, patch, PropertyMock, call
import pytest


# ---------------------------------------------------------------------------
# Mock GTK before importing any UI module.
# ---------------------------------------------------------------------------

def _setup_gtk_mocks() -> None:
    """Install GTK mock modules into sys.modules if not already present."""
    gtk_mock = MagicMock()
    adw_mock = MagicMock()
    glib_mock = MagicMock()
    gi_mock = MagicMock()

    # GLib.idle_add must call the function synchronously for tests.
    def _idle_add(func, *args):
        func(*args)
        return False

    glib_mock.idle_add = _idle_add
    glib_mock.SOURCE_REMOVE = False

    sys.modules.setdefault("gi", gi_mock)
    sys.modules.setdefault("gi.repository", gtk_mock)
    sys.modules.setdefault("gi.repository.Gtk", gtk_mock)
    sys.modules.setdefault("gi.repository.Adw", adw_mock)
    sys.modules.setdefault("gi.repository.GLib", glib_mock)
    sys.modules.setdefault("gi.repository.Gio", MagicMock())


_setup_gtk_mocks()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_status(state_name: str, ip: str = "", error: str = "") -> object:
    """Create a ConnectionStatus-like mock."""
    from snxui.core.types import ConnectionState, ConnectionStatus, Profile

    state_map = {
        "CONNECTED": ConnectionState.CONNECTED,
        "CONNECTING": ConnectionState.CONNECTING,
        "DISCONNECTED": ConnectionState.DISCONNECTED,
        "DISCONNECTING": ConnectionState.DISCONNECTING,
        "ERROR": ConnectionState.ERROR,
    }
    profile = Profile(
        name="TestProfile",
        server="vpn.example.com",
        username="alice",
    )
    return ConnectionStatus(
        state=state_map[state_name],
        profile=profile,
        ip_address=ip or None,
        error_message=error or None,
    )


def _make_home_page() -> object:
    """Build a HomePage with mocked GTK and backend dependencies."""
    from snxui.ui import home_page as hp_mod

    # Patch _GTK_AVAILABLE so the constructor proceeds.
    with patch.object(hp_mod, "_GTK_AVAILABLE", True):
        # Patch the GTK widget constructors.
        with (
            patch.object(hp_mod, "Adw", MagicMock()),
            patch.object(hp_mod, "Gtk", MagicMock()),
            patch.object(hp_mod, "GLib", hp_mod.GLib if hasattr(hp_mod, "GLib") else MagicMock()),
        ):
            mock_pm = MagicMock()
            mock_pm.list_all.return_value = []
            mock_cs = MagicMock()
            mock_be = MagicMock()
            mock_be.get_status.return_value = _make_status("DISCONNECTED")

            from snxui.ui.home_page import HomePage

            page = HomePage(
                profile_manager=mock_pm,
                credential_store=mock_cs,
                snx_backend=mock_be,
            )
    return page, mock_pm, mock_cs, mock_be


# ---------------------------------------------------------------------------
# _on_connect_clicked routing tests
# ---------------------------------------------------------------------------


class TestHomePageOnConnectClicked:
    """Verify the Connect/Disconnect button click handler routes correctly.

    _on_connect_clicked() calls get_status() to decide between _do_connect()
    and _do_disconnect().  All three branches must be exercised:
      1. CONNECTED  → _do_disconnect()
      2. not-CONNECTED → _do_connect()
      3. get_status() raises → _do_connect() (safe default)

    None of the existing tests cover this routing because they all call
    _do_connect() / _do_disconnect() directly.
    """

    def test_connected_state_routes_to_disconnect(self) -> None:
        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.get_status.return_value = _make_status("CONNECTED", ip="10.0.0.1")

        with patch.object(page, "_do_disconnect") as mock_disc, \
             patch.object(page, "_do_connect") as mock_conn:
            page._on_connect_clicked(None)

        mock_disc.assert_called_once()
        mock_conn.assert_not_called()

    def test_disconnected_state_routes_to_connect(self) -> None:
        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.get_status.return_value = _make_status("DISCONNECTED")

        with patch.object(page, "_do_disconnect") as mock_disc, \
             patch.object(page, "_do_connect") as mock_conn:
            page._on_connect_clicked(None)

        mock_conn.assert_called_once()
        mock_disc.assert_not_called()

    def test_get_status_exception_routes_to_connect(self) -> None:
        """When get_status() raises, the handler must default to _do_connect()."""
        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.get_status.side_effect = RuntimeError("backend unavailable")

        with patch.object(page, "_do_disconnect") as mock_disc, \
             patch.object(page, "_do_connect") as mock_conn:
            page._on_connect_clicked(None)

        mock_conn.assert_called_once()
        mock_disc.assert_not_called()


# ---------------------------------------------------------------------------
# Status update tests
# ---------------------------------------------------------------------------


class TestHomePageStatusUpdates:
    """Verify that _apply_status mutates widget state correctly."""

    def setup_method(self) -> None:
        from snxui.ui import home_page as hp_mod

        self._hp_mod = hp_mod
        # Patch at module level so _apply_status can access the mock GLib.
        self._glib_mock = MagicMock()
        self._glib_mock.idle_add = lambda fn, *args: fn(*args)
        self._glib_mock.SOURCE_REMOVE = False
        self._patch_glib = patch.object(hp_mod, "GLib", self._glib_mock)
        self._patch_glib.start()

    def teardown_method(self) -> None:
        self._patch_glib.stop()

    def _page_with_status(self, state_name: str, ip: str = "", error: str = "") -> object:
        page, _pm, _cs, _be = _make_home_page()
        status = _make_status(state_name, ip=ip, error=error)
        # _apply_status is tested directly (not via idle_add indirection).
        page._apply_status(status)
        return page

    def test_connected_state_sets_disconnect_label(self) -> None:
        page = self._page_with_status("CONNECTED", ip="10.0.0.1")
        page._connect_btn.set_label.assert_called_with("Disconnect")

    def test_connected_state_shows_info_label(self) -> None:
        page = self._page_with_status("CONNECTED", ip="10.0.0.1")
        page._info_label.set_visible.assert_called_with(True)

    def test_disconnected_state_sets_connect_label(self) -> None:
        page = self._page_with_status("DISCONNECTED")
        page._connect_btn.set_label.assert_called_with("Connect")

    def test_disconnected_state_hides_info_label(self) -> None:
        page = self._page_with_status("DISCONNECTED")
        page._info_label.set_visible.assert_called_with(False)

    def test_connecting_state_shows_spinner(self) -> None:
        page = self._page_with_status("CONNECTING")
        page._spinner.set_visible.assert_called_with(True)
        page._spinner.set_spinning.assert_called_with(True)

    def test_connecting_state_disables_button(self) -> None:
        page = self._page_with_status("CONNECTING")
        page._connect_btn.set_sensitive.assert_called_with(False)

    def test_disconnecting_state_disables_button(self) -> None:
        page = self._page_with_status("DISCONNECTING")
        page._connect_btn.set_sensitive.assert_called_with(False)

    def test_disconnecting_state_shows_spinner(self) -> None:
        page = self._page_with_status("DISCONNECTING")
        page._spinner.set_visible.assert_called_with(True)
        page._spinner.set_spinning.assert_called_with(True)

    def test_disconnecting_state_hides_info_label(self) -> None:
        """_apply_disconnecting must hide the info label.

        Without this, the IP address stays visible while the tunnel is being
        torn down — an inconsistency with the CONNECTING and DISCONNECTED
        states which both call self._info_label.set_visible(False).
        """
        page = self._page_with_status("DISCONNECTING")
        page._info_label.set_visible.assert_called_with(False)

    def test_error_state_shows_error_message(self) -> None:
        page = self._page_with_status("ERROR", error="Auth failed")
        page._status_label.set_label.assert_called_with("Error: Auth failed")

    def test_error_state_re_enables_button(self) -> None:
        page = self._page_with_status("ERROR", error="something")
        page._connect_btn.set_sensitive.assert_called_with(True)

    def test_update_status_calls_glib_idle_add(self) -> None:
        page, _pm, _cs, _be = _make_home_page()
        status = _make_status("CONNECTED")

        # Replace idle_add with a tracking mock for this single test.
        call_tracker = MagicMock(side_effect=lambda fn, *args: fn(*args))
        with patch.object(self._glib_mock, "idle_add", call_tracker):
            # Re-patch the module's GLib reference.
            from snxui.ui import home_page as hp_mod
            with patch.object(hp_mod, "GLib", self._glib_mock):
                self._glib_mock.idle_add = call_tracker
                page.update_status(status)

        assert call_tracker.call_count >= 1


# ---------------------------------------------------------------------------
# Profile selection tests
# ---------------------------------------------------------------------------


class TestHomePageProfiles:
    def test_refresh_profiles_populates_model(self) -> None:
        from snxui.core.types import Profile

        page, mock_pm, _cs, _be = _make_home_page()
        profiles = [
            Profile(name="Work", server="vpn.work.com", username="alice"),
            Profile(name="Home", server="vpn.home.com", username="bob"),
        ]
        mock_pm.list_all.return_value = profiles
        page._refresh_profiles()

        assert len(page._profiles) == 2
        assert page._profiles[0].name == "Work"

    def test_selected_profile_returns_none_when_no_profiles(self) -> None:
        page, mock_pm, _cs, _be = _make_home_page()
        mock_pm.list_all.return_value = []
        page._refresh_profiles()

        # Dropdown selected index returns 0 (MagicMock default).
        # With no real profiles the method should return None.
        result = page._selected_profile()
        assert result is None

    def test_selected_profile_returns_correct_profile(self) -> None:
        from snxui.core.types import Profile

        page, mock_pm, _cs, _be = _make_home_page()
        profile = Profile(name="Work", server="vpn.work.com", username="alice")
        page._profiles = [profile]
        page._profile_dropdown.get_selected.return_value = 0

        result = page._selected_profile()
        assert result is profile


# ---------------------------------------------------------------------------
# Connect / Disconnect button tests
# ---------------------------------------------------------------------------


class TestHomePageConnectDisconnect:
    def test_connect_with_no_profile_shows_no_profile_message(self) -> None:
        page, mock_pm, _cs, _be = _make_home_page()
        mock_pm.list_all.return_value = []
        page._refresh_profiles()
        page._profiles = []

        with patch.object(page, "_show_no_profile_toast") as mock_toast:
            page._do_connect()
        mock_toast.assert_called_once()

    def test_connect_uses_saved_password_from_keyring(self) -> None:
        from snxui.core.types import Profile

        page, mock_pm, mock_cs, mock_be = _make_home_page()
        profile = Profile(
            name="Work", server="vpn.work.com", username="alice", save_password=True
        )
        page._profiles = [profile]
        page._profile_dropdown.get_selected.return_value = 0
        mock_cs.get_password.return_value = "secret123"

        with patch.object(page, "_start_connect") as mock_start:
            page._do_connect()

        mock_cs.get_password.assert_called_once_with(profile.id)
        mock_start.assert_called_once_with(profile, "secret123")

    def test_connect_shows_password_dialog_when_no_saved_password(self) -> None:
        from snxui.core.types import Profile

        page, mock_pm, mock_cs, mock_be = _make_home_page()
        profile = Profile(
            name="Work", server="vpn.work.com", username="alice", save_password=False
        )
        page._profiles = [profile]
        page._profile_dropdown.get_selected.return_value = 0
        # Simulate no password stored in keyring (get_password returns None).
        # _do_connect() now always queries the keyring regardless of
        # profile.save_password, so the mock must explicitly return None to
        # trigger the "no saved password → show dialog" path.
        mock_cs.get_password.return_value = None

        # PasswordDialog is imported at call time inside _ask_password_then_connect
        # with "from snxui.ui.dialogs import PasswordDialog".
        # We track the call by replacing _ask_password_then_connect directly.
        called_with = []

        def _mock_ask(prof):
            called_with.append(prof)

        original = page._ask_password_then_connect
        page._ask_password_then_connect = _mock_ask
        page._do_connect()
        page._ask_password_then_connect = original

        assert called_with == [profile]

    def test_disconnect_triggers_backend_in_thread(self) -> None:
        """_do_disconnect runs backend.disconnect in a background thread."""
        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.disconnect.return_value = True

        # Run in the test thread by joining the spawned thread.
        finished = threading.Event()
        original_thread = threading.Thread

        def capturing_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            t.daemon = True

            original_start = t.start

            def start_and_signal():
                original_start()
                # Allow a moment for the thread to finish.
                t.join(timeout=2)
                finished.set()

            t.start = start_and_signal
            return t

        with patch("snxui.ui.home_page.threading.Thread", side_effect=capturing_thread):
            page._do_disconnect()

        finished.wait(timeout=3)
        mock_be.disconnect.assert_called_once()

    def test_disconnect_failure_does_not_call_refresh_status(self) -> None:
        """When disconnect() returns False, _refresh_status must NOT be called.

        Calling _refresh_status() would invoke get_status() → check tunsnx →
        if still exists → override ERROR with CONNECTED, hiding the error
        message from the user.
        """
        from snxui.core.types import ConnectionStatus, ConnectionState

        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.disconnect.return_value = False
        mock_be.get_cached_status.return_value = ConnectionStatus(
            state=ConnectionState.ERROR,
            error_message="Disconnect may not have succeeded",
        )

        finished = threading.Event()
        original_thread = threading.Thread

        def capturing_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            t.daemon = True

            original_start = t.start

            def start_and_signal():
                original_start()
                t.join(timeout=2)
                finished.set()

            t.start = start_and_signal
            return t

        refresh_calls: list[int] = []

        with patch.object(page, "_refresh_status", side_effect=lambda: refresh_calls.append(1)), \
             patch("snxui.ui.home_page.threading.Thread", side_effect=capturing_thread):
            page._do_disconnect()

        finished.wait(timeout=3)
        assert refresh_calls == [], (
            "_refresh_status must not be called when disconnect() fails; "
            "it would override ERROR status with CONNECTED (tunsnx still up)"
        )

    def test_disconnect_exception_calls_refresh_status(self) -> None:
        """When disconnect() raises an exception, _refresh_status must be called.

        The exception path (FileNotFoundError / RuntimeError from pexpect missing)
        cannot read cached status because disconnect() set no internal status —
        it raised before any _update_status() call.  The only safe recovery is
        to call _refresh_status() which probes get_status() to show actual state.

        This is the *opposite* of the success=False path (which must NOT call
        _refresh_status to avoid overriding ERROR with CONNECTED).
        """
        from snxui.ui import home_page as hp_mod

        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.disconnect.side_effect = RuntimeError("snx binary missing")

        finished = threading.Event()
        original_thread = threading.Thread

        def capturing_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            t.daemon = True

            original_start = t.start

            def start_and_signal():
                original_start()
                t.join(timeout=2)
                finished.set()

            t.start = start_and_signal
            return t

        refresh_calls: list[int] = []
        page._refresh_status = lambda: refresh_calls.append(1)

        original_glib = hp_mod.GLib
        glib_sync = MagicMock()
        glib_sync.idle_add = lambda fn, *args: fn(*args)
        hp_mod.GLib = glib_sync
        try:
            with patch("snxui.ui.home_page.threading.Thread", side_effect=capturing_thread):
                page._do_disconnect()
            finished.wait(timeout=3)
        finally:
            hp_mod.GLib = original_glib
            try:
                del page._refresh_status
            except AttributeError:
                pass

        assert refresh_calls == [1], (
            "_refresh_status must be called exactly once when disconnect() raises; "
            "it is the only way to sync UI state when disconnect() set no status."
        )

    def test_disconnect_failure_dispatches_cached_error_to_ui(self) -> None:
        """When disconnect() fails, the ERROR status must be shown in the UI.

        Previously the UI was left stuck at 'Disconnecting...' because
        _do_disconnect() called neither _refresh_status() nor any other
        UI update when disconnect() returned False.  The fix reads the
        cached backend status via get_cached_status() and dispatches it.

        Both hp_mod.GLib and page.update_status are replaced via direct
        assignment (not a context-manager patch) so the replacements remain
        active inside the background thread.  patch.object context managers
        are reverted as soon as their with-block exits, before the daemon
        thread has had a chance to run.
        """
        from snxui.core.types import ConnectionStatus, ConnectionState
        from snxui.ui import home_page as hp_mod

        page, _pm, _cs, mock_be = _make_home_page()
        mock_be.disconnect.return_value = False
        error_status = ConnectionStatus(
            state=ConnectionState.ERROR,
            error_message="Disconnect may not have succeeded",
        )
        mock_be.get_cached_status.return_value = error_status

        finished = threading.Event()
        original_thread = threading.Thread

        def capturing_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            t.daemon = True

            original_start = t.start

            def start_and_signal():
                original_start()
                t.join(timeout=2)
                finished.set()

            t.start = start_and_signal
            return t

        # Replace update_status and GLib directly so the changes persist across
        # the background thread's lifetime.
        page.update_status = MagicMock()
        original_glib = hp_mod.GLib
        glib_sync = MagicMock()
        glib_sync.idle_add = lambda fn, *args: fn(*args)
        hp_mod.GLib = glib_sync
        try:
            with patch("snxui.ui.home_page.threading.Thread", side_effect=capturing_thread):
                page._do_disconnect()
            finished.wait(timeout=3)
        finally:
            hp_mod.GLib = original_glib

        mock_be.get_cached_status.assert_called_once()
        page.update_status.assert_called_once()
        assert page.update_status.call_args[0][0].state == ConnectionState.ERROR
