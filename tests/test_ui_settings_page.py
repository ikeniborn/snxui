"""Tests for snxui.ui.settings_page.SettingsPage.

GTK4/Libadwaita are mocked so tests run without a display or GTK installation.

Covers:
- Static helpers _check_polkit() and _check_net_helper() (pure Python, no GTK)
- _on_autostart_toggled() re-entrancy guard
- _on_scheme_changed() out-of-bounds index protection
- minimize_to_tray property
- Graceful ImportError when GTK is absent
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch
import pytest


# ---------------------------------------------------------------------------
# Install GTK mocks before any snxui.ui import.
# Use setdefault so we don't collide with mocks from other test modules.
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
# Helper — build a SettingsPage with mocked GTK and AutostartManager
# ---------------------------------------------------------------------------


def _make_page(autostart_enabled: bool = False):
    """Return (page, mock_autostart, local_gtk, local_adw).

    All GTK constructors and shutil.which are mocked during construction so
    the test never touches the real filesystem.
    """
    from snxui.ui import settings_page as sp_mod

    local_gtk = MagicMock(name="Gtk")
    local_adw = MagicMock(name="Adw")
    mock_autostart = MagicMock()
    mock_autostart.is_enabled.return_value = autostart_enabled
    mock_shutil = MagicMock()
    mock_shutil.which.return_value = None

    with (
        patch.object(sp_mod, "_GTK_AVAILABLE", True),
        patch.object(sp_mod, "Adw", local_adw),
        patch.object(sp_mod, "Gtk", local_gtk),
        patch.object(sp_mod, "shutil", mock_shutil),
    ):
        from snxui.ui.settings_page import SettingsPage
        page = SettingsPage(autostart=mock_autostart)

    return page, mock_autostart, local_gtk, local_adw


# ---------------------------------------------------------------------------
# _check_net_helper() — pure Python static method
# ---------------------------------------------------------------------------


class TestCheckNetHelper:
    def test_returns_path_and_true_when_helper_exists(self, tmp_path) -> None:
        from snxui.ui.settings_page import SettingsPage

        helper = tmp_path / "snxui-net-helper"
        helper.touch()
        with patch("snxui.ui.settings_page.Path", return_value=helper):
            result_path, ok = SettingsPage._check_net_helper()

        assert ok is True
        assert "snxui-net-helper" in result_path

    def test_returns_not_found_and_false_when_missing(self, tmp_path) -> None:
        from snxui.ui.settings_page import SettingsPage

        missing = tmp_path / "snxui-net-helper"  # не создаём
        with patch("snxui.ui.settings_page.Path", return_value=missing):
            result_path, ok = SettingsPage._check_net_helper()

        assert ok is False
        assert "Not found" in result_path

    def test_subtitle_contains_reinstall_hint_when_missing(self, tmp_path) -> None:
        from snxui.ui.settings_page import SettingsPage

        missing = tmp_path / "snxui-net-helper"
        with patch("snxui.ui.settings_page.Path", return_value=missing):
            result_path, _ = SettingsPage._check_net_helper()

        assert "reinstall" in result_path.lower()


# ---------------------------------------------------------------------------
# _check_polkit() — pure Python static method
# ---------------------------------------------------------------------------


class TestCheckPolkit:
    def test_returns_available_with_path_when_pkexec_found(self) -> None:
        from snxui.ui.settings_page import SettingsPage

        with patch("snxui.ui.settings_page.shutil.which", return_value="/usr/bin/pkexec"):
            result = SettingsPage._check_polkit()

        assert "Available" in result
        assert "/usr/bin/pkexec" in result

    def test_returns_error_message_when_pkexec_missing(self) -> None:
        from snxui.ui.settings_page import SettingsPage

        with patch("snxui.ui.settings_page.shutil.which", return_value=None):
            result = SettingsPage._check_polkit()

        assert "not found" in result.lower()


# ---------------------------------------------------------------------------
# _on_autostart_toggled() — re-entrancy guard (non-trivial logic)
# ---------------------------------------------------------------------------


class TestOnAutostartToggled:
    """The re-entrancy guard prevents recursive toggle when set_active() is
    called inside the handler to revert a failed enable/disable operation."""

    def test_enable_success_does_not_revert_switch(self) -> None:
        """enable() → True: switch must NOT be reverted."""
        page, mock_autostart, _, _ = _make_page()
        mock_autostart.enable.return_value = True
        mock_row = MagicMock()
        mock_row.get_active.return_value = True

        page._on_autostart_toggled(mock_row, None)

        mock_autostart.enable.assert_called_once()
        mock_row.set_active.assert_not_called()

    def test_enable_failure_reverts_switch_to_false(self) -> None:
        """enable() → False: switch must be reverted to False."""
        page, mock_autostart, _, _ = _make_page()
        mock_autostart.enable.return_value = False
        mock_row = MagicMock()
        mock_row.get_active.return_value = True  # user turned it on

        page._on_autostart_toggled(mock_row, None)

        mock_row.set_active.assert_called_once_with(False)

    def test_disable_success_does_not_revert_switch(self) -> None:
        """disable() → True: switch must NOT be reverted."""
        page, mock_autostart, _, _ = _make_page()
        mock_autostart.disable.return_value = True
        mock_row = MagicMock()
        mock_row.get_active.return_value = False  # user turned it off

        page._on_autostart_toggled(mock_row, None)

        mock_autostart.disable.assert_called_once()
        mock_row.set_active.assert_not_called()

    def test_disable_failure_reverts_switch_to_true(self) -> None:
        """disable() → False: switch must be reverted to True."""
        page, mock_autostart, _, _ = _make_page()
        mock_autostart.disable.return_value = False
        mock_row = MagicMock()
        mock_row.get_active.return_value = False  # user turned it off

        page._on_autostart_toggled(mock_row, None)

        mock_row.set_active.assert_called_once_with(True)

    def test_reentrancy_guard_returns_immediately(self) -> None:
        """While _autostart_reverting is True, the handler returns immediately.

        GTK4 emits notify::active synchronously from set_active(), so reverting
        the switch inside the handler would immediately re-invoke it.  The guard
        prevents that second call from attempting the opposite operation.
        """
        page, mock_autostart, _, _ = _make_page()
        page._autostart_reverting = True
        mock_row = MagicMock()
        mock_row.get_active.return_value = True

        page._on_autostart_toggled(mock_row, None)

        mock_autostart.enable.assert_not_called()
        mock_autostart.disable.assert_not_called()
        mock_row.set_active.assert_not_called()

    def test_reverting_flag_cleared_after_successful_revert(self) -> None:
        """_autostart_reverting must be False after the handler exits,
        even when enable() fails."""
        page, mock_autostart, _, _ = _make_page()
        mock_autostart.enable.return_value = False
        mock_row = MagicMock()
        mock_row.get_active.return_value = True

        page._on_autostart_toggled(mock_row, None)

        # Flag must be cleared so subsequent real toggles work.
        assert not getattr(page, "_autostart_reverting", False)


# ---------------------------------------------------------------------------
# _on_scheme_changed() — index boundary check
# ---------------------------------------------------------------------------


class TestOnSchemeChanged:
    def test_valid_index_applies_scheme(self) -> None:
        """A valid index (0-2) calls StyleManager.set_color_scheme."""
        page, _, _, _ = _make_page()
        mock_row = MagicMock()
        mock_row.get_selected.return_value = 1  # Light

        import snxui.ui.settings_page as sp_mod
        local_adw = MagicMock(name="Adw")
        mock_sm = MagicMock()
        local_adw.StyleManager.get_default.return_value = mock_sm
        # getattr(local_adw.ColorScheme, "COLOR_SCHEME_FORCE_LIGHT") → MagicMock (not None)

        with patch.object(sp_mod, "Adw", local_adw):
            page._on_scheme_changed(mock_row, None)

        mock_sm.set_color_scheme.assert_called_once()

    def test_out_of_bounds_index_returns_early(self) -> None:
        """An index >= len(_ADW_COLOR_SCHEMES) must return without touching
        the StyleManager — the guard ``if scheme_name is None: return`` is the
        protection against a malformed dropdown selection.
        """
        page, _, _, _ = _make_page()
        mock_row = MagicMock()
        mock_row.get_selected.return_value = 99  # far out of bounds

        import snxui.ui.settings_page as sp_mod
        local_adw = MagicMock(name="Adw")
        local_adw.StyleManager.get_default.side_effect = AssertionError(
            "StyleManager must not be accessed for an out-of-bounds index"
        )

        with patch.object(sp_mod, "Adw", local_adw):
            page._on_scheme_changed(mock_row, None)  # must not raise

    def test_exception_in_set_color_scheme_does_not_propagate(self) -> None:
        """An exception from the GTK API must be caught and logged, not raised."""
        page, _, _, _ = _make_page()
        mock_row = MagicMock()
        mock_row.get_selected.return_value = 2  # Dark

        import snxui.ui.settings_page as sp_mod
        local_adw = MagicMock(name="Adw")
        mock_sm = MagicMock()
        mock_sm.set_color_scheme.side_effect = RuntimeError("no style manager")
        local_adw.StyleManager.get_default.return_value = mock_sm

        with patch.object(sp_mod, "Adw", local_adw):
            page._on_scheme_changed(mock_row, None)  # must not raise


# ---------------------------------------------------------------------------
# minimize_to_tray property
# ---------------------------------------------------------------------------


class TestMinimizeToTray:
    def test_returns_true_when_tray_row_is_active(self) -> None:
        page, _, _, _ = _make_page()
        page._tray_row.get_active.return_value = True
        assert page.minimize_to_tray is True

    def test_returns_false_when_tray_row_is_inactive(self) -> None:
        page, _, _, _ = _make_page()
        page._tray_row.get_active.return_value = False
        assert page.minimize_to_tray is False


# ---------------------------------------------------------------------------
# Graceful import guard
# ---------------------------------------------------------------------------


class TestGracefulImport:
    def test_init_raises_import_error_without_gtk(self) -> None:
        from snxui.ui import settings_page as sp_mod

        with patch.object(sp_mod, "_GTK_AVAILABLE", False):
            with pytest.raises(ImportError, match="GTK4"):
                from snxui.ui.settings_page import SettingsPage
                SettingsPage(autostart=MagicMock())
