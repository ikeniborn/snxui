"""Tests for snxui.app — argument parsing, logging setup, SNXApplication init.

GTK4/Libadwaita are mocked so these tests run without a display or GTK
installation.
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import pytest


# ---------------------------------------------------------------------------
# Mock GTK before any snxui.app import so conditional imports succeed.
# ---------------------------------------------------------------------------

_gtk_mock = MagicMock()
_adw_mock = MagicMock()
_gio_mock = MagicMock()
_gi_mock = MagicMock()

sys.modules.setdefault("gi", _gi_mock)
sys.modules.setdefault("gi.repository", _gtk_mock)
sys.modules.setdefault("gi.repository.Gtk", _gtk_mock)
sys.modules.setdefault("gi.repository.Adw", _adw_mock)
sys.modules.setdefault("gi.repository.GLib", _gtk_mock)
sys.modules.setdefault("gi.repository.Gio", _gio_mock)


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------


class TestParseArgs:
    def test_defaults(self) -> None:
        from snxui.app import parse_args

        with patch("sys.argv", ["snxui"]):
            args = parse_args()
        assert args.minimized is False
        assert args.debug is False

    def test_minimized_flag(self) -> None:
        from snxui.app import parse_args

        with patch("sys.argv", ["snxui", "--minimized"]):
            args = parse_args()
        assert args.minimized is True

    def test_debug_flag(self) -> None:
        from snxui.app import parse_args

        with patch("sys.argv", ["snxui", "--debug"]):
            args = parse_args()
        assert args.debug is True

    def test_version_exits(self) -> None:
        from snxui.app import parse_args

        with patch("sys.argv", ["snxui", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                parse_args()
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# setup_logging
# ---------------------------------------------------------------------------


class TestSetupLogging:
    def test_info_level_by_default(self) -> None:
        from snxui.app import setup_logging

        with patch("logging.basicConfig") as mock_basic:
            setup_logging(debug=False)
        mock_basic.assert_called_once()
        call_kwargs = mock_basic.call_args[1]
        assert call_kwargs["level"] == logging.INFO

    def test_debug_level_when_requested(self) -> None:
        from snxui.app import setup_logging

        with patch("logging.basicConfig") as mock_basic:
            setup_logging(debug=True)
        mock_basic.assert_called_once()
        call_kwargs = mock_basic.call_args[1]
        assert call_kwargs["level"] == logging.DEBUG

    def test_handlers_include_file_handler(self) -> None:
        from snxui.app import setup_logging

        with patch("logging.basicConfig") as mock_basic:
            setup_logging()
        call_kwargs = mock_basic.call_args[1]
        handler_types = [type(h).__name__ for h in call_kwargs["handlers"]]
        assert "FileHandler" in handler_types

    def test_handlers_include_stream_handler(self) -> None:
        from snxui.app import setup_logging

        with patch("logging.basicConfig") as mock_basic:
            setup_logging()
        call_kwargs = mock_basic.call_args[1]
        handler_types = [type(h).__name__ for h in call_kwargs["handlers"]]
        assert "StreamHandler" in handler_types

    def test_setup_logging_survives_mkdir_failure(self) -> None:
        """setup_logging must not raise if the log directory cannot be created.

        Without OSError handling, a read-only filesystem or missing parent
        directory propagates through main() as an unhandled exception (raw
        Python traceback), because main()'s except clause only catches
        ImportError.
        """
        from snxui.app import setup_logging

        with patch("logging.basicConfig"), \
             patch("pathlib.Path.mkdir", side_effect=OSError("read-only filesystem")):
            # Must not raise.
            setup_logging()


# ---------------------------------------------------------------------------
# SNXApplication
# ---------------------------------------------------------------------------


class TestSNXApplication:
    """Test SNXApplication init with fully mocked GTK and backends."""

    def _make_app(self, minimized: bool = False) -> object:
        """Build an SNXApplication instance with mocked dependencies."""
        from snxui.app import SNXApplication

        mock_pm = MagicMock(name="ProfileManager")
        mock_cs = MagicMock(name="CredentialStore")
        mock_be = MagicMock(name="SNXBackend")
        mock_tm = MagicMock(name="TrayManager")
        mock_as = MagicMock(name="AutostartManager")
        mock_adw_app = MagicMock(name="Adw.Application")

        with (
            patch("snxui.core.ProfileManager", return_value=mock_pm),
            patch("snxui.core.CredentialStore", return_value=mock_cs),
            patch("snxui.core.SNXBackend", return_value=mock_be),
            patch("snxui.system.TrayManager", return_value=mock_tm),
            patch("snxui.system.AutostartManager", return_value=mock_as),
            patch("snxui.app.SNXApplication._setup_gtk_app"),
        ):
            app = SNXApplication(minimized=minimized)
            app.app = mock_adw_app

        app.profile_manager = mock_pm
        app.credential_store = mock_cs
        app.snx_backend = mock_be
        app.tray_manager = mock_tm
        app.autostart = mock_as
        return app

    def test_init_creates_backend_components(self) -> None:
        from snxui.app import SNXApplication

        with (
            patch("snxui.core.ProfileManager") as mock_pm_cls,
            patch("snxui.core.CredentialStore") as mock_cs_cls,
            patch("snxui.core.SNXBackend") as mock_be_cls,
            patch("snxui.system.TrayManager") as mock_tm_cls,
            patch("snxui.system.AutostartManager") as mock_as_cls,
            patch("snxui.app.SNXApplication._setup_gtk_app"),
        ):
            app = SNXApplication(minimized=False)

        mock_pm_cls.assert_called_once()
        mock_cs_cls.assert_called_once()
        mock_be_cls.assert_called_once()
        mock_tm_cls.assert_called_once()
        mock_as_cls.assert_called_once()

    def test_minimized_flag_stored(self) -> None:
        app = self._make_app(minimized=True)
        assert app.minimized is True

    def test_not_minimized_by_default(self) -> None:
        app = self._make_app(minimized=False)
        assert app.minimized is False

    def test_run_starts_tray_and_gtk(self) -> None:
        app = self._make_app()
        app.app.run = MagicMock(return_value=0)

        result = app.run()

        app.tray_manager.start.assert_called_once()
        app.app.run.assert_called_once_with(None)
        assert result == 0

    def test_on_shutdown_calls_disconnect_and_stop(self) -> None:
        app = self._make_app()
        app._on_shutdown(app.app)
        app.snx_backend.disconnect.assert_called_once()
        app.tray_manager.stop.assert_called_once()

    def test_on_shutdown_handles_disconnect_exception(self) -> None:
        """Disconnect error on shutdown must not propagate."""
        app = self._make_app()
        app.snx_backend.disconnect.side_effect = RuntimeError("snx gone")
        # Should NOT raise.
        app._on_shutdown(app.app)
        app.tray_manager.stop.assert_called_once()

    def test_on_activate_presents_window_when_not_minimized(self) -> None:
        app = self._make_app(minimized=False)
        mock_window = MagicMock(name="MainWindow")

        # _on_activate imports MainWindow from snxui.ui.main_window at call time.
        with patch("snxui.ui.main_window.MainWindow", return_value=mock_window):
            app._on_activate(app.app)

        mock_window.present.assert_called_once()

    def test_on_activate_does_not_present_when_minimized(self) -> None:
        app = self._make_app(minimized=True)
        mock_window = MagicMock(name="MainWindow")

        with patch("snxui.ui.main_window.MainWindow", return_value=mock_window):
            app._on_activate(app.app)

        mock_window.present.assert_not_called()

    def test_on_activate_second_call_presents_existing_window(self) -> None:
        """Second activate signal must present the existing window, not create a new one.

        With Gio.ApplicationFlags.DEFAULT_FLAGS (unique application), when the
        user launches snxui a second time the primary instance receives a new
        "activate" signal.  Without a guard this creates a second MainWindow
        and a second visible window on screen.
        """
        app = self._make_app(minimized=False)
        mock_window = MagicMock(name="MainWindow")

        with patch("snxui.ui.main_window.MainWindow", return_value=mock_window) as MockMW:
            app._on_activate(app.app)   # first activation — creates window
            app._on_activate(app.app)   # second activation — must not recreate

        assert MockMW.call_count == 1, "MainWindow must be instantiated only once"


# ---------------------------------------------------------------------------
# main() integration
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_exits_on_import_error(self, capsys: pytest.CaptureFixture) -> None:
        from snxui import app as app_mod

        with (
            patch("sys.argv", ["snxui"]),
            patch.object(app_mod, "SNXApplication", side_effect=ImportError("no GTK")),
            pytest.raises(SystemExit) as exc_info,
        ):
            app_mod.main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "GTK4/Libadwaita not installed" in captured.err
