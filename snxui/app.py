#!/usr/bin/env python3
"""SNX VPN GUI Client — Main Application Entry Point"""
import sys
import logging
import argparse
from pathlib import Path

from snxui import __version__, __app_id__

logger = logging.getLogger("snxui.app")


def setup_logging(debug: bool = False) -> None:
    """Configure logging to stderr and optionally a log file."""
    level = logging.DEBUG if debug else logging.INFO
    log_dir = Path.home() / ".local" / "share" / "snxui"
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / "snxui.log", delay=True))
    except OSError as exc:
        # Read-only filesystem or permission denied — degrade gracefully to
        # stderr-only logging.  Without this guard, the OSError propagates
        # through main() as an unhandled exception (raw Python traceback)
        # because main()'s except clause only catches ImportError.
        print(f"Warning: cannot create log directory {log_dir}: {exc}", file=sys.stderr)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=handlers,
    )


class SNXApplication:
    """Основной класс приложения.

    Координирует GTK Application, TrayManager, ProfileManager, SNXBackend.
    """

    def __init__(self, minimized: bool = False) -> None:
        self.minimized = minimized
        self._setup_backend()
        self._setup_gtk_app()

    def _setup_backend(self) -> None:
        from snxui.core import ProfileManager, CredentialStore, SNXBackend
        from snxui.system import TrayManager, AutostartManager

        self.profile_manager = ProfileManager()
        self.credential_store = CredentialStore()
        self.snx_backend = SNXBackend()
        self.tray_manager = TrayManager()
        self.autostart = AutostartManager()

    def _setup_gtk_app(self) -> None:
        import gi

        gi.require_version("Adw", "1")
        gi.require_version("Gtk", "4.0")
        from gi.repository import Adw, Gio

        self.app = Adw.Application(
            application_id=__app_id__,
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.app.connect("activate", self._on_activate)
        self.app.connect("shutdown", self._on_shutdown)

    def _on_activate(self, app: object) -> None:
        # Guard against duplicate activation: GTK4 re-emits "activate" on the
        # primary instance when the user launches a second copy of snxui
        # (unique application_id = single-instance mode).  Without this check
        # each call creates a new MainWindow, resulting in multiple visible
        # windows and duplicate GAction registrations.
        if getattr(self, "window", None) is not None:
            self.window.present()
            return

        from snxui.ui.main_window import MainWindow

        self.window = MainWindow(
            application=app,
            profile_manager=self.profile_manager,
            credential_store=self.credential_store,
            snx_backend=self.snx_backend,
            tray_manager=self.tray_manager,
            autostart=self.autostart,
        )
        if not self.minimized:
            self.window.present()

    def _on_shutdown(self, app: object) -> None:
        try:
            self.snx_backend.disconnect()
        except Exception:
            logger.warning("Error during disconnect on shutdown", exc_info=True)
        self.tray_manager.stop()

    def run(self) -> int:
        self.tray_manager.start()
        return self.app.run(None)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SNX VPN GUI Client")
    p.add_argument("--minimized", action="store_true", help="Start minimized to tray")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--version", action="version", version=f"snxui {__version__}")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(debug=args.debug)

    try:
        application = SNXApplication(minimized=args.minimized)
        sys.exit(application.run())
    except ImportError as e:
        print(f"Error: GTK4/Libadwaita not installed: {e}", file=sys.stderr)
        print("Install with: sudo apt install python3-gi gir1.2-adw-1", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
