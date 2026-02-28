"""Main application window — Adw.ApplicationWindow with a ViewStack.

Layout:
    Adw.ApplicationWindow
      header_bar: Adw.HeaderBar
        title: Adw.WindowTitle ("SNX VPN")
        end: menu button (About, Quit)
      content:
        Adw.ViewStack (three pages)
          "home"     → HomePage
          "profiles" → ProfilesPage
          "settings" → SettingsPage
      bottom: Adw.ViewSwitcherBar
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from snxui.core import ProfileManager, CredentialStore, SNXBackend
    from snxui.system import TrayManager, AutostartManager

logger = logging.getLogger(__name__)

try:
    import gi

    gi.require_version("Adw", "1")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Adw, Gtk, Gio

    _GTK_AVAILABLE = True
except (ImportError, ValueError):
    Adw = None  # type: ignore[assignment]
    Gtk = None  # type: ignore[assignment]
    Gio = None  # type: ignore[assignment]
    _GTK_AVAILABLE = False
    logger.warning("GTK4/Libadwaita not available — MainWindow will not function.")


def _build_menu() -> "Gio.Menu":
    """Create the application menu (About, Quit)."""
    menu = Gio.Menu()
    menu.append("About SNX VPN", "app.about")
    menu.append("Quit", "app.quit")
    return menu


class MainWindow:
    """GTK4 + Libadwaita main application window.

    Args:
        application: The :class:`Adw.Application` instance.
        profile_manager: Core profile CRUD service.
        credential_store: Keyring credential service.
        snx_backend: VPN connection backend.
        tray_manager: System tray manager.
        autostart: Autostart manager.
    """

    DEFAULT_WIDTH = 480
    DEFAULT_HEIGHT = 600

    def __init__(
        self,
        *,
        application: object,
        profile_manager: "ProfileManager",
        credential_store: "CredentialStore",
        snx_backend: "SNXBackend",
        tray_manager: "TrayManager",
        autostart: "AutostartManager",
    ) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for MainWindow.")

        self._app = application
        self._profile_manager = profile_manager
        self._credential_store = credential_store
        self._snx_backend = snx_backend
        self._tray_manager = tray_manager
        self._autostart = autostart

        self._build_window()
        self._register_actions()
        self._connect_tray()

    # ------------------------------------------------------------------
    # Window construction
    # ------------------------------------------------------------------

    def _build_window(self) -> None:
        """Construct the Adw.ApplicationWindow hierarchy."""
        self._win = Adw.ApplicationWindow(application=self._app)
        self._win.set_default_size(self.DEFAULT_WIDTH, self.DEFAULT_HEIGHT)
        self._win.set_title("SNX VPN")

        # Intercept the close button to hide in tray instead of quitting.
        self._win.connect("close-request", self._on_close_request)

        # ToolbarView wraps HeaderBar + content + bottom bar.
        toolbar_view = Adw.ToolbarView()

        # Header bar.
        header_bar = Adw.HeaderBar()
        title_widget = Adw.WindowTitle(title="SNX VPN", subtitle="")
        header_bar.set_title_widget(title_widget)

        # Menu button.
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_menu_model(_build_menu())
        header_bar.pack_end(menu_button)
        toolbar_view.add_top_bar(header_bar)

        # ViewStack.
        self._stack = Adw.ViewStack()
        self._build_pages()
        toolbar_view.set_content(self._stack)

        # ViewSwitcherBar at the bottom.
        switcher_bar = Adw.ViewSwitcherBar()
        switcher_bar.set_stack(self._stack)
        switcher_bar.set_reveal(True)
        toolbar_view.add_bottom_bar(switcher_bar)

        self._win.set_content(toolbar_view)

    def _build_pages(self) -> None:
        """Instantiate and add each page to the ViewStack."""
        from snxui.ui.home_page import HomePage
        from snxui.ui.profiles_page import ProfilesPage
        from snxui.ui.settings_page import SettingsPage

        self._home_page = HomePage(
            profile_manager=self._profile_manager,
            credential_store=self._credential_store,
            snx_backend=self._snx_backend,
        )
        page_home = self._stack.add_titled(
            self._home_page.widget, "home", "Home"
        )
        page_home.set_icon_name("network-vpn-symbolic")

        self._profiles_page = ProfilesPage(
            profile_manager=self._profile_manager,
            credential_store=self._credential_store,
        )
        page_profiles = self._stack.add_titled(
            self._profiles_page.widget, "profiles", "Profiles"
        )
        page_profiles.set_icon_name("address-book-symbolic")

        self._settings_page = SettingsPage(
            autostart=self._autostart,
        )
        page_settings = self._stack.add_titled(
            self._settings_page.widget, "settings", "Settings"
        )
        page_settings.set_icon_name("preferences-system-symbolic")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _register_actions(self) -> None:
        """Register GAction instances on the application."""
        # "About" action.
        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self._on_about)
        self._app.add_action(about_action)

        # "Quit" action.
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", self._on_quit)
        self._app.add_action(quit_action)

    # ------------------------------------------------------------------
    # Tray integration
    # ------------------------------------------------------------------

    def _connect_tray(self) -> None:
        """Wire tray callbacks to window actions."""
        self._tray_manager.on_show_window(self.present)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def present(self) -> None:
        """Show and raise the window."""
        self._win.present()

    def hide(self) -> None:
        """Hide the window (keep running in background)."""
        self._win.set_visible(False)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_close_request(self, win: object) -> bool:
        """Hide to tray or allow destroy based on the Settings toggle."""
        if self._settings_page.minimize_to_tray:
            logger.debug("Close requested — hiding to tray.")
            self.hide()
            return True  # Prevent the default destroy.
        logger.debug("Close requested — quitting (minimize-to-tray is off).")
        return False  # Allow the default destroy.

    def _on_about(self, action: object, param: object) -> None:
        from snxui.ui.dialogs import AboutDialog

        AboutDialog().show(self._win)

    def _on_quit(self, action: object, param: object) -> None:
        logger.debug("Quit action triggered.")
        self._app.quit()
