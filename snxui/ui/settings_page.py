"""Settings page — application preferences.

Layout:
    Adw.PreferencesPage
      Adw.PreferencesGroup "General"
        Adw.SwitchRow "Launch at login"
        Adw.SwitchRow "Minimize to tray on close"
        Adw.ComboRow "Color scheme" (System / Light / Dark)
      Adw.PreferencesGroup "SNX"
        Adw.ActionRow "SNX Binary" (path)
        Adw.ActionRow "Polkit status"
"""

from __future__ import annotations

import logging
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from snxui.system import AutostartManager

logger = logging.getLogger(__name__)

try:
    import gi

    gi.require_version("Adw", "1")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Adw, Gtk

    _GTK_AVAILABLE = True
except (ImportError, ValueError):
    Adw = None  # type: ignore[assignment]
    Gtk = None  # type: ignore[assignment]
    _GTK_AVAILABLE = False
    logger.warning("GTK4/Libadwaita not available — SettingsPage will not function.")


_COLOR_SCHEMES = ["System", "Light", "Dark"]
_ADW_COLOR_SCHEMES = [
    "COLOR_SCHEME_DEFAULT",
    "COLOR_SCHEME_FORCE_LIGHT",
    "COLOR_SCHEME_FORCE_DARK",
]


class SettingsPage:
    """Application settings page.

    Args:
        autostart: Manages the XDG autostart .desktop file.
    """

    def __init__(self, *, autostart: "AutostartManager") -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for SettingsPage.")

        self._autostart = autostart
        self._build_widget()

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _build_widget(self) -> None:
        self._page = Adw.PreferencesPage()

        # ── General group ─────────────────────────────────────────────
        general_group = Adw.PreferencesGroup(title="General")
        self._page.add(general_group)

        # Autostart switch.
        self._autostart_row = Adw.SwitchRow(
            title="Launch at Login",
            subtitle="Start SNX VPN automatically when you log in",
        )
        self._autostart_row.set_active(self._autostart.is_enabled())
        self._autostart_row.connect("notify::active", self._on_autostart_toggled)
        general_group.add(self._autostart_row)

        # Minimize to tray switch.
        self._tray_row = Adw.SwitchRow(
            title="Minimize to Tray on Close",
            subtitle="Keep running in the system tray when the window is closed",
        )
        self._tray_row.set_active(True)  # Default: enabled.
        general_group.add(self._tray_row)

        # Color scheme combo.
        scheme_model = Gtk.StringList()
        for label in _COLOR_SCHEMES:
            scheme_model.append(label)
        self._scheme_row = Adw.ComboRow(
            title="Color Scheme",
            model=scheme_model,
        )
        self._scheme_row.set_selected(0)  # Default: system.
        self._scheme_row.connect("notify::selected", self._on_scheme_changed)
        general_group.add(self._scheme_row)

        # ── SNX group ─────────────────────────────────────────────────
        snx_group = Adw.PreferencesGroup(title="SNX")
        self._page.add(snx_group)

        # SNX binary path.
        snx_path = self._find_snx_binary()
        snx_row = Adw.ActionRow(
            title="SNX Binary",
            subtitle=snx_path,
        )
        snx_icon = Gtk.Image.new_from_icon_name(
            "utilities-terminal-symbolic" if snx_path != "Not found" else "dialog-warning-symbolic"
        )
        snx_row.add_prefix(snx_icon)
        snx_group.add(snx_row)

        # Polkit status.
        polkit_status = self._check_polkit()
        polkit_row = Adw.ActionRow(
            title="Polkit Status",
            subtitle=polkit_status,
        )
        polkit_icon = Gtk.Image.new_from_icon_name(
            "security-high-symbolic" if "available" in polkit_status.lower() else "security-low-symbolic"
        )
        polkit_row.add_prefix(polkit_icon)
        snx_group.add(polkit_row)

    @property
    def widget(self) -> "Adw.PreferencesPage":
        return self._page

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_snx_binary() -> str:
        """Return the path to the SNX binary, or 'Not found'."""
        for candidate in ("/usr/bin/snx", "/usr/local/bin/snx"):
            if shutil.which(candidate):
                return candidate
        found = shutil.which("snx")
        return found or "Not found"

    @staticmethod
    def _check_polkit() -> str:
        """Return a human-readable polkit status string."""
        pkexec = shutil.which("pkexec")
        if not pkexec:
            return "pkexec not found — install policykit-1"
        return f"Available ({pkexec})"

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_autostart_toggled(self, row: "Adw.SwitchRow", _param: object) -> None:
        # Guard against re-entrant calls: GTK4 emits notify::active synchronously
        # from set_active(), so reverting the switch inside this handler would
        # immediately re-invoke it.  Without the guard that second invocation
        # would try the opposite operation, potentially fail again, revert again,
        # and recurse until RecursionError (e.g. on a read-only filesystem where
        # both enable() and disable() fail).
        if getattr(self, "_autostart_reverting", False):
            return
        active = row.get_active()
        if active:
            ok = self._autostart.enable()
        else:
            ok = self._autostart.disable()
        if not ok:
            self._autostart_reverting = True
            try:
                row.set_active(not active)
            finally:
                self._autostart_reverting = False
            logger.error("Failed to %s autostart.", "enable" if active else "disable")

    def _on_scheme_changed(self, row: "Adw.ComboRow", _param: object) -> None:
        idx = row.get_selected()
        scheme_name = _ADW_COLOR_SCHEMES[idx] if idx < len(_ADW_COLOR_SCHEMES) else None
        if scheme_name is None:
            return
        try:
            style_manager = Adw.StyleManager.get_default()
            scheme = getattr(Adw.ColorScheme, scheme_name, None)
            if scheme is not None:
                style_manager.set_color_scheme(scheme)
                logger.debug("Color scheme set to %s.", scheme_name)
        except Exception as exc:
            logger.warning("Failed to set color scheme: %s", exc)

    @property
    def minimize_to_tray(self) -> bool:
        """Return whether 'minimize to tray on close' is enabled."""
        return self._tray_row.get_active()
