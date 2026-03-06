"""Settings page — application preferences.

Layout:
    Adw.PreferencesPage
      Adw.PreferencesGroup "General"
        Adw.SwitchRow "Launch at login"
        Adw.SwitchRow "Minimize to tray on close"
        Adw.ComboRow "Color scheme" (System / Light / Dark)
      Adw.PreferencesGroup "System"
        Adw.ActionRow "Polkit status"
        Adw.ActionRow "Net Helper" (path)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path
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


def _settings_path() -> Path:
    """Return the path to the application settings JSON file."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "snxui" / "settings.json"


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
        self._settings: dict = self._load_settings()
        self._build_widget()

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _build_widget(self) -> None:
        self._page = Adw.PreferencesPage()
        self._page.add(self._build_general_group())
        self._page.add(self._build_connection_group())
        self._page.add(self._build_system_group())

    def _build_general_group(self) -> "Adw.PreferencesGroup":
        """Build and return the General preferences group."""
        general_group = Adw.PreferencesGroup(title="General")

        self._autostart_row = Adw.SwitchRow(
            title="Launch at Login",
            subtitle="Start SNX VPN automatically when you log in",
        )
        self._autostart_row.set_active(self._autostart.is_enabled())
        self._autostart_row.connect("notify::active", self._on_autostart_toggled)
        general_group.add(self._autostart_row)

        self._tray_row = Adw.SwitchRow(
            title="Minimize to Tray on Close",
            subtitle="Keep running in the system tray when the window is closed",
        )
        self._tray_row.set_active(self._settings.get("minimize_to_tray", True))
        self._tray_row.connect("notify::active", self._on_tray_toggled)
        general_group.add(self._tray_row)

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
        return general_group

    def _build_connection_group(self) -> "Adw.PreferencesGroup":
        """Build and return the Connection preferences group."""
        conn_group = Adw.PreferencesGroup(title="Connection")

        self._ask_mfa_row = Adw.SwitchRow(
            title="Ask Server for MFA Prompts",
            subtitle="Show MFA dialog on every connection, even if 2FA is not configured in profile",
        )
        self._ask_mfa_row.set_active(self._settings.get("ask_server_mfa", False))
        self._ask_mfa_row.connect("notify::active", self._on_ask_mfa_toggled)
        conn_group.add(self._ask_mfa_row)

        return conn_group

    def _build_system_group(self) -> "Adw.PreferencesGroup":
        """Build and return the System diagnostics preferences group."""
        system_group = Adw.PreferencesGroup(title="System")

        polkit_status = self._check_polkit()
        polkit_row = Adw.ActionRow(
            title="Polkit Status",
            subtitle=polkit_status,
        )
        polkit_ok = "available" in polkit_status.lower()
        polkit_row.add_prefix(Gtk.Image.new_from_icon_name(
            "security-high-symbolic" if polkit_ok else "security-low-symbolic"
        ))
        system_group.add(polkit_row)

        helper_path, helper_ok = self._check_net_helper()
        helper_row = Adw.ActionRow(
            title="Net Helper",
            subtitle=helper_path,
        )
        helper_row.add_prefix(Gtk.Image.new_from_icon_name(
            "security-high-symbolic" if helper_ok else "dialog-warning-symbolic"
        ))
        system_group.add(helper_row)

        return system_group

    @property
    def widget(self) -> "Adw.PreferencesPage":
        return self._page

    # ------------------------------------------------------------------
    # Settings persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _load_settings() -> dict:
        """Load persisted settings from JSON file; return defaults on any error."""
        path = _settings_path()
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
            logger.warning("settings.json has invalid structure — resetting.")
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read settings.json: %s", exc)
            return {}

    def _save_settings(self) -> None:
        """Persist current in-memory settings to JSON file."""
        path = _settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._settings, fh, indent=2, ensure_ascii=False)
            tmp.replace(path)
        except OSError as exc:
            logger.warning("Failed to save settings.json: %s", exc)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                logger.debug("Failed to remove settings staging file.", exc_info=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_polkit() -> str:
        """Return a human-readable polkit status string."""
        pkexec = shutil.which("pkexec")
        if not pkexec:
            return "pkexec not found — install policykit-1"
        return f"Available ({pkexec})"

    @staticmethod
    def _check_net_helper() -> tuple[str, bool]:
        """Return (subtitle, ok) for the snxui-net-helper diagnostic row."""
        path = Path("/usr/lib/snxui/snxui-net-helper")
        if path.exists():
            return str(path), True
        return "Not found — reinstall snxui package", False

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

    def _on_tray_toggled(self, row: "Adw.SwitchRow", _param: object) -> None:
        self._settings["minimize_to_tray"] = row.get_active()
        self._save_settings()

    def _on_ask_mfa_toggled(self, row: "Adw.SwitchRow", _param: object) -> None:
        self._settings["ask_server_mfa"] = row.get_active()
        self._save_settings()

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

    @property
    def ask_server_mfa(self) -> bool:
        """Return whether 'ask server for MFA prompts' is enabled."""
        return self._ask_mfa_row.get_active()
