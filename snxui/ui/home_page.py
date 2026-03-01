"""Home page — connection status, profile selector, connect/disconnect button.

Layout (vertical Gtk.Box inside a ScrolledWindow):
    [Status icon + label]
    [Profile dropdown]
    [IP / Server info (visible when connected)]
    [Connect / Disconnect button]
    [Spinner (visible when connecting)]
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from snxui.core import ProfileManager, CredentialStore, SNXBackend
    from snxui.core.types import ConnectionStatus, Profile, TwoFactorCallback
    from snxui.system import TrayManager

logger = logging.getLogger(__name__)

try:
    import gi

    gi.require_version("Adw", "1")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Adw, Gtk, GLib

    _GTK_AVAILABLE = True
except (ImportError, ValueError):
    Adw = None  # type: ignore[assignment]
    Gtk = None  # type: ignore[assignment]
    GLib = None  # type: ignore[assignment]
    _GTK_AVAILABLE = False
    logger.warning("GTK4/Libadwaita not available — HomePage will not function.")


class HomePage:
    """Connection status and control page.

    Args:
        profile_manager: Provides the list of saved profiles.
        credential_store: Retrieves saved passwords from the keyring.
        snx_backend: Handles connect/disconnect operations.
    """

    def __init__(
        self,
        *,
        profile_manager: "ProfileManager",
        credential_store: "CredentialStore",
        snx_backend: "SNXBackend",
        tray_manager: "Optional[TrayManager]" = None,
    ) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for HomePage.")

        self._pm = profile_manager
        self._cs = credential_store
        self._backend = snx_backend
        self._tray = tray_manager
        self._profiles: list["Profile"] = []
        self._connecting = False

        self._build_widget()
        self._refresh_profiles()
        self._refresh_status()

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _build_widget(self) -> None:
        """Build the page widget tree."""
        self._page = Adw.PreferencesPage()
        self._page.add(self._build_status_group())
        self._page.add(self._build_profile_group())
        self._page.add(self._build_action_group())

    def _build_status_group(self) -> "Adw.PreferencesGroup":
        """Build and return the status display group."""
        status_group = Adw.PreferencesGroup()

        self._status_icon = Gtk.Image()
        self._status_icon.set_from_icon_name("network-offline-symbolic")
        self._status_icon.set_pixel_size(64)
        self._status_icon.set_margin_top(24)
        self._status_icon.set_margin_bottom(8)

        self._status_label = Gtk.Label(label="Disconnected")
        self._status_label.add_css_class("title-2")
        self._status_label.set_margin_bottom(4)

        self._info_label = Gtk.Label(label="")
        self._info_label.add_css_class("caption")
        self._info_label.set_opacity(0.6)
        self._info_label.set_margin_bottom(16)
        self._info_label.set_wrap(True)
        self._info_label.set_justify(Gtk.Justification.CENTER)
        self._info_label.set_visible(False)

        self._spinner = Gtk.Spinner()
        self._spinner.set_size_request(32, 32)
        self._spinner.set_margin_bottom(8)
        self._spinner.set_visible(False)

        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        status_box.set_halign(Gtk.Align.CENTER)
        status_box.append(self._status_icon)
        status_box.append(self._status_label)
        status_box.append(self._info_label)
        status_box.append(self._spinner)
        status_group.add(status_box)
        return status_group

    def _build_profile_group(self) -> "Adw.PreferencesGroup":
        """Build and return the profile selection group."""
        profile_group = Adw.PreferencesGroup(title="Connection Profile")

        self._profile_model = Gtk.StringList()
        self._profile_dropdown = Gtk.DropDown(model=self._profile_model)
        self._profile_dropdown.set_margin_start(16)
        self._profile_dropdown.set_margin_end(16)
        self._profile_dropdown.set_margin_top(8)
        self._profile_dropdown.set_margin_bottom(8)
        profile_group.add(self._profile_dropdown)
        return profile_group

    def _build_action_group(self) -> "Adw.PreferencesGroup":
        """Build and return the connect/disconnect action group."""
        action_group = Adw.PreferencesGroup()

        self._connect_btn = Gtk.Button(label="Connect")
        self._connect_btn.add_css_class("suggested-action")
        self._connect_btn.add_css_class("pill")
        self._connect_btn.set_margin_start(32)
        self._connect_btn.set_margin_end(32)
        self._connect_btn.set_margin_top(16)
        self._connect_btn.set_margin_bottom(32)
        self._connect_btn.connect("clicked", self._on_connect_clicked)
        action_group.add(self._connect_btn)
        return action_group

    @property
    def widget(self) -> "Adw.PreferencesPage":
        """Return the root GTK widget for this page."""
        return self._page

    # ------------------------------------------------------------------
    # Profile list helpers
    # ------------------------------------------------------------------

    def _refresh_profiles(self) -> None:
        """Reload profiles from ProfileManager into the dropdown."""
        try:
            self._profiles = self._pm.list_all()
        except Exception:
            logger.exception("Failed to load profiles.")
            self._profiles = []

        # Rebuild the StringList model by replacing it with a new instance.
        self._profile_model = Gtk.StringList()
        self._profile_dropdown.set_model(self._profile_model)

        if self._profiles:
            for p in self._profiles:
                self._profile_model.append(p.name or p.server)
        else:
            self._profile_model.append("(No profiles — add one in Profiles tab)")

    def _selected_profile(self) -> Optional["Profile"]:
        """Return the currently selected Profile, or None."""
        idx = self._profile_dropdown.get_selected()
        if self._profiles and 0 <= idx < len(self._profiles):
            return self._profiles[idx]
        return None

    # ------------------------------------------------------------------
    # Status update (can be called from any thread)
    # ------------------------------------------------------------------

    def update_status(self, status: "ConnectionStatus") -> None:
        """Update the page UI to reflect *status*.

        Thread-safe: schedules an idle callback if called from a non-main thread.
        """
        GLib.idle_add(self._apply_status, status)

    def _apply_status(self, status: "ConnectionStatus") -> bool:
        """Apply a status update on the main thread."""
        from snxui.core.types import ConnectionState

        state = status.state
        if state == ConnectionState.CONNECTED:
            self._apply_connected(status)
        elif state == ConnectionState.CONNECTING:
            self._apply_connecting()
        elif state == ConnectionState.DISCONNECTING:
            self._apply_disconnecting()
        elif state == ConnectionState.ERROR:
            self._apply_error(status)
        else:  # DISCONNECTED
            self._apply_disconnected()
        return GLib.SOURCE_REMOVE

    def _apply_connected(self, status: "ConnectionStatus") -> None:
        """Update UI for the CONNECTED state."""
        self._status_icon.set_from_icon_name("network-vpn-symbolic")
        self._status_label.set_label("Connected")
        ip = status.ip_address or ""
        server = status.profile.server if status.profile else ""
        info = f"IP: {ip}" if ip else ""
        if server:
            info = f"{info}  |  {server}" if info else server
        self._info_label.set_label(info)
        self._info_label.set_visible(bool(info))
        self._connect_btn.set_label("Disconnect")
        self._connect_btn.remove_css_class("suggested-action")
        self._connect_btn.add_css_class("destructive-action")
        self._spinner.set_spinning(False)
        self._spinner.set_visible(False)
        self._connect_btn.set_sensitive(True)
        self._connecting = False
        if self._tray is not None:
            profile_name = status.profile.name or status.profile.server if status.profile else ""
            self._tray.set_connected(True, profile_name)

    def _apply_connecting(self) -> None:
        """Update UI for the CONNECTING state."""
        self._status_icon.set_from_icon_name("network-transmit-receive-symbolic")
        self._status_label.set_label("Connecting...")
        self._info_label.set_visible(False)
        self._connect_btn.set_sensitive(False)
        self._spinner.set_spinning(True)
        self._spinner.set_visible(True)

    def _apply_disconnecting(self) -> None:
        """Update UI for the DISCONNECTING state."""
        self._status_icon.set_from_icon_name("network-offline-symbolic")
        self._status_label.set_label("Disconnecting...")
        self._info_label.set_visible(False)
        self._connect_btn.set_sensitive(False)
        self._spinner.set_spinning(True)
        self._spinner.set_visible(True)

    def _apply_error(self, status: "ConnectionStatus") -> None:
        """Update UI for the ERROR state."""
        self._status_icon.set_from_icon_name("network-error-symbolic")
        err = status.error_message or "Unknown error"

        # Split multi-line messages: first line as title, rest as detail.
        lines = err.strip().splitlines()
        title_line = lines[0] if lines else err
        detail_line = " ".join(l.strip() for l in lines[1:] if l.strip()) if len(lines) > 1 else ""

        self._status_label.set_label(f"Error: {title_line}")
        if detail_line:
            self._info_label.set_label(detail_line)
            self._info_label.set_visible(True)
        else:
            self._info_label.set_visible(False)

        self._connect_btn.set_label("Connect")
        self._connect_btn.remove_css_class("destructive-action")
        self._connect_btn.add_css_class("suggested-action")
        self._connect_btn.set_sensitive(True)
        self._spinner.set_spinning(False)
        self._spinner.set_visible(False)
        self._connecting = False
        if self._tray is not None:
            self._tray.set_error(title_line)
        if status.profile and self._is_auth_failure(err):
            self._retry_password_after_failure(status.profile, err)

    @staticmethod
    def _is_auth_failure(error_message: str) -> bool:
        """Return True if the error message indicates wrong credentials."""
        keywords = ("authentication failed", "invalid password", "access denied", "login failed")
        return any(kw in error_message.lower() for kw in keywords)

    def _retry_password_after_failure(self, profile: "Profile", error_msg: str) -> None:
        """Clear the saved (wrong) password and re-show the password dialog."""
        try:
            self._cs.delete_password(profile.id)
        except Exception:
            logger.debug("Could not clear saved password for profile %s.", profile.id)
        self._ask_password_then_connect(profile, error_hint=error_msg)

    def _apply_disconnected(self) -> None:
        """Update UI for the DISCONNECTED state."""
        self._status_icon.set_from_icon_name("network-offline-symbolic")
        self._status_label.set_label("Disconnected")
        self._info_label.set_visible(False)
        self._connect_btn.set_label("Connect")
        self._connect_btn.remove_css_class("destructive-action")
        self._connect_btn.add_css_class("suggested-action")
        self._connect_btn.set_sensitive(True)
        self._spinner.set_spinning(False)
        self._spinner.set_visible(False)
        self._connecting = False
        if self._tray is not None:
            self._tray.set_connected(False)

    def _refresh_status(self) -> None:
        """Query the backend for the current status and apply it."""
        try:
            status = self._backend.get_status()
            self._apply_status(status)
        except Exception:
            logger.exception("Failed to get initial status.")

    # ------------------------------------------------------------------
    # Public action API (used by MainWindow tray wiring)
    # ------------------------------------------------------------------

    def do_connect(self) -> None:
        """Initiate VPN connection (same as clicking the Connect button)."""
        self._do_connect()

    def do_disconnect(self) -> None:
        """Initiate VPN disconnection (same as clicking the Disconnect button)."""
        self._do_disconnect()

    def refresh_profiles(self) -> None:
        """Reload the profile dropdown (call after external profile changes)."""
        self._refresh_profiles()

    # ------------------------------------------------------------------
    # Connect / Disconnect logic
    # ------------------------------------------------------------------

    def _on_connect_clicked(self, btn: "Gtk.Button") -> None:
        """Handle the Connect / Disconnect button click."""
        from snxui.core.types import ConnectionState

        try:
            current = self._backend.get_status()
        except Exception:
            current = None

        if current and current.state == ConnectionState.CONNECTED:
            self._do_disconnect()
        else:
            self._do_connect()

    def _do_disconnect(self) -> None:
        """Initiate disconnection in a background thread."""
        self._apply_disconnecting()

        def _run() -> None:
            try:
                success = self._backend.disconnect()
            except Exception as exc:
                # Pre-pexpect exception (FileNotFoundError, RuntimeError).
                # disconnect() set no internal status — refresh to show the
                # actual interface state.
                logger.exception("Disconnect error: %s", exc)
                GLib.idle_add(self._refresh_status)
            else:
                if success:
                    GLib.idle_add(self._refresh_status)
                else:
                    # Do NOT call _refresh_status() here: get_status() would
                    # re-probe tunsnx (still up) and flip ERROR → CONNECTED,
                    # hiding the disconnect-failure message.  Read the error
                    # snapshot cached by disconnect() via _update_status()
                    # and dispatch it to the UI directly.
                    cached = self._backend.get_cached_status()
                    GLib.idle_add(self.update_status, cached)

        threading.Thread(target=_run, daemon=True).start()

    def _do_connect(self) -> None:
        """Initiate connection: ask for password if needed, then connect."""
        profile = self._selected_profile()
        if profile is None:
            self._show_no_profile_toast()
            return

        # Always try to retrieve a saved password from the keyring.
        # This covers both profile.save_password=True (explicitly configured in
        # profile settings) and the case where the user previously checked
        # "Remember password" in the connect dialog (which saves regardless of
        # profile.save_password).  Guarding with "if profile.save_password:"
        # here would make the dialog checkbox ineffective whenever the profile
        # does not have save_password enabled — the password would be stored but
        # never auto-loaded.
        password = None
        try:
            password = self._cs.get_password(profile.id)
        except Exception:
            logger.debug("Could not retrieve saved password for profile %s.", profile.id)

        if password:
            self._start_connect(profile, password)
        else:
            self._ask_password_then_connect(profile)

    def _ask_password_then_connect(
        self, profile: "Profile", error_hint: Optional[str] = None
    ) -> None:
        """Show the PasswordDialog, then connect if the user confirms."""
        from snxui.ui.dialogs import PasswordDialog

        def _on_response(password: Optional[str], save: bool) -> None:
            if password is None:
                return  # User cancelled.
            # Save if the user checked "Remember" OR if the profile is
            # configured to always persist the password (save_password=True).
            # Without the "or profile.save_password" branch, a user who enables
            # "Save Password" at the profile level would still have to check the
            # dialog checkbox every time — the profile setting would have no
            # effect on saving.
            if save or profile.save_password:
                try:
                    self._cs.set_password(profile.id, password)
                except Exception:
                    logger.warning("Failed to save password to keyring.")
            self._start_connect(profile, password)

        parent = self._page.get_root()
        dialog = PasswordDialog(
            profile_name=profile.name or profile.server,
            error_hint=error_hint,
        )
        dialog.show(callback=_on_response, parent=parent)

    def _start_connect(self, profile: "Profile", password: str) -> None:
        """Launch the SNX connect in a background thread."""
        if self._connecting:
            return
        self._connecting = True
        self._apply_connecting()

        two_factor_callback = self._build_two_factor_callback(profile)

        def _run() -> None:
            try:
                success = self._backend.connect(
                    profile,
                    password,
                    status_callback=self.update_status,
                    two_factor_callback=two_factor_callback,
                )
            except Exception as exc:
                # FileNotFoundError (binary missing) or RuntimeError (pexpect
                # not installed) — connect() did not set any status yet.
                logger.exception("Connect error: %s", exc)
                from snxui.core.types import ConnectionStatus, ConnectionState
                GLib.idle_add(
                    self._apply_status,
                    ConnectionStatus(
                        state=ConnectionState.ERROR,
                        error_message=str(exc),
                    ),
                )
                # Do NOT refresh here: _refresh_status() would call get_status()
                # which returns DISCONNECTED (no tunnel) and immediately override
                # the ERROR status above, making the error message invisible.
            else:
                # connect() returned without raising.  For the success path,
                # schedule a refresh so the UI is in sync with the real tunsnx
                # state.  For the failure path (success=False), connect() already
                # dispatched an ERROR status via status_callback — a refresh here
                # would again override it with DISCONNECTED.
                if success:
                    GLib.idle_add(self._refresh_status)

        threading.Thread(target=_run, daemon=True).start()

    def _show_no_profile_toast(self) -> None:
        """Display a toast warning when no profile is selected."""
        # get_root() returns the toplevel Gtk.Window/Adw.ApplicationWindow.
        # Adw.ApplicationWindow has add_toast() in libadwaita >= 1.2.
        window = self._page.get_root()
        if window is not None and hasattr(window, "add_toast"):
            toast = Adw.Toast(title="Please add a profile first.")
            window.add_toast(toast)
        else:
            logger.warning("No profile selected for connection.")

    def _build_two_factor_callback(
        self, profile: "Profile"
    ) -> "Optional[TwoFactorCallback]":
        """Return appropriate 2FA callback based on profile's method."""
        from snxui.core.types import TwoFactorMethod
        if profile.two_factor_method == TwoFactorMethod.NONE:
            return None
        if profile.two_factor_method in (TwoFactorMethod.TOTP, TwoFactorMethod.HOTP):
            secret: Optional[str] = None
            try:
                secret = self._cs.get_totp_secret(profile.id)
            except Exception:
                pass
            if secret is not None:
                # Явное non-optional связывание для mypy strict
                _secret: str = secret

                def _auto_totp(_prompt: str) -> Optional[str]:
                    from snxui.core.totp import generate_totp
                    try:
                        return generate_totp(_secret)
                    except ValueError as exc:
                        logger.error("TOTP generation failed: %s", exc)
                        return None
                return _auto_totp
        # RSA, challenge, RADIUS, TOTP без хранимого секрета — интерактивный диалог
        return self._make_interactive_two_factor_callback(profile)

    def _make_interactive_two_factor_callback(
        self, profile: "Profile"
    ) -> "TwoFactorCallback":
        """Build a callback that shows TwoFactorDialog from the GTK main thread.

        Blocks the background thread via threading.Event until the user acts.
        """
        def _callback(prompt_text: str) -> Optional[str]:
            result: dict[str, Optional[str]] = {"code": None}
            event = threading.Event()

            def _show_dialog() -> bool:  # GLib.SOURCE_REMOVE compatible
                from snxui.ui.dialogs import TwoFactorDialog

                def _on_response(code: Optional[str]) -> None:
                    result["code"] = code
                    event.set()

                parent = self._page.get_root()
                TwoFactorDialog(
                    profile_name=profile.name or profile.server,
                    prompt_text=prompt_text,
                ).show(callback=_on_response, parent=parent)
                return GLib.SOURCE_REMOVE

            GLib.idle_add(_show_dialog)
            if not event.wait(timeout=120.0):
                logger.warning("2FA dialog timed out after 120s.")
                return None
            return result["code"]

        return _callback
