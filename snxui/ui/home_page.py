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
    from snxui.core.types import ConnectionStatus, Profile

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
    ) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for HomePage.")

        self._pm = profile_manager
        self._cs = credential_store
        self._backend = snx_backend
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
        # Root: scrollable preferences page.
        self._page = Adw.PreferencesPage()

        # ── Status group ─────────────────────────────────────────────
        status_group = Adw.PreferencesGroup()
        self._page.add(status_group)

        # Status icon.
        self._status_icon = Gtk.Image()
        self._status_icon.set_icon_name("network-offline-symbolic")
        self._status_icon.set_pixel_size(64)
        self._status_icon.set_margin_top(24)
        self._status_icon.set_margin_bottom(8)

        # Status label.
        self._status_label = Gtk.Label(label="Disconnected")
        self._status_label.add_css_class("title-2")
        self._status_label.set_margin_bottom(4)

        # IP / server info (hidden when disconnected).
        self._info_label = Gtk.Label(label="")
        self._info_label.add_css_class("caption")
        self._info_label.set_opacity(0.6)
        self._info_label.set_margin_bottom(16)
        self._info_label.set_visible(False)

        # Spinner.
        self._spinner = Gtk.Spinner()
        self._spinner.set_size_request(32, 32)
        self._spinner.set_margin_bottom(8)
        self._spinner.set_visible(False)

        # Pack status elements into a vertical box.
        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        status_box.set_halign(Gtk.Align.CENTER)
        status_box.append(self._status_icon)
        status_box.append(self._status_label)
        status_box.append(self._info_label)
        status_box.append(self._spinner)
        status_group.add(status_box)

        # ── Profile group ─────────────────────────────────────────────
        profile_group = Adw.PreferencesGroup(title="Connection Profile")
        self._page.add(profile_group)

        # Profile drop-down.
        self._profile_model = Gtk.StringList()
        self._profile_dropdown = Gtk.DropDown(model=self._profile_model)
        self._profile_dropdown.set_margin_start(16)
        self._profile_dropdown.set_margin_end(16)
        self._profile_dropdown.set_margin_top(8)
        self._profile_dropdown.set_margin_bottom(8)
        profile_group.add(self._profile_dropdown)

        # ── Action group ──────────────────────────────────────────────
        action_group = Adw.PreferencesGroup()
        self._page.add(action_group)

        # Connect / Disconnect button.
        self._connect_btn = Gtk.Button(label="Connect")
        self._connect_btn.add_css_class("suggested-action")
        self._connect_btn.add_css_class("pill")
        self._connect_btn.set_margin_start(32)
        self._connect_btn.set_margin_end(32)
        self._connect_btn.set_margin_top(16)
        self._connect_btn.set_margin_bottom(32)
        self._connect_btn.connect("clicked", self._on_connect_clicked)
        action_group.add(self._connect_btn)

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
            self._status_icon.set_icon_name("network-vpn-symbolic")
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

        elif state == ConnectionState.CONNECTING:
            self._status_icon.set_icon_name("network-transmit-receive-symbolic")
            self._status_label.set_label("Connecting...")
            self._info_label.set_visible(False)
            self._connect_btn.set_sensitive(False)
            self._spinner.set_spinning(True)
            self._spinner.set_visible(True)

        elif state == ConnectionState.DISCONNECTING:
            self._status_icon.set_icon_name("network-offline-symbolic")
            self._status_label.set_label("Disconnecting...")
            self._connect_btn.set_sensitive(False)
            self._spinner.set_spinning(True)
            self._spinner.set_visible(True)

        elif state == ConnectionState.ERROR:
            self._status_icon.set_icon_name("network-error-symbolic")
            err = status.error_message or "Unknown error"
            self._status_label.set_label(f"Error: {err}")
            self._info_label.set_visible(False)
            self._connect_btn.set_label("Connect")
            self._connect_btn.remove_css_class("destructive-action")
            self._connect_btn.add_css_class("suggested-action")
            self._connect_btn.set_sensitive(True)
            self._spinner.set_spinning(False)
            self._spinner.set_visible(False)
            self._connecting = False

        else:  # DISCONNECTED
            self._status_icon.set_icon_name("network-offline-symbolic")
            self._status_label.set_label("Disconnected")
            self._info_label.set_visible(False)
            self._connect_btn.set_label("Connect")
            self._connect_btn.remove_css_class("destructive-action")
            self._connect_btn.add_css_class("suggested-action")
            self._connect_btn.set_sensitive(True)
            self._spinner.set_spinning(False)
            self._spinner.set_visible(False)
            self._connecting = False

        return GLib.SOURCE_REMOVE

    def _refresh_status(self) -> None:
        """Query the backend for the current status and apply it."""
        try:
            status = self._backend.get_status()
            self._apply_status(status)
        except Exception:
            logger.exception("Failed to get initial status.")

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
        self._connect_btn.set_sensitive(False)
        self._spinner.set_spinning(True)
        self._spinner.set_visible(True)
        self._status_label.set_label("Disconnecting...")

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
                # success=False: disconnect() already dispatched ERROR status
                # via _update_status().  Calling _refresh_status() here would
                # invoke get_status() → check tunsnx → if still exists →
                # override ERROR with CONNECTED, hiding the error message.
                # Mirror the pattern used in _start_connect (Round 4 fix).

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
            logger.debug("No saved password for profile %s.", profile.id)

        if password:
            self._start_connect(profile, password)
        else:
            self._ask_password_then_connect(profile)

    def _ask_password_then_connect(self, profile: "Profile") -> None:
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

        dialog = PasswordDialog(profile_name=profile.name or profile.server)
        dialog.show(callback=_on_response)

    def _start_connect(self, profile: "Profile", password: str) -> None:
        """Launch the SNX connect in a background thread."""
        if self._connecting:
            return
        self._connecting = True
        self._connect_btn.set_sensitive(False)
        self._spinner.set_spinning(True)
        self._spinner.set_visible(True)
        self._status_label.set_label("Connecting...")

        def _run() -> None:
            try:
                success = self._backend.connect(
                    profile,
                    password,
                    status_callback=self.update_status,
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
