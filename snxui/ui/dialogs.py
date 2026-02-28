"""UI dialogs — PasswordDialog, ProfileDialog, AboutDialog.

All dialogs follow the Adw.Dialog pattern: they are presented modally
over the calling window and deliver their result via a callback to avoid
blocking the GTK main loop.
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from snxui.core.types import Profile

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
    logger.warning("GTK4/Libadwaita not available — dialogs will not function.")


# ---------------------------------------------------------------------------
# PasswordDialog
# ---------------------------------------------------------------------------


class PasswordDialog:
    """Modal dialog that requests a VPN password from the user.

    Args:
        profile_name: Human-readable name shown in the dialog heading.

    Callback signature::

        callback(password: Optional[str], save: bool)

        password is None when the user cancels.
    """

    def __init__(self, profile_name: str = "") -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for PasswordDialog.")

        self._profile_name = profile_name

    def show(
        self,
        callback: Callable[[Optional[str], bool], None],
        parent: object = None,
    ) -> None:
        """Present the dialog.

        Args:
            callback: Called with (password, save_flag) when the user acts.
            parent: Optional parent GTK widget/window.
        """
        dialog = Adw.Dialog(title="Connect to VPN")
        dialog.set_content_width(360)

        # Content.
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_margin_top(24)
        content_box.set_margin_bottom(24)
        content_box.set_margin_start(24)
        content_box.set_margin_end(24)

        heading = Gtk.Label(label=f"Password for {self._profile_name}")
        heading.add_css_class("title-3")
        heading.set_halign(Gtk.Align.START)
        content_box.append(heading)

        # Password entry.
        prefs_group = Adw.PreferencesGroup()
        password_row = Adw.PasswordEntryRow(title="Password")
        prefs_group.add(password_row)
        content_box.append(prefs_group)

        # Save password checkbox.
        save_check = Gtk.CheckButton(label="Remember password in keyring")
        content_box.append(save_check)

        # Buttons.
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect(
            "clicked",
            lambda _b: (dialog.close(), callback(None, False)),
        )
        btn_box.append(cancel_btn)

        connect_btn = Gtk.Button(label="Connect")
        connect_btn.add_css_class("suggested-action")
        connect_btn.connect(
            "clicked",
            lambda _b: (
                # Read widget values BEFORE closing the dialog.  dialog.close()
                # schedules widget destruction; although GTK4 defers the actual
                # teardown until the next main-loop iteration, reading after
                # close() is fragile and implementation-dependent.
                callback(password_row.get_text(), save_check.get_active()),
                dialog.close(),
            ),
        )
        btn_box.append(connect_btn)
        content_box.append(btn_box)

        dialog.set_child(content_box)

        if parent is not None:
            dialog.present(parent)
        else:
            dialog.present(None)


# ---------------------------------------------------------------------------
# ProfileDialog
# ---------------------------------------------------------------------------


class ProfileDialog:
    """Modal dialog for creating or editing a connection profile.

    Args:
        profile: Existing profile to edit, or None to create a new one.
        callback: Called with the resulting Profile, or None on cancel.
    """

    def __init__(
        self,
        profile: Optional["Profile"],
        callback: Callable[[Optional["Profile"]], None],
    ) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for ProfileDialog.")

        self._profile = profile
        self._callback = callback

    def show(self, parent: object = None) -> None:
        """Present the profile editor dialog."""
        from snxui.core.types import Profile

        is_new = self._profile is None
        title = "Add Profile" if is_new else "Edit Profile"

        dialog = Adw.Dialog(title=title)
        dialog.set_content_width(400)

        # Scrolled content.
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(300)
        scroll.set_max_content_height(500)

        prefs_page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(title="Profile Details")
        prefs_page.add(group)

        # Name.
        name_row = Adw.EntryRow(title="Profile Name")
        name_row.set_text(self._profile.name if self._profile else "")
        group.add(name_row)

        # Server.
        server_row = Adw.EntryRow(title="Server (hostname)")
        server_row.set_text(self._profile.server if self._profile else "")
        group.add(server_row)

        # Username.
        user_row = Adw.EntryRow(title="Username")
        user_row.set_text(self._profile.username if self._profile else "")
        group.add(user_row)

        # SSL Port.
        port_row = Adw.SpinRow.new_with_range(1, 65535, 1)
        port_row.set_title("SSL Port")
        port_row.set_value(self._profile.ssl_port if self._profile else 443)
        group.add(port_row)

        # CA certs path.
        ca_row = Adw.EntryRow(title="CA Certificates Path")
        ca_row.set_text(self._profile.ca_list if self._profile else "/etc/ssl/certs")
        group.add(ca_row)

        # Client certificate (optional).
        cert_row = Adw.EntryRow(title="Client Certificate (optional)")
        cert_row.set_text(self._profile.certificate or "" if self._profile else "")
        group.add(cert_row)

        # Save password checkbox row.
        save_pwd_row = Adw.SwitchRow(title="Save Password in Keyring")
        save_pwd_row.set_active(self._profile.save_password if self._profile else False)
        group.add(save_pwd_row)

        scroll.set_child(prefs_page)

        # Buttons.
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_margin_top(12)
        btn_box.set_margin_bottom(16)
        btn_box.set_margin_start(16)
        btn_box.set_margin_end(16)
        btn_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _b: (dialog.close(), self._callback(None)))
        btn_box.append(cancel_btn)

        save_label = "Add" if is_new else "Save"
        save_btn = Gtk.Button(label=save_label)
        save_btn.add_css_class("suggested-action")

        # Inline error label — shown only when validation fails.
        error_label = Gtk.Label(label="")
        error_label.add_css_class("error")
        error_label.set_margin_top(4)
        error_label.set_margin_bottom(4)
        error_label.set_margin_start(16)
        error_label.set_halign(Gtk.Align.START)
        error_label.set_visible(False)

        def _on_save(_btn: object) -> None:
            server = server_row.get_text().strip()
            username = user_row.get_text().strip()
            if not server or not username:
                # Keep dialog open and show which field is missing.
                missing = "Server" if not server else "Username"
                error_label.set_label(f"{missing} is required.")
                error_label.set_visible(True)
                return
            error_label.set_visible(False)
            # Read ALL widget values BEFORE closing the dialog.  dialog.close()
            # schedules widget destruction; reading after close() is fragile and
            # implementation-dependent.  Same rule applied to PasswordDialog.
            name = name_row.get_text().strip()
            ssl_port = int(port_row.get_value())
            ca_list = ca_row.get_text().strip() or "/etc/ssl/certs"
            certificate = cert_row.get_text().strip() or None
            save_password = save_pwd_row.get_active()
            dialog.close()
            profile = Profile(
                id=self._profile.id if self._profile else str(uuid.uuid4()),
                name=name,
                server=server,
                username=username,
                ssl_port=ssl_port,
                ca_list=ca_list,
                certificate=certificate,
                save_password=save_password,
            )
            self._callback(profile)

        save_btn.connect("clicked", _on_save)
        btn_box.append(save_btn)

        # Wrap scroll + error label + buttons in a vertical box.
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.append(scroll)
        outer.append(error_label)
        outer.append(btn_box)

        dialog.set_child(outer)

        if parent is not None:
            dialog.present(parent)
        else:
            dialog.present(None)


# ---------------------------------------------------------------------------
# AboutDialog
# ---------------------------------------------------------------------------


class AboutDialog:
    """Thin wrapper around Adw.AboutDialog."""

    def show(self, parent: object = None) -> None:
        """Present the About dialog.

        Args:
            parent: Parent GTK window, or None.
        """
        if not _GTK_AVAILABLE:
            logger.warning("GTK4 not available — cannot show About dialog.")
            return

        dialog = Adw.AboutDialog(
            application_name="SNX VPN",
            application_icon="network-vpn",
            developer_name="SNX UI Contributors",
            version="0.1.0",
            comments="GUI client for Check Point SNX VPN",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/YOUR_ORG/snxui",
            issue_url="https://github.com/YOUR_ORG/snxui/issues",
        )

        if parent is not None:
            dialog.present(parent)
        else:
            dialog.present(None)
