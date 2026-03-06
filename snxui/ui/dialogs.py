"""UI dialogs — PasswordDialog, ProfileDialog, AboutDialog.

All dialogs follow the Adw.Dialog pattern: they are presented modally
over the calling window and deliver their result via a callback to avoid
blocking the GTK main loop.
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from typing import Callable, Optional, TYPE_CHECKING

from snxui import __version__

if TYPE_CHECKING:
    from snxui.core.types import Profile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 2FA method constants (used in ProfileDialog and TwoFactorDialog)
# ---------------------------------------------------------------------------

_2FA_METHOD_LABELS = [
    "None", "TOTP (Time-based)", "HOTP (Counter-based)",
    "RSA SecurID", "Challenge-Response", "RADIUS Token",
]
_2FA_METHOD_VALUES = ["none", "totp", "hotp", "rsa", "challenge", "radius"]

try:
    import gi

    gi.require_version("Adw", "1")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Adw, GLib, Gtk

    _GTK_AVAILABLE = True
except (ImportError, ValueError):
    Adw = None  # type: ignore[assignment]
    GLib = None  # type: ignore[assignment]
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
        error_hint: Optional error message shown in red (e.g. after a failed attempt).

    Callback signature::

        callback(password: Optional[str], save: bool)

        password is None when the user cancels.
    """

    def __init__(self, profile_name: str = "", error_hint: Optional[str] = None) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for PasswordDialog.")

        self._profile_name = profile_name
        self._error_hint = error_hint

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
        content_box = self._build_content(dialog, callback)
        dialog.set_child(content_box)
        dialog.present(parent)

    def _build_content(
        self,
        dialog: object,
        callback: Callable[[Optional[str], bool], None],
    ) -> "Gtk.Box":
        """Build and return the content box for the password dialog."""
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_margin_top(24)
        content_box.set_margin_bottom(24)
        content_box.set_margin_start(24)
        content_box.set_margin_end(24)

        heading = Gtk.Label(label=f"Password for {self._profile_name}")
        heading.add_css_class("title-3")
        heading.set_halign(Gtk.Align.START)
        content_box.append(heading)

        if self._error_hint:
            error_label = Gtk.Label(label=self._error_hint)
            error_label.add_css_class("error")
            error_label.set_halign(Gtk.Align.START)
            error_label.set_wrap(True)
            content_box.append(error_label)

        prefs_group = Adw.PreferencesGroup()
        password_row = Adw.PasswordEntryRow(title="Password")
        prefs_group.add(password_row)
        content_box.append(prefs_group)

        save_check = Gtk.CheckButton(label="Remember password in keyring")
        content_box.append(save_check)

        content_box.append(
            self._build_password_buttons(dialog, callback, password_row, save_check)
        )
        return content_box

    def _build_password_buttons(
        self,
        dialog: object,
        callback: Callable[[Optional[str], bool], None],
        password_row: object,
        save_check: object,
    ) -> "Gtk.Box":
        """Build and return the Cancel / Connect button row."""
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
        return btn_box


# ---------------------------------------------------------------------------
# TwoFactorDialog
# ---------------------------------------------------------------------------


class TwoFactorDialog:
    """Modal dialog для ввода 2FA кода.

    Callback: callback(code: Optional[str]) — None при отмене.
    """

    def __init__(self, profile_name: str = "", prompt_text: str = "") -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for TwoFactorDialog.")
        self._profile_name = profile_name
        self._prompt_text = prompt_text

    def show(
        self,
        callback: Callable[[Optional[str]], None],
        parent: object = None,
    ) -> None:
        """Present the dialog.

        Args:
            callback: Called with the entered code, or None on cancel.
            parent: Optional parent GTK widget/window.
        """
        dialog = Adw.Dialog(title="Two-Factor Authentication")
        dialog.set_content_width(360)
        content_box = self._build_content(dialog, callback)
        dialog.set_child(content_box)
        dialog.present(parent)

    def _build_content(self, dialog: object, callback: Callable[[Optional[str]], None]) -> "Gtk.Box":
        """Build and return the content box for the 2FA dialog."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        heading = Gtk.Label(label=f"2FA Required — {self._profile_name}")
        heading.add_css_class("title-3")
        heading.set_halign(Gtk.Align.START)
        box.append(heading)

        if self._prompt_text.strip():
            prompt_label = Gtk.Label(label=self._prompt_text.strip())
            prompt_label.add_css_class("caption")
            prompt_label.set_wrap(True)
            prompt_label.set_halign(Gtk.Align.START)
            box.append(prompt_label)

        prefs_group = Adw.PreferencesGroup()
        # EntryRow (не PasswordEntryRow) — 2FA коды принято видеть при вводе
        code_row = Adw.EntryRow(title="Authentication Code")
        code_row.set_input_purpose(Gtk.InputPurpose.DIGITS)
        prefs_group.add(code_row)
        box.append(prefs_group)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        # Читаем значение ДО close() — паттерн из PasswordDialog
        cancel_btn.connect("clicked", lambda _b: (dialog.close(), callback(None)))
        btn_box.append(cancel_btn)

        ok_btn = Gtk.Button(label="Authenticate")
        ok_btn.add_css_class("suggested-action")
        ok_btn.connect(
            "clicked",
            lambda _b: (
                callback(code_row.get_text().strip() or None),
                dialog.close(),
            ),
        )
        btn_box.append(ok_btn)
        box.append(btn_box)
        return box


# ---------------------------------------------------------------------------
# Profile field validation helpers
# ---------------------------------------------------------------------------

_RE_HOSTNAME = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$')
_RE_BASE32 = re.compile(r'^[A-Z2-7]+=*$')


def _clean_server(raw: str) -> str:
    """Strip URL scheme and trailing path/slash from a server string.

    Converts ``https://vpn.example.com/`` → ``vpn.example.com`` so the
    raw value is safe to pass to ``snx -s``.
    """
    value = raw.strip()
    for scheme in ("https://", "http://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme):]
    # Drop any trailing path component (e.g. /vpn or /).
    value = value.split("/")[0].strip()
    return value


def _validate_server(server: str) -> Optional[str]:
    """Return an error string if *server* is not a valid hostname/IP, else None."""
    if not server:
        return "Server hostname is required."
    if " " in server:
        return "Server hostname must not contain spaces."
    if not _RE_HOSTNAME.match(server):
        return "Invalid server hostname — use a valid hostname or IP address."
    return None


def _validate_username(username: str) -> Optional[str]:
    """Return an error string if *username* is invalid, else None."""
    if not username:
        return "Username is required."
    if " " in username:
        return "Username must not contain spaces."
    return None


def _validate_totp_secret(secret: str) -> Optional[str]:
    """Return an error string if *secret* is not valid Base32, else None."""
    normalised = secret.upper().replace(" ", "")
    if not _RE_BASE32.match(normalised):
        return "TOTP secret must be a valid Base32 string (A–Z, 2–7)."
    return None


# ---------------------------------------------------------------------------
# ProfileDialog
# ---------------------------------------------------------------------------


class ProfileDialog:
    """Modal dialog for creating or editing a connection profile.

    Args:
        profile: Existing profile to edit, or None to create a new one.
        callback: Called with (profile, totp_secret) or (None, None) on cancel.
            The second argument is the new TOTP secret string if entered, or None.
    """

    def __init__(
        self,
        profile: Optional["Profile"],
        callback: Callable[[Optional["Profile"], Optional[str]], None],
    ) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for ProfileDialog.")

        self._profile = profile
        self._callback = callback

    def show(self, parent: object = None) -> None:
        """Present the profile editor dialog."""
        is_new = self._profile is None
        dialog = Adw.Window(title="Add Profile" if is_new else "Edit Profile")
        dialog.set_modal(True)
        dialog.set_resizable(True)
        dialog.set_default_size(480, 580)
        if parent is not None:
            dialog.set_transient_for(parent)
        # Store window reference so sub-dialogs (e.g. Discover picker) can
        # use it as parent for transient positioning.
        self._dialog_window: object = dialog

        scroll, rows = self._build_form_rows()
        action_area = self._build_action_area(dialog, is_new, rows)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.set_vexpand(True)
        outer.append(scroll)
        outer.append(action_area)

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        toolbar_view.set_content(outer)
        dialog.set_content(toolbar_view)
        dialog.present()

    def _build_form_rows(self) -> "tuple[Gtk.ScrolledWindow, dict]":
        """Build the scrolled form and return (scroll, rows_dict).

        Uses separate ``Adw.PreferencesGroup`` objects for the username and
        certificate sections so that hiding/showing an entire group is
        reliable across all Libadwaita versions (toggling visibility on
        individual rows inside a group can be unreliable).
        """
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)

        prefs_page = Adw.PreferencesPage()
        scroll.set_child(prefs_page)

        p = self._profile

        # ── Group 1: identity + auth selector (always visible) ──────────
        group = Adw.PreferencesGroup(title="Profile Details")
        prefs_page.add(group)

        name_row = Adw.EntryRow(title="Profile Name")
        name_row.set_text(p.name if p else "")
        group.add(name_row)

        server_row = Adw.EntryRow(title="Server (hostname)")
        server_row.set_text(p.server if p else "")
        group.add(server_row)

        _cert_initially = bool(p and p.certificate)
        auth_model = Gtk.StringList()
        auth_model.append("Username / Password")
        auth_model.append("Certificate File")
        auth_mode_row = Adw.ComboRow(title="Authentication")
        auth_mode_row.set_model(auth_model)
        auth_mode_row.set_selected(1 if _cert_initially else 0)
        group.add(auth_mode_row)

        # ── Group 2: username / password fields (hidden in cert mode) ───
        user_group = Adw.PreferencesGroup()
        prefs_page.add(user_group)

        user_row = Adw.EntryRow(title="Username")
        user_row.set_text(p.username if p else "")
        user_group.add(user_row)

        domain_row = Adw.EntryRow(title="Windows Domain (optional)")
        domain_row.set_text(p.domain or "" if p else "")
        user_group.add(domain_row)

        # ── Group 3: connection settings (always visible) ────────────────
        conn_group = Adw.PreferencesGroup()
        prefs_page.add(conn_group)

        port_row = Adw.SpinRow.new_with_range(1, 65535, 1)
        port_row.set_title("SSL Port")
        port_row.set_value(p.ssl_port if p else 443)
        conn_group.add(port_row)

        ca_row = Adw.EntryRow(title="CA Certificates Path")
        ca_row.set_text(p.ca_list if p else "/etc/ssl/certs")
        conn_group.add(ca_row)

        # ── Group 4: certificate auth field (hidden in user mode) ────────
        cert_group = Adw.PreferencesGroup()
        prefs_page.add(cert_group)

        cert_row = Adw.EntryRow(title="Certificate File Path")
        cert_row.set_text(p.certificate or "" if p else "")
        cert_group.add(cert_row)

        # Save-password belongs with user-auth section.
        save_pwd_row = Adw.SwitchRow(title="Save Password in Keyring")
        save_pwd_row.set_active(p.save_password if p else False)
        user_group.add(save_pwd_row)

        def _on_auth_mode_changed(combo: object, _param: object) -> None:
            cert_mode = combo.get_selected() == 1  # type: ignore[union-attr]
            user_group.set_visible(not cert_mode)
            cert_group.set_visible(cert_mode)

        auth_mode_row.connect("notify::selected", _on_auth_mode_changed)
        _on_auth_mode_changed(auth_mode_row, None)  # apply initial state

        tunnel_row, esp_row, ike_row = self._build_tunnel_group(prefs_page)

        cur_method_idx = 0
        if p and p.two_factor_method.value in _2FA_METHOD_VALUES:
            cur_method_idx = _2FA_METHOD_VALUES.index(p.two_factor_method.value)
        method_row, totp_row, save_totp_row = (
            self._build_2fa_group(prefs_page, cur_method_idx)
        )

        ignore_cert_row = self._build_backend_group(prefs_page)

        rows = {
            "name": name_row, "server": server_row, "auth_mode": auth_mode_row,
            "user": user_row, "domain": domain_row,
            "port": port_row, "ca": ca_row, "cert": cert_row,
            "save_pwd": save_pwd_row,
            "tunnel": tunnel_row, "esp": esp_row, "ike": ike_row,
            "2fa_method": method_row, "totp_secret": totp_row, "save_totp": save_totp_row,
            "ignore_server_cert": ignore_cert_row,
        }
        return scroll, rows

    def _build_tunnel_group(
        self, prefs_page: object
    ) -> "tuple[object, object, object]":
        """Build Tunnel Type group with conditional ESP/IKE fields.

        Returns:
            Tuple of (tunnel_row, esp_row, ike_row).
        """
        from snxui.core.types import TunnelType

        p = self._profile

        tunnel_group = Adw.PreferencesGroup(title="Connection Mode")
        prefs_page.add(tunnel_group)

        tunnel_model = Gtk.StringList()
        tunnel_model.append("SSL (default)")
        tunnel_model.append("IPSec / ESP (not yet supported)")
        tunnel_row = Adw.ComboRow(
            title="Tunnel Type",
            subtitle="IPSec is not yet implemented in the Python SSL backend",
            model=tunnel_model,
        )
        # Always force SSL — IPSec not implemented; lock to index 0.
        tunnel_row.set_selected(0)
        tunnel_row.set_sensitive(False)
        tunnel_group.add(tunnel_row)

        # IPSec-specific parameters — hidden until IPSec is implemented.
        ipsec_group = Adw.PreferencesGroup()
        prefs_page.add(ipsec_group)

        esp_row = Adw.EntryRow(title="ESP Algorithm (e.g. aes256-sha256)")
        esp_row.set_text(p.esp_settings or "" if p else "")
        ipsec_group.add(esp_row)

        ike_row = Adw.EntryRow(title="IKE Proposal (e.g. aes256-sha256-modp2048)")
        ike_row.set_text(p.ike_settings or "" if p else "")
        ipsec_group.add(ike_row)

        def _on_tunnel_changed(combo: object, _param: object) -> None:
            ipsec_group.set_visible(combo.get_selected() == 1)  # type: ignore[union-attr]

        tunnel_row.connect("notify::selected", _on_tunnel_changed)
        _on_tunnel_changed(tunnel_row, None)  # apply initial state

        return tunnel_row, esp_row, ike_row

    def _build_2fa_group(
        self, prefs_page: object, cur_method_idx: int
    ) -> "tuple[object, object, object]":
        """Build the Two-Factor Authentication group and add it to *prefs_page*.

        Args:
            prefs_page: The Adw.PreferencesPage to add the group to.
            cur_method_idx: Index of the currently selected 2FA method.

        Returns:
            Tuple of (method_row, totp_row, save_totp_row).
        """
        tfa_group = Adw.PreferencesGroup(title="Two-Factor Authentication")
        prefs_page.add(tfa_group)

        method_model = Gtk.StringList()
        for label in _2FA_METHOD_LABELS:
            method_model.append(label)
        method_row = Adw.ComboRow(title="2FA Method", model=method_model)
        method_row.set_selected(cur_method_idx)
        tfa_group.add(method_row)

        p = self._profile
        totp_row = Adw.PasswordEntryRow(title="TOTP Secret (Base32, optional)")
        # Do not pre-fill with stored secret — only accept new input here.
        totp_row.set_visible(cur_method_idx in (1, 2))  # TOTP / HOTP
        tfa_group.add(totp_row)

        save_totp_row = Adw.SwitchRow(title="Save TOTP Secret in Keyring")
        save_totp_row.set_active(p.save_totp_secret if p else False)
        save_totp_row.set_visible(cur_method_idx in (1, 2))
        tfa_group.add(save_totp_row)

        def _on_method_changed(row: object, _param: object) -> None:
            is_totp = method_row.get_selected() in (1, 2)
            totp_row.set_visible(is_totp)
            save_totp_row.set_visible(is_totp)
        method_row.connect("notify::selected", _on_method_changed)

        return method_row, totp_row, save_totp_row

    def _build_backend_group(self, prefs_page: object) -> object:
        """Build the Connection Options group and add it to *prefs_page*.

        The python_ssl backend is the only supported backend, so backend and
        transport selection are no longer shown.  Only the certificate
        verification toggle remains.

        Args:
            prefs_page: The Adw.PreferencesPage to add the group to.

        Returns:
            The ``ignore_cert_row`` SwitchRow.
        """
        p = self._profile

        options_group = Adw.PreferencesGroup(title="Connection Options")
        prefs_page.add(options_group)

        ignore_cert_row = Adw.SwitchRow(
            title="Ignore Server Certificate",
            subtitle="Skip TLS certificate verification (use only for testing)",
        )
        ignore_cert_row.set_active(bool(p.ignore_server_cert) if p else False)
        options_group.add(ignore_cert_row)

        return ignore_cert_row

    def _build_action_area(
        self, dialog: object, is_new: bool, rows: "dict[str, object]"
    ) -> "Gtk.Box":
        """Build the error label + button row beneath the form."""
        error_label = Gtk.Label(label="")
        error_label.add_css_class("error")
        error_label.set_margin_top(4)
        error_label.set_margin_bottom(4)
        error_label.set_margin_start(16)
        error_label.set_halign(Gtk.Align.START)
        error_label.set_visible(False)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_margin_top(12)
        btn_box.set_margin_bottom(16)
        btn_box.set_margin_start(16)
        btn_box.set_margin_end(16)
        btn_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _b: (dialog.close(), self._callback(None, None)))
        btn_box.append(cancel_btn)
        btn_box.append(self._build_save_button(dialog, is_new, rows, error_label))

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.append(error_label)
        outer.append(btn_box)
        return outer

    def _build_save_button(
        self,
        dialog: object,
        is_new: bool,
        rows: "dict[str, object]",
        error_label: object,
    ) -> "Gtk.Button":
        """Build the Add/Save button with its on-save handler."""
        save_btn = Gtk.Button(label="Add" if is_new else "Save")
        save_btn.add_css_class("suggested-action")

        def _on_save(_btn: object) -> None:
            raw_server = rows["server"].get_text()
            server = _clean_server(raw_server)
            username = rows["user"].get_text().strip()
            certificate = rows["cert"].get_text().strip()

            cert_mode = rows["auth_mode"].get_selected() == 1
            err = _validate_server(server)
            if err is None:
                if cert_mode:
                    if not certificate:
                        err = "Certificate file path is required."
                else:
                    err = _validate_username(username)
            if err is None:
                # Validate TOTP secret only when a secret was entered.
                method_idx = rows["2fa_method"].get_selected()
                totp_text = rows["totp_secret"].get_text().strip()
                if method_idx in (1, 2) and totp_text:
                    err = _validate_totp_secret(totp_text)

            if err:
                error_label.set_label(err)
                error_label.set_visible(True)
                return

            # Reflect the cleaned server value back into the widget so the
            # user sees the normalised form (e.g. scheme stripped).
            if server != raw_server.strip():
                rows["server"].set_text(server)

            error_label.set_visible(False)
            # Read ALL widget values BEFORE closing.  dialog.close() schedules
            # widget destruction; reading after is fragile.  Same rule as
            # PasswordDialog.
            profile, totp_secret = self._collect_profile_from_rows(
                rows, server, username
            )
            dialog.close()
            self._callback(profile, totp_secret)

        save_btn.connect("clicked", _on_save)
        return save_btn

    def _collect_profile_from_rows(
        self,
        rows: "dict[str, object]",
        server: str,
        username: str,
    ) -> "tuple[object, Optional[str]]":
        """Read all form widget values and construct a :class:`Profile`.

        Args:
            rows: Widget dict from :meth:`_build_form_rows`.
            server: Pre-read server string (validated by caller).
            username: Pre-read username string (validated by caller).

        Returns:
            Tuple of ``(Profile, totp_secret)`` where *totp_secret* is the
            new TOTP secret entered by the user, or ``None``.
        """
        from snxui.core.types import Profile, TunnelType, TwoFactorMethod  # noqa: PLC0415

        cert_mode = rows["auth_mode"].get_selected() == 1
        cert_text = rows["cert"].get_text().strip() or None
        domain_text = rows["domain"].get_text().strip() or None
        method_idx = rows["2fa_method"].get_selected()
        two_factor_method = TwoFactorMethod(_2FA_METHOD_VALUES[method_idx])
        totp_secret: Optional[str] = rows["totp_secret"].get_text().strip() or None
        ipsec_mode = rows["tunnel"].get_selected() == 1
        tunnel_type = TunnelType.IPSEC if ipsec_mode else TunnelType.SSL

        profile = Profile(
            id=self._profile.id if self._profile else str(uuid.uuid4()),
            name=rows["name"].get_text().strip(),
            server=server,
            username="" if cert_mode else username,
            domain=None if cert_mode else domain_text,
            ssl_port=int(rows["port"].get_value()),
            ca_list=rows["ca"].get_text().strip(),
            certificate=cert_text if cert_mode else None,
            save_password=False if cert_mode else rows["save_pwd"].get_active(),
            two_factor_method=two_factor_method,
            save_totp_secret=rows["save_totp"].get_active(),
            combined_auth=False,
            portal_auth=False,
            ccc_only_auth=False,
            tunnel_type=tunnel_type,
            esp_settings=rows["esp"].get_text().strip() or None if ipsec_mode else None,
            ike_settings=rows["ike"].get_text().strip() or None if ipsec_mode else None,
            backend="python_ssl",
            login_type=self._profile.login_type if self._profile else "",
            transport_type="auto",
            ignore_server_cert=rows["ignore_server_cert"].get_active(),
        )
        return profile, totp_secret


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
            version=__version__,
            comments="GUI client for Check Point SNX VPN",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/ikeniborn/snxui",
            issue_url="https://github.com/ikeniborn/snxui/issues",
        )

        dialog.present(parent)
