"""Profiles page — list, add, edit and delete connection profiles.

Layout:
    Adw.PreferencesPage
      Adw.PreferencesGroup "Connection Profiles"
        [Adw.ActionRow per profile]
          title: profile.name
          subtitle: username@server
          suffix: Edit button, Delete button
      [Add Profile button row]
"""

from __future__ import annotations

import logging
from typing import Callable, TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from snxui.core import ProfileManager, CredentialStore
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
    logger.warning("GTK4/Libadwaita not available — ProfilesPage will not function.")


class ProfilesPage:
    """Profile management page.

    Args:
        profile_manager: CRUD service for profiles.
        credential_store: Optional keyring store.  When provided, the stored
            password is deleted together with the profile so no orphaned
            keyring entries are left behind.
    """

    def __init__(
        self,
        *,
        profile_manager: "ProfileManager",
        credential_store: Optional["CredentialStore"] = None,
    ) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for ProfilesPage.")

        self._pm = profile_manager
        self._cs = credential_store
        self._on_profiles_changed: Optional[Callable[[], None]] = None
        self._build_widget()
        self.refresh()

    def set_on_profiles_changed(self, callback: Callable[[], None]) -> None:
        """Register a callback invoked after any create/update/delete."""
        self._on_profiles_changed = callback

    def _notify_profiles_changed(self) -> None:
        if self._on_profiles_changed is not None:
            try:
                self._on_profiles_changed()
            except Exception:
                logger.exception("profiles_changed callback raised.")

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _build_widget(self) -> None:
        self._page = Adw.PreferencesPage()

        # Profiles group.
        self._group = Adw.PreferencesGroup(title="Connection Profiles")
        self._page.add(self._group)

        # "Add profile" button group.
        add_group = Adw.PreferencesGroup()
        self._page.add(add_group)

        add_row = Adw.ActionRow(title="Add Profile")
        add_row.set_activatable(True)
        add_row.connect("activated", self._on_add)
        add_icon = Gtk.Image.new_from_icon_name("list-add-symbolic")
        add_row.add_prefix(add_icon)
        add_group.add(add_row)

    @property
    def widget(self) -> "Adw.PreferencesPage":
        return self._page

    # ------------------------------------------------------------------
    # List management
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload profiles from the manager and rebuild the list."""
        # Remove old rows from the group.
        # Adw.PreferencesGroup doesn't have a clear() method, so we track rows.
        for row in getattr(self, "_profile_rows", []):
            self._group.remove(row)
        self._profile_rows: list["Adw.ActionRow"] = []

        try:
            profiles = self._pm.list_all()
        except Exception:
            logger.exception("Failed to list profiles.")
            profiles = []

        if not profiles:
            placeholder = Adw.ActionRow(
                title="No profiles yet",
                subtitle="Tap 'Add Profile' below to create one.",
            )
            self._group.add(placeholder)
            self._profile_rows.append(placeholder)
            return

        for profile in profiles:
            row = self._make_row(profile)
            self._group.add(row)
            self._profile_rows.append(row)

    def _make_row(self, profile: "Profile") -> "Adw.ActionRow":
        """Build an ActionRow for a single profile."""
        login = f"{profile.domain}\\{profile.username}" if profile.domain else profile.username
        row = Adw.ActionRow(
            title=profile.name or "(unnamed)",
            subtitle=f"{login} · {profile.server}",
        )

        # Edit button.
        edit_btn = Gtk.Button.new_from_icon_name("document-edit-symbolic")
        edit_btn.set_valign(Gtk.Align.CENTER)
        edit_btn.add_css_class("flat")
        edit_btn.set_tooltip_text("Edit profile")
        edit_btn.connect("clicked", lambda _b, p=profile: self._on_edit(p))
        row.add_suffix(edit_btn)

        # Delete button.
        del_btn = Gtk.Button.new_from_icon_name("user-trash-symbolic")
        del_btn.set_valign(Gtk.Align.CENTER)
        del_btn.add_css_class("flat")
        del_btn.add_css_class("destructive-action")
        del_btn.set_tooltip_text("Delete profile")
        del_btn.connect("clicked", lambda _b, p=profile: self._on_delete(p))
        row.add_suffix(del_btn)

        # Double-click (activate) also opens edit.
        row.set_activatable(True)
        row.connect("activated", lambda _r, p=profile: self._on_edit(p))

        return row

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_add(self, *_args: object) -> None:
        from snxui.ui.dialogs import ProfileDialog

        def _on_saved(profile: Optional["Profile"], totp_secret: Optional[str]) -> None:
            if profile is None:
                return
            if totp_secret is not None and self._cs is not None:
                try:
                    self._cs.set_totp_secret(profile.id, totp_secret)
                except Exception as exc:
                    logger.warning("Failed to save TOTP secret: %s", exc)
            try:
                self._pm.create(profile)
            except Exception as exc:
                logger.error("Failed to create profile: %s", exc)
            self.refresh()
            self._notify_profiles_changed()

        ProfileDialog(profile=None, callback=_on_saved).show(self._page.get_root())

    def _on_edit(self, profile: "Profile") -> None:
        from snxui.ui.dialogs import ProfileDialog

        def _on_saved(updated: Optional["Profile"], totp_secret: Optional[str]) -> None:
            if updated is None:
                return
            if totp_secret is not None and self._cs is not None:
                try:
                    self._cs.set_totp_secret(updated.id, totp_secret)
                except Exception as exc:
                    logger.warning("Failed to save TOTP secret: %s", exc)
            try:
                self._pm.update(updated)
            except Exception as exc:
                logger.error("Failed to update profile: %s", exc)
            self.refresh()
            self._notify_profiles_changed()

        ProfileDialog(profile=profile, callback=_on_saved).show(self._page.get_root())

    def _on_delete(self, profile: "Profile") -> None:
        """Show a confirmation dialog before deleting."""
        dialog = Adw.AlertDialog(
            heading="Delete Profile?",
            body=f"Profile '{profile.name or profile.server}' will be permanently removed.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def _on_response(d: object, response: str) -> None:
            if response == "delete":
                try:
                    self._pm.delete(profile.id)
                except Exception as exc:
                    logger.error("Failed to delete profile: %s", exc)
                # Remove the stored password so no orphaned keyring entry
                # is left behind after the profile is deleted.
                if self._cs is not None:
                    try:
                        self._cs.delete_password(profile.id)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Failed to delete password for profile %s: %s",
                            profile.id,
                            exc,
                        )
                    try:
                        self._cs.delete_totp_secret(profile.id)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Failed to delete TOTP secret for profile %s: %s",
                            profile.id,
                            exc,
                        )
                self.refresh()
                self._notify_profiles_changed()

        dialog.connect("response", _on_response)
        # Present relative to the page's root window if possible.
        try:
            parent_win = self._page.get_root()
            dialog.present(parent_win)
        except Exception:
            dialog.present(None)
