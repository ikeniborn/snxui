"""Debug log window — live stream of snxui logging output.

Opens a persistent, non-modal window with a scrollable monospace text view.
Log entries from all ``snxui.*`` loggers are coloured by severity and appended
in real time via :class:`snxui.core.debug_log.GtkDebugHandler`.

Typical use::

    from snxui.ui.debug_window import DebugWindow
    DebugWindow.show_or_raise(parent=main_win)
"""

from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from snxui.core.debug_log import LogEntry

logger = logging.getLogger(__name__)

try:
    import gi

    gi.require_version("Adw", "1")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Adw, Gtk, GLib, Gdk, Pango

    _GTK_AVAILABLE = True
except (ImportError, ValueError):
    Adw = Gtk = GLib = Gdk = Pango = None  # type: ignore[assignment]
    _GTK_AVAILABLE = False


def _levelno_to_tag(levelno: int) -> str:
    if levelno >= logging.CRITICAL:
        return "critical"
    if levelno >= logging.ERROR:
        return "error"
    if levelno >= logging.WARNING:
        return "warning"
    if levelno >= logging.INFO:
        return "info"
    return "debug"


class DebugWindow:
    """Non-modal window showing real-time SNX log output.

    Only one instance may exist at a time.  Call :meth:`show_or_raise` to
    open or bring forward the window.
    """

    _instance: Optional["DebugWindow"] = None

    def __init__(self) -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for DebugWindow.")
        self._win: Optional[object] = None
        self._text_buffer: Optional[object] = None
        self._scrolled: Optional[object] = None
        self._auto_scroll: bool = True

    @classmethod
    def show_or_raise(cls, parent: object = None) -> "DebugWindow":
        """Open the debug window or raise it if already open."""
        if cls._instance is None:
            cls._instance = cls()
        cls._instance._present(parent)
        return cls._instance

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def _present(self, parent: object = None) -> None:
        if self._win is None:
            self._build_window()
        self._load_history()
        if parent is not None:
            self._win.set_transient_for(parent)  # type: ignore[union-attr]
        self._win.present()  # type: ignore[union-attr]
        from snxui.core.debug_log import get_handler
        get_handler().set_callback(self._on_new_entry)

    def _build_window(self) -> None:
        self._win = Adw.Window(title="Debug Log")
        self._win.set_default_size(760, 500)
        self._win.set_resizable(True)
        self._win.connect("close-request", self._on_close_request)

        # ── Header bar ──────────────────────────────────────────────────
        header = Adw.HeaderBar()

        clear_btn = Gtk.Button(label="Clear")
        clear_btn.set_tooltip_text("Clear log buffer")
        clear_btn.connect("clicked", self._on_clear)
        header.pack_start(clear_btn)

        copy_btn = Gtk.Button()
        copy_btn.set_icon_name("edit-copy-symbolic")
        copy_btn.set_tooltip_text("Copy all entries to clipboard")
        copy_btn.connect("clicked", self._on_copy_all)
        header.pack_end(copy_btn)

        self._auto_scroll_btn = Gtk.ToggleButton(label="Auto-scroll")
        self._auto_scroll_btn.set_active(True)
        self._auto_scroll_btn.set_tooltip_text("Scroll to newest entry automatically")
        self._auto_scroll_btn.connect("toggled", self._on_auto_scroll_toggled)
        header.pack_end(self._auto_scroll_btn)

        # ── Text view ───────────────────────────────────────────────────
        self._text_buffer = Gtk.TextBuffer()
        self._setup_tags()

        text_view = Gtk.TextView(buffer=self._text_buffer)
        text_view.set_editable(False)
        text_view.set_cursor_visible(False)
        text_view.set_monospace(True)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        text_view.set_margin_top(6)
        text_view.set_margin_bottom(6)
        text_view.set_margin_start(10)
        text_view.set_margin_end(10)

        self._scrolled = Gtk.ScrolledWindow()
        self._scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self._scrolled.set_vexpand(True)
        self._scrolled.set_child(text_view)

        # ── Layout ──────────────────────────────────────────────────────
        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(header)
        toolbar_view.set_content(self._scrolled)
        self._win.set_content(toolbar_view)

    def _setup_tags(self) -> None:
        buf = self._text_buffer
        # Colours chosen for legibility on both light and dark system themes.
        buf.create_tag("debug",    foreground="#888888")
        buf.create_tag("info")                                         # default theme colour
        buf.create_tag("warning",  foreground="#E07800")
        buf.create_tag("error",    foreground="#CC3333",
                       weight=Pango.Weight.BOLD)
        buf.create_tag("critical", foreground="#BB0000",
                       weight=Pango.Weight.BOLD)

    # ------------------------------------------------------------------
    # Log display
    # ------------------------------------------------------------------

    def _load_history(self) -> None:
        """Populate the buffer with buffered history on window open."""
        if self._text_buffer is None:
            return
        self._text_buffer.set_text("")
        from snxui.core.debug_log import get_handler
        for entry in get_handler().get_history():
            self._append_entry(entry.text, entry.levelno)

    def _append_entry(self, text: str, levelno: int) -> bool:
        """Insert one log line (must run on the GTK main thread)."""
        if self._text_buffer is None:
            return False
        end = self._text_buffer.get_end_iter()
        tag = _levelno_to_tag(levelno)
        self._text_buffer.insert_with_tags_by_name(end, text + "\n", tag)
        if self._auto_scroll:
            self._scroll_to_end()
        return False  # GLib.idle_add compatibility

    def _scroll_to_end(self) -> None:
        if self._scrolled is None:
            return
        adj = self._scrolled.get_vadjustment()
        adj.set_value(adj.get_upper() - adj.get_page_size())

    # ------------------------------------------------------------------
    # Callback from GtkDebugHandler (may arrive from any thread)
    # ------------------------------------------------------------------

    def _on_new_entry(self, entry: "LogEntry") -> None:
        if self._text_buffer is None:
            return
        GLib.idle_add(self._append_entry, entry.text, entry.levelno)

    # ------------------------------------------------------------------
    # Button handlers
    # ------------------------------------------------------------------

    def _on_clear(self, _btn: object) -> None:
        from snxui.core.debug_log import get_handler
        get_handler().clear_history()
        if self._text_buffer is not None:
            self._text_buffer.set_text("")

    def _on_copy_all(self, _btn: object) -> None:
        if self._text_buffer is None:
            return
        start, end = self._text_buffer.get_bounds()
        text = self._text_buffer.get_text(start, end, False)
        display = Gdk.Display.get_default()
        if display is not None:
            display.get_clipboard().set(text)

    def _on_auto_scroll_toggled(self, btn: object) -> None:
        self._auto_scroll = btn.get_active()  # type: ignore[union-attr]
        if self._auto_scroll:
            self._scroll_to_end()

    def _on_close_request(self, _win: object) -> bool:
        from snxui.core.debug_log import get_handler
        get_handler().set_callback(None)
        self._win = None
        self._text_buffer = None
        self._scrolled = None
        DebugWindow._instance = None
        return False  # allow normal close
