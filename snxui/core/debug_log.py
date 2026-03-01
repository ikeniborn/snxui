"""In-process debug log buffer shared between the core and GUI layers.

:class:`GtkDebugHandler` is a standard :class:`logging.Handler` that stores
entries in a bounded ring-buffer and notifies an optional GUI callback on each
new entry.  The callback is invoked on the *calling* thread; it is the
callback's responsibility to marshal UI updates to the GTK main thread (e.g.
via ``GLib.idle_add``).

Usage::

    from snxui.core.debug_log import install
    install()                         # attach to "snxui" logger once at startup

    # In the GUI layer:
    from snxui.core.debug_log import get_handler
    get_handler().set_callback(debug_window.on_new_entry)
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional


_MAX_HISTORY = 2000


@dataclass
class LogEntry:
    """One formatted log line with its severity level."""

    text: str
    levelno: int = logging.INFO


class GtkDebugHandler(logging.Handler):
    """Logging handler that stores entries in a ring buffer.

    Thread-safe: ``emit()`` acquires the handler's built-in lock so that
    concurrent calls from the SNX background thread and the GTK main thread
    do not corrupt the history deque.
    """

    def __init__(self, maxlen: int = _MAX_HISTORY) -> None:
        super().__init__(level=logging.DEBUG)
        self._history: deque[LogEntry] = deque(maxlen=maxlen)
        self._callback: Optional[Callable[[LogEntry], None]] = None
        self.setFormatter(
            logging.Formatter(
                "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = self.format(record)
            entry = LogEntry(text=text, levelno=record.levelno)
            self.acquire()
            try:
                self._history.append(entry)
                cb = self._callback
            finally:
                self.release()
            if cb is not None:
                try:
                    cb(entry)
                except Exception:
                    pass
        except Exception:
            self.handleError(record)

    def set_callback(self, cb: Optional[Callable[[LogEntry], None]]) -> None:
        """Register (or clear) a GUI callback invoked on each new entry."""
        self.acquire()
        try:
            self._callback = cb
        finally:
            self.release()

    def get_history(self) -> list[LogEntry]:
        """Return a snapshot of the current history (newest last)."""
        self.acquire()
        try:
            return list(self._history)
        finally:
            self.release()

    def clear_history(self) -> None:
        """Discard all buffered entries."""
        self.acquire()
        try:
            self._history.clear()
        finally:
            self.release()


_handler: Optional[GtkDebugHandler] = None


def get_handler() -> GtkDebugHandler:
    """Return (creating if necessary) the process-wide singleton handler."""
    global _handler
    if _handler is None:
        _handler = GtkDebugHandler()
    return _handler


def install(logger_name: str = "snxui") -> GtkDebugHandler:
    """Attach the debug handler to *logger_name* and return it.

    Safe to call multiple times — the handler is only added once.
    The named logger's effective level is lowered to DEBUG so that
    DEBUG-level messages reach the handler even when the root logger
    is set to INFO.
    """
    h = get_handler()
    log = logging.getLogger(logger_name)
    if h not in log.handlers:
        log.addHandler(h)
    if log.level == logging.NOTSET or log.level > logging.DEBUG:
        log.setLevel(logging.DEBUG)
    return h
