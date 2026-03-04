"""TrafficMonitor — периодическое чтение /proc/net/dev для отображения
входящего/исходящего трафика и скорости VPN-соединения.

Использует GLib.timeout_add (3 с) в главном потоке GTK — не нужен lock,
не нужен threading.Event. Данные передаются через callback.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Интерфейсы VPN-туннеля (SNX binary / snx-rs)
_IFACE_CANDIDATES = ("tunsnx", "tunsnx0")

# Интервал опроса в миллисекундах
_POLL_INTERVAL_MS = 3000

# Callback: (rx_bps, tx_bps, rx_total, tx_total)
TrafficCallback = Callable[[float, float, int, int], None]


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------


def _read_iface_bytes(iface: str) -> Optional[tuple[int, int]]:
    """Прочитать RX/TX счётчики байт из /proc/net/dev для заданного интерфейса.

    Args:
        iface: Имя сетевого интерфейса (например ``tunsnx``).

    Returns:
        ``(rx_bytes, tx_bytes)`` или ``None`` если интерфейс не найден.
    """
    try:
        with open("/proc/net/dev", "r", encoding="ascii") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith(iface + ":"):
                    # Формат: "tunsnx:  RX_BYTES packets errs ... TX_BYTES ..."
                    # Разбираем всё после двоеточия
                    parts = stripped.split(":", 1)[1].split()
                    if len(parts) >= 9:
                        return int(parts[0]), int(parts[8])
    except OSError:
        logger.debug("TrafficMonitor: не удалось прочитать /proc/net/dev")
    return None


def format_speed(bps: float) -> str:
    """Форматировать скорость в байтах/с в удобочитаемый вид.

    Args:
        bps: Скорость в байтах в секунду.

    Returns:
        Строка вида ``"2.4 MB/s"``, ``"320 KB/s"``, ``"500 B/s"``.

    Examples:
        >>> format_speed(0)
        '0 B/s'
        >>> format_speed(1_500_000)
        '1.4 MB/s'
    """
    if bps >= 1_073_741_824:  # >= 1 GB/s
        return f"{bps / 1_073_741_824:.1f} GB/s"
    if bps >= 1_048_576:  # >= 1 MB/s
        return f"{bps / 1_048_576:.1f} MB/s"
    if bps >= 1024:  # >= 1 KB/s
        return f"{bps / 1024:.0f} KB/s"
    return f"{int(bps)} B/s"


def format_bytes(total: int) -> str:
    """Форматировать суммарный объём трафика в удобочитаемый вид.

    Args:
        total: Количество байт.

    Returns:
        Строка вида ``"145 MB"``, ``"1.2 GB"``, ``"512 KB"``.

    Examples:
        >>> format_bytes(0)
        '0 B'
        >>> format_bytes(1_500_000_000)
        '1.4 GB'
    """
    if total >= 1_073_741_824:
        return f"{total / 1_073_741_824:.1f} GB"
    if total >= 1_048_576:
        return f"{total / 1_048_576:.0f} MB"
    if total >= 1024:
        return f"{total / 1024:.0f} KB"
    return f"{total} B"


# ---------------------------------------------------------------------------
# TrafficMonitor
# ---------------------------------------------------------------------------


class TrafficMonitor:
    """Периодически опрашивает /proc/net/dev и сообщает о скорости/объёме.

    Работает через GLib.timeout_add — вызовы выполняются в GTK main thread,
    что исключает необходимость в дополнительной синхронизации.

    Args:
        callback: Вызывается каждые ~3 с с аргументами
            ``(rx_bps, tx_bps, rx_total_from_start, tx_total_from_start)``.
    """

    def __init__(self, callback: TrafficCallback) -> None:
        self._callback = callback
        self._timer_id: Optional[int] = None
        self._iface: str = _IFACE_CANDIDATES[0]
        self._prev_rx: Optional[int] = None
        self._prev_tx: Optional[int] = None
        self._prev_time: Optional[float] = None
        self._base_rx: int = 0
        self._base_tx: int = 0

    def start(self, iface: str = "tunsnx") -> None:
        """Запустить периодический опрос /proc/net/dev.

        Если ``iface`` не найден в /proc/net/dev, будет проверен список
        кандидатов ``_IFACE_CANDIDATES``. Безопасен при повторном вызове
        (останавливает предыдущий таймер).

        Args:
            iface: Имя VPN-интерфейса.
        """
        self.stop()

        # Проверяем переданный интерфейс, потом кандидатов по умолчанию
        resolved = self._resolve_iface(iface)
        if resolved is None:
            logger.debug(
                "TrafficMonitor: интерфейс %r не найден в /proc/net/dev, "
                "мониторинг трафика отключён.",
                iface,
            )
            return

        self._iface = resolved
        self._prev_rx = None
        self._prev_tx = None
        self._prev_time = None
        self._base_rx = 0
        self._base_tx = 0

        # Инициализируем базовые счётчики
        counts = _read_iface_bytes(self._iface)
        if counts is not None:
            self._base_rx, self._base_tx = counts
            self._prev_rx, self._prev_tx = counts
            self._prev_time = time.monotonic()

        try:
            from gi.repository import GLib
            self._timer_id = GLib.timeout_add(
                _POLL_INTERVAL_MS, self._tick
            )
            logger.debug(
                "TrafficMonitor: запущен для %r (timer_id=%d)",
                self._iface,
                self._timer_id,
            )
        except Exception:
            logger.debug("TrafficMonitor: GLib недоступен, таймер не запущен")

    def stop(self) -> None:
        """Остановить таймер опроса. Безопасен при повторном вызове."""
        if self._timer_id is not None:
            try:
                from gi.repository import GLib
                GLib.source_remove(self._timer_id)
            except Exception:
                logger.debug("TrafficMonitor: не удалось снять таймер %d", self._timer_id)
            self._timer_id = None
            logger.debug("TrafficMonitor: остановлен")

    def _tick(self) -> bool:
        """Один тик таймера — читает счётчики, вызывает callback.

        Returns:
            ``GLib.SOURCE_CONTINUE`` (True) чтобы таймер продолжался,
            или ``GLib.SOURCE_REMOVE`` (False) чтобы остановить.
        """
        try:
            from gi.repository import GLib
            SOURCE_CONTINUE: bool = bool(GLib.SOURCE_CONTINUE)
            SOURCE_REMOVE: bool = bool(GLib.SOURCE_REMOVE)
        except Exception:
            SOURCE_CONTINUE = True
            SOURCE_REMOVE = False

        counts = _read_iface_bytes(self._iface)
        if counts is None:
            # Интерфейс пропал — VPN отключился
            logger.debug(
                "TrafficMonitor: интерфейс %r исчез, останавливаем мониторинг",
                self._iface,
            )
            self._timer_id = None
            return SOURCE_REMOVE

        rx_now, tx_now = counts
        now = time.monotonic()

        # Первый тик — нет предыдущих данных
        if self._prev_rx is None or self._prev_time is None:
            self._prev_rx, self._prev_tx = rx_now, tx_now
            self._prev_time = now
            return SOURCE_CONTINUE

        delta_t = now - self._prev_time
        if delta_t <= 0:
            return SOURCE_CONTINUE

        rx_delta = max(0, rx_now - self._prev_rx)
        tx_delta = max(0, tx_now - (self._prev_tx or 0))

        rx_bps = rx_delta / delta_t
        tx_bps = tx_delta / delta_t

        rx_total = max(0, rx_now - self._base_rx)
        tx_total = max(0, tx_now - self._base_tx)

        self._prev_rx = rx_now
        self._prev_tx = tx_now
        self._prev_time = now

        try:
            self._callback(rx_bps, tx_bps, rx_total, tx_total)
        except Exception:
            logger.exception("TrafficMonitor: ошибка в callback")

        return SOURCE_CONTINUE

    @staticmethod
    def _resolve_iface(iface: str) -> Optional[str]:
        """Найти первый доступный интерфейс в /proc/net/dev.

        Проверяет сначала ``iface``, затем список кандидатов.
        """
        candidates = [iface] + [c for c in _IFACE_CANDIDATES if c != iface]
        for candidate in candidates:
            if _read_iface_bytes(candidate) is not None:
                return candidate
        return None
