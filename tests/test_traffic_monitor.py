"""Тесты для snxui.system.traffic_monitor."""

from __future__ import annotations

from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from snxui.system.traffic_monitor import (
    TrafficMonitor,
    _read_iface_bytes,
    format_bytes,
    format_speed,
)

# ---------------------------------------------------------------------------
# format_speed
# ---------------------------------------------------------------------------


class TestFormatSpeed:
    def test_zero(self) -> None:
        assert format_speed(0) == "0 B/s"

    def test_bytes(self) -> None:
        assert format_speed(500) == "500 B/s"

    def test_one_byte(self) -> None:
        assert format_speed(1) == "1 B/s"

    def test_kilobytes(self) -> None:
        result = format_speed(1024)
        assert "KB/s" in result

    def test_kilobytes_320(self) -> None:
        assert format_speed(327_680) == "320 KB/s"

    def test_megabytes(self) -> None:
        result = format_speed(2.4 * 1_048_576)
        assert "MB/s" in result
        assert "2.4" in result

    def test_megabytes_boundary(self) -> None:
        result = format_speed(1_048_576)
        assert result == "1.0 MB/s"

    def test_gigabytes(self) -> None:
        result = format_speed(2 * 1_073_741_824)
        assert "GB/s" in result
        assert "2.0" in result

    def test_just_below_kilobyte(self) -> None:
        result = format_speed(1023)
        assert "B/s" in result
        assert "KB" not in result


# ---------------------------------------------------------------------------
# format_bytes
# ---------------------------------------------------------------------------


class TestFormatBytes:
    def test_zero(self) -> None:
        assert format_bytes(0) == "0 B"

    def test_bytes(self) -> None:
        assert format_bytes(512) == "512 B"

    def test_kilobytes(self) -> None:
        assert format_bytes(2048) == "2 KB"

    def test_megabytes(self) -> None:
        assert format_bytes(145 * 1_048_576) == "145 MB"

    def test_gigabytes(self) -> None:
        result = format_bytes(1_500_000_000)
        assert "GB" in result

    def test_gigabyte_boundary(self) -> None:
        result = format_bytes(1_073_741_824)
        assert result == "1.0 GB"

    def test_just_below_megabyte(self) -> None:
        result = format_bytes(1_048_575)
        assert "KB" in result
        assert "MB" not in result


# ---------------------------------------------------------------------------
# _read_iface_bytes
# ---------------------------------------------------------------------------

_PROC_NET_DEV_CONTENT = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
 tunsnx:  987654    200    0    0    0     0          0         0   111222     150    0    0    0     0       0          0
   eth0:    5000      50    0    0    0     0          0         0     3000      30    0    0    0     0       0          0
"""


class TestReadIfaceBytes:
    def test_found(self) -> None:
        with patch("builtins.open") as mock_open:
            mock_open.return_value.__enter__ = lambda s: iter(
                _PROC_NET_DEV_CONTENT.splitlines(keepends=True)
            )
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            result = _read_iface_bytes("tunsnx")

        assert result == (987654, 111222)

    def test_not_found(self) -> None:
        with patch("builtins.open") as mock_open:
            mock_open.return_value.__enter__ = lambda s: iter(
                _PROC_NET_DEV_CONTENT.splitlines(keepends=True)
            )
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            result = _read_iface_bytes("nonexistent0")

        assert result is None

    def test_os_error(self) -> None:
        with patch("builtins.open", side_effect=OSError("No such file")):
            result = _read_iface_bytes("tunsnx")
        assert result is None

    def test_partial_iface_name_not_matched(self) -> None:
        """'tunsnx' must not match 'tunsnx0' and vice versa."""
        content = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
 tunsnx0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
"""
        with patch("builtins.open") as mock_open:
            mock_open.return_value.__enter__ = lambda s: iter(
                content.splitlines(keepends=True)
            )
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            result = _read_iface_bytes("tunsnx")
        assert result is None


# ---------------------------------------------------------------------------
# TrafficMonitor
# ---------------------------------------------------------------------------


class TestTrafficMonitorStopWithoutStart:
    def test_stop_without_start(self) -> None:
        """stop() не должен падать если таймер не был запущен."""
        monitor = TrafficMonitor(callback=lambda *a: None)
        monitor.stop()  # не должно быть исключения
        monitor.stop()  # повторный вызов тоже безопасен


class TestTrafficMonitorCallbackCalled:
    """Тест что callback вызывается при _tick() с корректными данными."""

    def test_tick_calls_callback(self) -> None:
        results: list[tuple] = []

        def callback(rx_bps: float, tx_bps: float, rx_total: int, tx_total: int) -> None:
            results.append((rx_bps, tx_bps, rx_total, tx_total))

        monitor = TrafficMonitor(callback=callback)
        monitor._iface = "tunsnx"
        # Имитируем первый тик: задаём предыдущие данные
        monitor._prev_rx = 1000
        monitor._prev_tx = 500
        import time
        monitor._prev_time = time.monotonic() - 3.0  # 3 секунды назад
        monitor._base_rx = 1000
        monitor._base_tx = 500

        # Имитируем чтение /proc/net/dev — новые значения выросли
        mock_counts = (4000, 2000)  # rx выросло на 3000, tx на 1500 за ~3s

        with patch(
            "snxui.system.traffic_monitor._read_iface_bytes",
            return_value=mock_counts,
        ):
            monitor._tick()

        # Callback должен быть вызван
        assert len(results) == 1
        rx_bps, tx_bps, rx_total, tx_total = results[0]
        # Скорость ~1000 B/s для rx, ~500 B/s для tx (3000/3, 1500/3)
        assert rx_bps == pytest.approx(1000.0, rel=0.1)
        assert tx_bps == pytest.approx(500.0, rel=0.1)
        # Суммарный трафик от базы: 4000-1000=3000, 2000-500=1500
        assert rx_total == 3000
        assert tx_total == 1500

    def test_tick_stops_when_iface_gone(self) -> None:
        """_tick() должен вернуть SOURCE_REMOVE если интерфейс пропал."""
        monitor = TrafficMonitor(callback=lambda *a: None)
        monitor._iface = "tunsnx"
        monitor._prev_rx = 1000
        monitor._prev_tx = 500
        import time
        monitor._prev_time = time.monotonic() - 1.0
        monitor._base_rx = 1000
        monitor._base_tx = 500

        with patch(
            "snxui.system.traffic_monitor._read_iface_bytes",
            return_value=None,
        ):
            monitor._tick()

        # Таймер должен быть сброшен
        assert monitor._timer_id is None

    def test_first_tick_no_callback(self) -> None:
        """Первый тик (нет prev данных) не вызывает callback."""
        results: list = []
        monitor = TrafficMonitor(callback=lambda *a: results.append(a))
        monitor._iface = "tunsnx"
        # prev_rx/prev_time = None → первый тик

        with patch(
            "snxui.system.traffic_monitor._read_iface_bytes",
            return_value=(1000, 500),
        ):
            monitor._tick()

        assert results == []

    def test_start_resolves_iface(self) -> None:
        """start() ищет первый доступный интерфейс из кандидатов."""
        monitor = TrafficMonitor(callback=lambda *a: None)

        def fake_read(iface: str) -> Optional[tuple[int, int]]:
            if iface == "tunsnx0":
                return (100, 50)
            return None

        glib_mock = MagicMock()
        glib_mock.timeout_add.return_value = 42

        with patch("snxui.system.traffic_monitor._read_iface_bytes", side_effect=fake_read):
            with patch.dict("sys.modules", {"gi.repository": MagicMock(GLib=glib_mock)}):
                with patch(
                    "snxui.system.traffic_monitor.TrafficMonitor._resolve_iface",
                    return_value="tunsnx0",
                ):
                    monitor.start("tunsnx")

        assert monitor._iface == "tunsnx0"
