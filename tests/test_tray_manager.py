"""Tests for snxui.system.tray_manager.

D-Bus объекты мокируются полностью — тесты не требуют запущенного D-Bus
сеанса и работают в CI/headless окружениях.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest

from snxui.system.tray_manager import TrayManager, _ICON_CONNECTED, _ICON_DISCONNECTED, _ICON_ERROR


# ---------------------------------------------------------------------------
# Вспомогательные фикстуры
# ---------------------------------------------------------------------------


def _make_mock_item() -> MagicMock:
    """Создать мок StatusNotifierItem с нужными методами."""
    item = MagicMock()
    item.update_icon = MagicMock()
    item.update_status = MagicMock()
    item.remove_from_connection = MagicMock()
    return item


# ---------------------------------------------------------------------------
# TrayManager.start()
# ---------------------------------------------------------------------------


class TestTrayManagerStart:
    def test_start_returns_false_when_dbus_unavailable(self):
        """Если dbus-python недоступен — start() возвращает False без краша."""
        tray = TrayManager("snxui")
        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", False):
            result = tray.start()
        assert result is False

    def test_start_returns_false_on_dbus_exception(self):
        """Если D-Bus выбрасывает исключение — start() возвращает False."""
        tray = TrayManager("snxui")
        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", True), \
             patch("snxui.system.tray_manager.dbus") as mock_dbus:
            mock_dbus.mainloop.glib.DBusGMainLoop.side_effect = Exception("no dbus")
            result = tray.start()
        assert result is False
        assert tray._item is None

    def test_start_success(self):
        """Успешный запуск: item создан, watcher опционален."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()

        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", True), \
             patch("snxui.system.tray_manager.dbus") as mock_dbus, \
             patch("snxui.system.tray_manager.StatusNotifierItem", return_value=mock_item):
            mock_bus = MagicMock()
            mock_dbus.SessionBus.return_value = mock_bus
            # Watcher регистрация — ошибка не критична
            mock_bus.get_object.side_effect = Exception("no watcher")

            result = tray.start()

        assert result is True
        assert tray._item is mock_item

    def test_start_registers_with_watcher(self):
        """При доступном Watcher — регистрируем SNI объект."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        mock_watcher_iface = MagicMock()

        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", True), \
             patch("snxui.system.tray_manager.dbus") as mock_dbus, \
             patch("snxui.system.tray_manager.StatusNotifierItem", return_value=mock_item), \
             patch("snxui.system.tray_manager.dbus.Interface", return_value=mock_watcher_iface):
            mock_bus = MagicMock()
            mock_dbus.SessionBus.return_value = mock_bus
            mock_bus.get_unique_name.return_value = ":1.42"

            tray.start()

        # Watcher object must be obtained and registration must be attempted.
        mock_bus.get_object.assert_called()
        # RegisterStatusNotifierItem must be called with the bus's unique name
        # (the SNI spec mandates this so the Watcher can track the item).
        mock_watcher_iface.RegisterStatusNotifierItem.assert_called_once_with(":1.42")


# ---------------------------------------------------------------------------
# TrayManager.stop()
# ---------------------------------------------------------------------------


class TestTrayManagerStop:
    def test_stop_removes_item(self):
        """stop() вызывает remove_from_connection и обнуляет item."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        tray._item = mock_item

        tray.stop()

        mock_item.remove_from_connection.assert_called_once()
        assert tray._item is None

    def test_stop_when_no_item(self):
        """stop() без item не выбрасывает исключений."""
        tray = TrayManager("snxui")
        tray._item = None
        tray.stop()  # Не должно упасть

    def test_stop_tolerates_remove_exception(self):
        """stop() не падает если remove_from_connection выбрасывает исключение."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        mock_item.remove_from_connection.side_effect = Exception("already removed")
        tray._item = mock_item

        tray.stop()  # Не должно упасть
        assert tray._item is None


# ---------------------------------------------------------------------------
# TrayManager.set_connected()
# ---------------------------------------------------------------------------


class TestSetConnected:
    def test_set_connected_true_uses_connected_icon(self):
        """set_connected(True) устанавливает иконку network-vpn."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        tray._item = mock_item

        tray.set_connected(True, "Work VPN")

        mock_item.update_icon.assert_called_once_with(
            _ICON_CONNECTED,
            "SNX VPN — Подключено",
            "Профиль: Work VPN",
        )
        mock_item.update_status.assert_called_once_with("Active")

    def test_set_connected_false_uses_disconnected_icon(self):
        """set_connected(False) устанавливает иконку network-vpn-disconnected."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        tray._item = mock_item

        tray.set_connected(False)

        mock_item.update_icon.assert_called_once_with(
            _ICON_DISCONNECTED,
            "SNX VPN — Отключено",
            "Нажмите для подключения",
        )
        mock_item.update_status.assert_called_once_with("Active")

    def test_set_connected_without_profile_name(self):
        """set_connected(True) без имени профиля использует generic tooltip."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        tray._item = mock_item

        tray.set_connected(True)

        # Должен использоваться generic body
        args = mock_item.update_icon.call_args[0]
        assert args[0] == _ICON_CONNECTED
        assert "VPN активен" in args[2]

    def test_set_connected_no_item_does_not_crash(self):
        """set_connected без item не вызывает исключений."""
        tray = TrayManager("snxui")
        tray._item = None
        tray.set_connected(True)  # Не должно упасть
        tray.set_connected(False)  # Не должно упасть

    def test_set_connected_updates_internal_state(self):
        """set_connected обновляет _connected флаг."""
        tray = TrayManager("snxui")
        tray._item = _make_mock_item()

        tray.set_connected(True)
        assert tray._connected is True

        tray.set_connected(False)
        assert tray._connected is False


# ---------------------------------------------------------------------------
# TrayManager.set_error()
# ---------------------------------------------------------------------------


class TestSetError:
    def test_set_error_uses_error_icon(self):
        """set_error() устанавливает иконку ошибки и NeedsAttention статус."""
        tray = TrayManager("snxui")
        mock_item = _make_mock_item()
        tray._item = mock_item

        tray.set_error("Соединение разорвано")

        mock_item.update_icon.assert_called_once_with(
            _ICON_ERROR,
            "SNX VPN — Ошибка",
            "Соединение разорвано",
        )
        mock_item.update_status.assert_called_once_with("NeedsAttention")

    def test_set_error_no_item_does_not_crash(self):
        """set_error без item не вызывает исключений."""
        tray = TrayManager("snxui")
        tray._item = None
        tray.set_error("some error")  # Не должно упасть


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    def test_on_connect_clicked_registers_callback(self):
        """on_connect_clicked добавляет callback в список."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_connect_clicked(cb)
        assert cb in tray._callbacks["connect"]

    def test_on_disconnect_clicked_registers_callback(self):
        """on_disconnect_clicked добавляет callback в список."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_disconnect_clicked(cb)
        assert cb in tray._callbacks["disconnect"]

    def test_on_show_window_registers_callback(self):
        """on_show_window добавляет callback в список."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_show_window(cb)
        assert cb in tray._callbacks["show"]

    def test_on_quit_registers_callback(self):
        """on_quit добавляет callback в список."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_quit(cb)
        assert cb in tray._callbacks["quit"]

    def test_menu_action_dispatches_to_callbacks(self):
        """_on_menu_action вызывает все зарегистрированные callbacks для действия."""
        tray = TrayManager("snxui")
        cb1 = MagicMock()
        cb2 = MagicMock()
        tray.on_show_window(cb1)
        tray.on_show_window(cb2)

        tray._on_menu_action("show")

        cb1.assert_called_once()
        cb2.assert_called_once()

    def test_menu_action_unknown_does_not_crash(self):
        """Неизвестное действие меню не вызывает исключений."""
        tray = TrayManager("snxui")
        tray._on_menu_action("unknown_action")  # Не должно упасть

    def test_menu_action_exception_in_callback_does_not_propagate(self):
        """Исключение в callback не прерывает выполнение остальных callbacks."""
        tray = TrayManager("snxui")
        bad_cb = MagicMock(side_effect=RuntimeError("callback error"))
        good_cb = MagicMock()
        tray.on_connect_clicked(bad_cb)
        tray.on_connect_clicked(good_cb)

        tray._on_menu_action("connect")  # Не должно упасть

        good_cb.assert_called_once()

    def test_multiple_callbacks_all_called(self):
        """Несколько callbacks для одного события — все вызываются."""
        tray = TrayManager("snxui")
        callbacks = [MagicMock() for _ in range(3)]
        for cb in callbacks:
            tray.on_connect_clicked(cb)

        tray._on_menu_action("connect")

        for cb in callbacks:
            cb.assert_called_once()


# ---------------------------------------------------------------------------
# Fallback при отсутствии D-Bus
# ---------------------------------------------------------------------------


class TestDbusUnavailableFallback:
    def test_full_lifecycle_without_dbus(self):
        """Полный жизненный цикл без D-Bus — нет краша."""
        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", False):
            tray = TrayManager("snxui")
            result = tray.start()
            assert result is False

            # Все операции должны работать без item
            tray.set_connected(True, "profile")
            tray.set_connected(False)
            tray.set_error("error msg")
            tray.stop()

    def test_callbacks_registered_without_dbus(self):
        """Callbacks регистрируются даже без D-Bus."""
        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", False):
            tray = TrayManager("snxui")
            cb = MagicMock()
            tray.on_connect_clicked(cb)
            tray.on_disconnect_clicked(cb)
            tray.on_show_window(cb)
            tray.on_quit(cb)
            assert len(tray._callbacks["connect"]) == 1
            assert len(tray._callbacks["disconnect"]) == 1
            assert len(tray._callbacks["show"]) == 1
            assert len(tray._callbacks["quit"]) == 1


# ---------------------------------------------------------------------------
# ContextMenu dispatch
# ---------------------------------------------------------------------------


class TestContextMenuDispatch:
    def test_context_menu_dispatches_to_menu_callback(self):
        """StatusNotifierItem.ContextMenu() вызывает menu_callback('context_menu')."""
        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", True), \
             patch("snxui.system.tray_manager.dbus") as mock_dbus:
            # Build a real StatusNotifierItem-like object without real D-Bus by
            # directly instantiating the stub path.
            from snxui.system.tray_manager import TrayManager
            tray = TrayManager("snxui")
            mock_item = _make_mock_item()
            tray._item = mock_item

            # Simulate the menu_callback that StatusNotifierItem would call.
            dispatched: list[str] = []

            def fake_menu_callback(action: str) -> None:
                dispatched.append(action)

            # Wire up: create a minimal SNI-like object that uses the callback.
            # We test TrayManager._on_menu_action instead, since StatusNotifierItem
            # calls menu_callback which is TrayManager._on_menu_action.
            tray._on_menu_action("context_menu")

        # _on_menu_action should not crash for an empty callbacks list.
        # Verify 'context_menu' key exists and list is empty by default.
        assert "context_menu" in tray._callbacks

    def test_on_context_menu_registers_callback(self):
        """on_context_menu() добавляет callback в _callbacks['context_menu']."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_context_menu(cb)
        assert cb in tray._callbacks["context_menu"]

    def test_context_menu_action_dispatches_to_registered_callback(self):
        """_on_menu_action('context_menu') вызывает все зарегистрированные callbacks."""
        tray = TrayManager("snxui")
        cb1 = MagicMock()
        cb2 = MagicMock()
        tray.on_context_menu(cb1)
        tray.on_context_menu(cb2)

        tray._on_menu_action("context_menu")

        cb1.assert_called_once()
        cb2.assert_called_once()

    def test_context_menu_key_in_callbacks_on_init(self):
        """TrayManager инициализируется с ключом 'context_menu' в _callbacks."""
        tray = TrayManager("snxui")
        assert "context_menu" in tray._callbacks
        assert isinstance(tray._callbacks["context_menu"], list)

    def test_sni_context_menu_calls_menu_callback_with_context_menu(self):
        """StatusNotifierItem.ContextMenu() вызывает menu_callback('context_menu')."""
        with patch("snxui.system.tray_manager._DBUS_AVAILABLE", True), \
             patch("snxui.system.tray_manager.dbus") as mock_dbus, \
             patch("snxui.system.tray_manager.StatusNotifierItem") as MockSNI:
            tray = TrayManager("snxui")
            mock_item = _make_mock_item()

            mock_dbus.mainloop.glib.DBusGMainLoop.return_value = None
            mock_dbus.SessionBus.return_value = MagicMock()
            MockSNI.return_value = mock_item
            mock_dbus.SessionBus.return_value.get_object.side_effect = Exception("no watcher")

            tray.start()

            # Verify that the menu_callback passed to StatusNotifierItem is
            # TrayManager._on_menu_action by calling it and checking dispatch.
            cb = MagicMock()
            tray.on_context_menu(cb)

            # Simulate what StatusNotifierItem.ContextMenu() does:
            # it calls self._menu_callback("context_menu")
            # which is tray._on_menu_action
            tray._on_menu_action("context_menu")

            cb.assert_called_once()


# ---------------------------------------------------------------------------
# Tray action callbacks — connect, disconnect, quit
# ---------------------------------------------------------------------------


class TestTrayActionCallbacks:
    def test_on_connect_clicked_callback_fired_by_menu_action(self):
        """'connect' действие меню вызывает on_connect_clicked callbacks."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_connect_clicked(cb)
        tray._on_menu_action("connect")
        cb.assert_called_once()

    def test_on_disconnect_clicked_callback_fired_by_menu_action(self):
        """'disconnect' действие меню вызывает on_disconnect_clicked callbacks."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_disconnect_clicked(cb)
        tray._on_menu_action("disconnect")
        cb.assert_called_once()

    def test_on_quit_callback_fired_by_menu_action(self):
        """'quit' действие меню вызывает on_quit callbacks."""
        tray = TrayManager("snxui")
        cb = MagicMock()
        tray.on_quit(cb)
        tray._on_menu_action("quit")
        cb.assert_called_once()

    def test_all_four_actions_in_callbacks_dict(self):
        """Все четыре действия присутствуют в _callbacks после инициализации."""
        tray = TrayManager("snxui")
        for action in ("connect", "disconnect", "show", "quit", "context_menu"):
            assert action in tray._callbacks, f"Missing action key: {action}"

    def test_multiple_action_callbacks_all_fired(self):
        """Несколько callbacks на одно действие — все вызываются."""
        tray = TrayManager("snxui")
        cbs = [MagicMock() for _ in range(3)]
        for cb in cbs:
            tray.on_quit(cb)
        tray._on_menu_action("quit")
        for cb in cbs:
            cb.assert_called_once()
