"""TrayManager: системный трей через org.kde.StatusNotifierItem D-Bus API.

Совместим с: GNOME + KDE Status Notifier extension, KDE Plasma, XFCE, LXDE.

Использует StatusNotifierItem (SNI) спецификацию вместо AppIndicator3, т.к.
AppIndicator3 несовместим с GTK4 и не поддерживается нативно в GNOME 40+.

SNI зарегистрирован как D-Bus сервис под именем
``org.kde.StatusNotifierItem-{pid}-{seq}`` и объектом по пути
``/StatusNotifierItem``.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Попытка импорта dbus. При отсутствии пакета — graceful fallback.
# ---------------------------------------------------------------------------

try:
    import dbus
    import dbus.service
    import dbus.mainloop.glib
    _DBUS_AVAILABLE = True
except ImportError:
    dbus = None  # type: ignore[assignment]
    _DBUS_AVAILABLE = False
    logger.warning(
        "dbus-python не установлен. Системный трей недоступен. "
        "Установите: sudo apt install python3-dbus"
    )

# ---------------------------------------------------------------------------
# D-Bus интерфейс StatusNotifierItem
# ---------------------------------------------------------------------------

_SNI_INTERFACE = "org.kde.StatusNotifierItem"
_SNI_PATH = "/StatusNotifierItem"
_SNW_INTERFACE = "org.kde.StatusNotifierWatcher"
_SNW_SERVICE = "org.kde.StatusNotifierWatcher"
_SNW_PATH = "/StatusNotifierWatcher"

# XDG иконки для состояний (только symbolic-варианты, которые есть в Adwaita)
_ICON_CONNECTED = "network-vpn-symbolic"
_ICON_DISCONNECTED = "network-vpn-disconnected-symbolic"
_ICON_CONNECTING = "network-vpn-acquiring-symbolic"
_ICON_ERROR = "network-error-symbolic"


class _StatusNotifierItemBase:
    """Заглушка для случая когда dbus недоступен."""
    pass


if _DBUS_AVAILABLE:
    class StatusNotifierItem(dbus.service.Object):  # type: ignore[misc]
        """D-Bus объект StatusNotifierItem.

        Реализует минимально необходимый набор свойств и сигналов
        по спецификации org.kde.StatusNotifierItem.

        Свойства:
            Category: ``ApplicationStatus``
            Id: идентификатор приложения (``snxui``)
            Status: ``Active`` | ``Passive`` | ``NeedsAttention``
            IconName: имя XDG иконки
            Title: заголовок для tooltip
            ToolTipTitle: первая строка tooltip
            ToolTipBody: расширенное описание
        """

        def __init__(
            self,
            bus: "dbus.SessionBus",
            app_id: str = "snxui",
            menu_callback: Optional[Callable[[str], None]] = None,
        ) -> None:
            self._app_id = app_id
            self._status = "Active"
            self._icon_name = _ICON_DISCONNECTED
            self._title = "SNX VPN"
            self._tooltip_title = "SNX VPN"
            self._tooltip_body = "Отключено"
            self._menu_callback = menu_callback

            conn = dbus.service.BusName(
                f"org.kde.StatusNotifierItem-{self._app_id}",
                bus=bus,
            )
            super().__init__(conn, _SNI_PATH)

        # ------------------------------------------------------------------
        # D-Bus свойства (через метод Get/GetAll — упрощённая реализация)
        # ------------------------------------------------------------------

        @dbus.service.method(
            dbus_interface="org.freedesktop.DBus.Properties",
            in_signature="ss",
            out_signature="v",
        )
        def Get(self, interface_name: str, property_name: str) -> "dbus.String":
            return self._get_property(property_name)

        def _build_properties(self) -> dict:
            """Return the full D-Bus property mapping for this SNI item."""
            return {
                "Category": dbus.String("ApplicationStatus"),
                "Id": dbus.String(self._app_id),
                "Status": dbus.String(self._status),
                "IconName": dbus.String(self._icon_name),
                "Title": dbus.String(self._title),
                "ToolTipTitle": dbus.String(self._tooltip_title),
                "ToolTipBody": dbus.String(self._tooltip_body),
                "ToolTipIconName": dbus.String(self._icon_name),
                "IconThemePath": dbus.String(""),
                "Menu": dbus.ObjectPath("/NO_DBUSMENU"),
                "ItemIsMenu": dbus.Boolean(False),
                "OverlayIconName": dbus.String(""),
                "AttentionIconName": dbus.String(""),
                "AttentionMovieName": dbus.String(""),
            }

        @dbus.service.method(
            dbus_interface="org.freedesktop.DBus.Properties",
            in_signature="s",
            out_signature="a{sv}",
        )
        def GetAll(self, interface_name: str) -> dict:
            return self._build_properties()

        def _get_property(self, name: str) -> "dbus.String":
            return self._build_properties().get(name, dbus.String(""))

        # ------------------------------------------------------------------
        # SNI методы
        # ------------------------------------------------------------------

        @dbus.service.method(dbus_interface=_SNI_INTERFACE)
        def Activate(self, x: int, y: int) -> None:
            """Левый клик по иконке трея — показать контекстное меню.

            GNOME с AppIndicator не вызывает ContextMenu, поэтому левый клик
            тоже открывает наше GTK PopoverMenu.
            """
            logger.debug("TrayItem.Activate called (%d, %d)", x, y)
            if self._menu_callback:
                self._menu_callback("context_menu")

        @dbus.service.method(dbus_interface=_SNI_INTERFACE)
        def SecondaryActivate(self, x: int, y: int) -> None:
            """Средняя кнопка мыши."""
            logger.debug("TrayItem.SecondaryActivate called (%d, %d)", x, y)

        @dbus.service.method(dbus_interface=_SNI_INTERFACE)
        def ContextMenu(self, x: int, y: int) -> None:
            """Правая кнопка мыши — контекстное меню.

            Dispatches the 'context_menu' action to the registered callback so
            the application layer can show a GTK popup menu via GLib.idle_add.
            """
            logger.debug("TrayItem.ContextMenu called (%d, %d)", x, y)
            if self._menu_callback:
                self._menu_callback("context_menu")

        @dbus.service.method(dbus_interface=_SNI_INTERFACE)
        def Scroll(self, delta: int, orientation: str) -> None:
            """Прокрутка колёсиком."""

        # ------------------------------------------------------------------
        # SNI сигналы
        # ------------------------------------------------------------------

        @dbus.service.signal(dbus_interface=_SNI_INTERFACE)
        def NewStatus(self, status: str) -> None:  # type: ignore[empty-body]
            pass

        @dbus.service.signal(dbus_interface=_SNI_INTERFACE)
        def NewIcon(self) -> None:  # type: ignore[empty-body]
            pass

        @dbus.service.signal(dbus_interface=_SNI_INTERFACE)
        def NewToolTip(self) -> None:  # type: ignore[empty-body]
            pass

        # ------------------------------------------------------------------
        # Внутренние методы обновления состояния
        # ------------------------------------------------------------------

        def update_icon(self, icon_name: str, title: str, tooltip_body: str) -> None:
            """Обновить иконку и tooltip, выслать соответствующие сигналы."""
            changed = False
            if self._icon_name != icon_name:
                self._icon_name = icon_name
                changed = True
            self._tooltip_title = title
            self._tooltip_body = tooltip_body
            if changed:
                try:
                    self.NewIcon()
                except Exception:
                    logger.debug("NewIcon signal failed (normal if no watcher)", exc_info=True)
            try:
                self.NewToolTip()
            except Exception:
                logger.debug("NewToolTip signal failed", exc_info=True)

        def update_status(self, status: str) -> None:
            """Обновить статус (Active/Passive/NeedsAttention)."""
            if self._status != status:
                self._status = status
                try:
                    self.NewStatus(status)
                except Exception:
                    logger.debug("NewStatus signal failed", exc_info=True)

else:
    # Заглушка если dbus недоступен
    class StatusNotifierItem(_StatusNotifierItemBase):  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs) -> None:
            pass

        def update_icon(self, *args, **kwargs) -> None:
            pass

        def update_status(self, *args, **kwargs) -> None:
            pass


# ---------------------------------------------------------------------------
# TrayManager
# ---------------------------------------------------------------------------


class TrayManager:
    """Управляет иконкой приложения в системном трее через D-Bus SNI.

    Пример использования::

        tray = TrayManager("snxui")
        tray.on_connect_clicked(lambda: backend.connect(...))
        tray.on_show_window(lambda: window.present())
        tray.start()

        # При изменении состояния:
        tray.set_connected(True, "Work VPN")

        # При завершении:
        tray.stop()
    """

    def __init__(self, app_id: str = "snxui") -> None:
        self._app_id = app_id
        self._item: Optional[StatusNotifierItem] = None
        self._connected = False
        self._bus: Optional["dbus.SessionBus"] = None
        self._callbacks: dict[str, list[Callable[[], None]]] = {
            "connect": [],
            "disconnect": [],
            "show": [],
            "quit": [],
            "context_menu": [],
        }

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Запустить D-Bus StatusNotifierItem трей.

        Returns:
            ``True`` если трей успешно инициализирован,
            ``False`` если D-Bus недоступен (без краша).
        """
        if not _DBUS_AVAILABLE:
            logger.warning("dbus-python недоступен. Трей отключён.")
            return False

        try:
            # Инициализировать GLib mainloop для dbus-python.
            # Вызов безопасен при повторном вызове.
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            self._bus = dbus.SessionBus()
            self._item = StatusNotifierItem(
                self._bus,
                app_id=self._app_id,
                menu_callback=self._on_menu_action,
            )
            self._register_with_watcher()
            logger.info("TrayManager: SNI трей запущен (app_id=%s).", self._app_id)
            return True
        except Exception as exc:
            logger.warning("TrayManager: не удалось запустить трей: %s", exc)
            self._item = None
            self._bus = None
            return False

    def stop(self) -> None:
        """Остановить трей и освободить D-Bus ресурсы."""
        if self._item is not None:
            try:
                self._item.remove_from_connection()
            except Exception:
                logger.debug("TrayManager: remove_from_connection failed", exc_info=True)
            self._item = None
        self._bus = None
        logger.debug("TrayManager: трей остановлен.")

    def set_connected(self, connected: bool, profile_name: str = "") -> None:
        """Обновить иконку трея в соответствии с состоянием подключения.

        Args:
            connected: ``True`` — VPN подключен, ``False`` — отключён.
            profile_name: Имя активного профиля (для tooltip).
        """
        self._connected = connected
        if self._item is None:
            return

        if connected:
            icon = _ICON_CONNECTED
            title = "SNX VPN — Подключено"
            body = f"Профиль: {profile_name}" if profile_name else "VPN активен"
            status = "Active"
        else:
            icon = _ICON_DISCONNECTED
            title = "SNX VPN — Отключено"
            body = "Нажмите для подключения"
            status = "Active"

        self._item.update_icon(icon, title, body)
        self._item.update_status(status)
        logger.debug("TrayManager: set_connected(%s, %r)", connected, profile_name)

    def set_connecting(self) -> None:
        """Показать иконку «подключение» в трее."""
        if self._item is None:
            return
        self._item.update_icon(_ICON_CONNECTING, "SNX VPN — Подключение…", "Установка соединения")
        self._item.update_status("Active")
        logger.debug("TrayManager: set_connecting()")

    def set_error(self, error: str) -> None:
        """Показать иконку ошибки с описанием в tooltip.

        Args:
            error: Текст ошибки для tooltip.
        """
        if self._item is None:
            return
        self._item.update_icon(_ICON_ERROR, "SNX VPN — Ошибка", error)
        self._item.update_status("NeedsAttention")
        logger.debug("TrayManager: set_error(%r)", error)

    # ------------------------------------------------------------------
    # Регистрация обработчиков
    # ------------------------------------------------------------------

    def on_connect_clicked(self, callback: Callable[[], None]) -> None:
        """Зарегистрировать обработчик действия «Подключить»."""
        self._callbacks["connect"].append(callback)

    def on_disconnect_clicked(self, callback: Callable[[], None]) -> None:
        """Зарегистрировать обработчик действия «Отключить»."""
        self._callbacks["disconnect"].append(callback)

    def on_show_window(self, callback: Callable[[], None]) -> None:
        """Зарегистрировать обработчик показа/скрытия главного окна."""
        self._callbacks["show"].append(callback)

    def on_quit(self, callback: Callable[[], None]) -> None:
        """Зарегистрировать обработчик выхода из приложения."""
        self._callbacks["quit"].append(callback)

    def on_context_menu(self, callback: Callable[[], None]) -> None:
        """Зарегистрировать обработчик запроса контекстного меню (правая кнопка)."""
        self._callbacks["context_menu"].append(callback)

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------

    def _on_menu_action(self, action: str) -> None:
        """Диспетчеризировать действия меню на зарегистрированные callback-и."""
        callbacks = self._callbacks.get(action, [])
        for cb in callbacks:
            try:
                cb()
            except Exception:
                logger.exception("TrayManager: исключение в callback %r", action)

    def _register_with_watcher(self) -> None:
        """Зарегистрировать SNI объект в StatusNotifierWatcher (если доступен).

        KDE Plasma и некоторые другие окружения требуют явной регистрации
        в Watcher. GNOME (с extension) находит SNI по имени шины автоматически.
        Ошибка регистрации не является фатальной.
        """
        if self._bus is None:
            return
        try:
            watcher = self._bus.get_object(_SNW_SERVICE, _SNW_PATH)
            watcher_iface = dbus.Interface(watcher, _SNW_INTERFACE)
            service_name = str(
                self._bus.get_unique_name()
            )
            watcher_iface.RegisterStatusNotifierItem(service_name)
            logger.debug(
                "TrayManager: зарегистрировано в StatusNotifierWatcher (%s).",
                service_name,
            )
        except Exception as exc:
            # Watcher может быть недоступен (например, в GNOME без extension).
            logger.debug(
                "TrayManager: StatusNotifierWatcher недоступен: %s. "
                "Трей может не отображаться в GNOME без соответствующего extension.",
                exc,
            )
