"""AutostartManager: управление автозапуском через XDG .desktop файл.

При включении автозапуска создаётся файл
``~/.config/autostart/snxui.desktop`` согласно спецификации XDG Autostart.

Спецификация:
    https://specifications.freedesktop.org/autostart-spec/autostart-spec-latest.html
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Содержимое .desktop файла для автозапуска
AUTOSTART_CONTENT = """\
[Desktop Entry]
Type=Application
Name=SNX VPN
Name[ru]=SNX VPN
Comment=Check Point SNX VPN Client
Comment[ru]=Клиент Check Point SNX VPN
Exec=snxui --minimized
Icon=network-vpn
X-GNOME-Autostart-enabled=true
Hidden=false
NoDisplay=false
"""


class AutostartManager:
    """Управляет автозапуском snxui через XDG autostart механизм.

    Пример::

        mgr = AutostartManager()
        mgr.enable()        # Создать ~/.config/autostart/snxui.desktop
        mgr.is_enabled()    # True
        mgr.disable()       # Удалить файл
        mgr.toggle()        # Переключить и вернуть новый статус
    """

    _AUTOSTART_FILENAME = "snxui.desktop"

    # ------------------------------------------------------------------
    # Свойства путей
    # ------------------------------------------------------------------

    @property
    def autostart_dir(self) -> Path:
        """Каталог XDG autostart: ``$XDG_CONFIG_HOME/autostart/``.

        Respects the ``XDG_CONFIG_HOME`` environment variable per the XDG Base
        Directory Specification.  Falls back to ``~/.config`` when the variable
        is not set, which matches the behaviour of :func:`_xdg_config_home` in
        ``profile_manager`` and the XDG default.
        """
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "")
        xdg_config = Path(xdg_config_home) if xdg_config_home else Path.home() / ".config"
        return xdg_config / "autostart"

    @property
    def autostart_file(self) -> Path:
        """Полный путь к .desktop файлу автозапуска."""
        return self.autostart_dir / self._AUTOSTART_FILENAME

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def enable(self) -> bool:
        """Включить автозапуск: создать XDG .desktop файл.

        Создаёт каталог ``~/.config/autostart/`` если он не существует.

        Returns:
            ``True`` при успехе, ``False`` при ошибке записи.
        """
        try:
            self.autostart_dir.mkdir(parents=True, exist_ok=True)
            self.autostart_file.write_text(AUTOSTART_CONTENT, encoding="utf-8")
            logger.info("Автозапуск включён: %s", self.autostart_file)
            return True
        except OSError as exc:
            logger.error("Не удалось включить автозапуск: %s", exc)
            return False

    def disable(self) -> bool:
        """Выключить автозапуск: удалить XDG .desktop файл.

        Returns:
            ``True`` при успехе (или если файл уже не существует),
            ``False`` при ошибке удаления.
        """
        try:
            if self.autostart_file.exists():
                self.autostart_file.unlink()
                logger.info("Автозапуск выключен: %s удалён.", self.autostart_file)
            else:
                logger.debug("Файл автозапуска не существует, ничего не удаляем.")
            return True
        except OSError as exc:
            logger.error("Не удалось выключить автозапуск: %s", exc)
            return False

    def is_enabled(self) -> bool:
        """Проверить активен ли автозапуск.

        Returns:
            ``True`` если XDG .desktop файл существует и автозапуск
            не отключён полем ``Hidden=true``.
        """
        if not self.autostart_file.exists():
            return False

        try:
            content = self.autostart_file.read_text(encoding="utf-8")
            # Проверить явное отключение через Hidden=true
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.lower() == "hidden=true":
                    return False
            return True
        except OSError as exc:
            logger.warning("Не удалось прочитать файл автозапуска: %s", exc)
            return False

    def toggle(self) -> bool:
        """Переключить состояние автозапуска.

        Returns:
            Фактический новый статус автозапуска (``True`` = включён).
            Если файловая операция завершилась с ошибкой, отражает
            реальное состояние файла, а не предполагаемое.
        """
        if self.is_enabled():
            self.disable()
        else:
            self.enable()
        return self.is_enabled()
