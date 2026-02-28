"""PrivilegeHandler: запуск SNX с правами root через pkexec + polkit.

SNX требует привилегий root для создания TUN-интерфейса. Запускать весь GUI
как root недопустимо. Данный модуль изолирует запуск SNX-бинарника через
``pkexec`` с polkit-правилом ``com.snxui.connect``.

Минимальная версия polkit: 0.119 (закрывает CVE-2021-4034 / PwnKit).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Путь к polkit policy-файлу в системе
_POLKIT_ACTIONS_DIR = Path("/usr/share/polkit-1/actions")

# Минимальная безопасная версия polkit
_MIN_POLKIT_VERSION = (0, 119)


class PrivilegeHandler:
    """Управляет привилегированным запуском SNX через pkexec.

    Пример::

        handler = PrivilegeHandler()
        if handler.is_polkit_available():
            proc = handler.run_snx_privileged(["-s", "vpn.example.com", "-u", "alice"])
            proc.wait()
    """

    POLKIT_ACTION = "com.snxui.connect"
    POLKIT_DISCONNECT_ACTION = "com.snxui.disconnect"

    # Расположение SNX binary (проверяется в порядке приоритета)
    _SNX_PATHS = [
        Path("/usr/bin/snx"),
        Path("/usr/local/bin/snx"),
    ]

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def run_snx_privileged(self, snx_args: list[str]) -> subprocess.Popen:
        """Запустить SNX binary с правами root через pkexec.

        Polkit отобразит диалог аутентификации пользователю (если требуется).
        После подтверждения SNX запустится от имени root.

        Args:
            snx_args: Аргументы для SNX binary (без имени самого бинарника).
                      Пример: ``["-s", "vpn.example.com", "-u", "alice"]``

        Returns:
            Объект :class:`subprocess.Popen` запущенного процесса.

        Raises:
            FileNotFoundError: Если ``pkexec`` или SNX binary не найдены.
            RuntimeError: Если polkit недоступен.
        """
        pkexec_path = self._find_pkexec()
        snx_path = self._find_snx()

        cmd = [pkexec_path, str(snx_path)] + snx_args
        logger.info("Запуск SNX через pkexec: %s", " ".join(cmd))

        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def is_polkit_available(self) -> bool:
        """Проверить доступность pkexec в системе.

        Returns:
            ``True`` если ``pkexec`` найден в PATH, ``False`` иначе.
        """
        result = shutil.which("pkexec")
        available = result is not None
        logger.debug("pkexec %s", "доступен" if available else "недоступен")
        return available

    def check_polkit_version(self) -> Optional[str]:
        """Получить строку версии установленного polkit.

        Проверяет что версия >= 0.119 (CVE-2021-4034 / PwnKit закрыт).

        Returns:
            Строка версии (например ``"0.120"``), или ``None`` при ошибке.

        Note:
            Метод логирует предупреждение при версии < 0.119.
        """
        try:
            result = subprocess.run(
                ["pkexec", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout + result.stderr).strip()
            parsed = self._parse_polkit_version_string(output)
            if parsed is None:
                return None
            version_str, is_old = parsed
            if is_old:
                logger.warning(
                    "Версия polkit %s < 0.119. Уязвимость CVE-2021-4034 (PwnKit) "
                    "не закрыта. Обновите polkit.",
                    version_str,
                )
            else:
                logger.debug("polkit версия %s OK (>= 0.119).", version_str)
            return version_str
        except FileNotFoundError:
            logger.debug("pkexec не найден при проверке версии.")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("pkexec --version завис.")
            return None
        except Exception as exc:
            logger.warning("Ошибка при проверке версии polkit: %s", exc)
            return None

    def _parse_polkit_version_string(self, output: str) -> Optional[tuple]:
        """Распарсить строку вывода pkexec --version.

        Args:
            output: Объединённый stdout+stderr из ``pkexec --version``.

        Returns:
            Кортеж ``(version_str, is_old)`` или ``None`` при неудаче.
            ``is_old`` равно ``True`` если версия < 0.119.
        """
        # Современные версии polkit (122+) используют одно число без точки.
        # Старые версии (0.105, 0.119, 0.120) — формат major.minor.
        # Пробуем сначала формат с точкой, потом одиночное число.
        dot_match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", output)
        if dot_match:
            version_str = dot_match.group(0)
            major = int(dot_match.group(1))
            minor = int(dot_match.group(2))
            is_old = (major, minor) < _MIN_POLKIT_VERSION
            return version_str, is_old

        # Одиночное число — современный polkit (>= 100 >> 0.119)
        single_match = re.search(r"\b(\d+)\b", output)
        if not single_match:
            logger.warning("Не удалось распарсить версию polkit из: %r", output)
            return None
        version_str = single_match.group(1)
        major = int(version_str)
        # Одиночный номер >= 100 заведомо новее 0.119
        is_old = major < 100 and (major, 0) < _MIN_POLKIT_VERSION
        return version_str, is_old

    def install_policy(self, policy_path: Path) -> bool:
        """Установить polkit .policy файл в системный каталог.

        Требует прав root (использует pkexec cp или sudo cp).
        В продакшн-сборке файл устанавливается пакетным менеджером.
        Этот метод предназначен для development-установки.

        Args:
            policy_path: Путь к .policy файлу для установки.

        Returns:
            ``True`` при успешной установке, ``False`` при ошибке.
        """
        if not policy_path.exists():
            logger.error("Policy файл не найден: %s", policy_path)
            return False

        dest = _POLKIT_ACTIONS_DIR / policy_path.name
        logger.info("Установка polkit policy: %s -> %s", policy_path, dest)

        # Попытка через pkexec cp
        for copy_cmd in [
            ["pkexec", "cp", str(policy_path), str(dest)],
            ["sudo", "cp", str(policy_path), str(dest)],
        ]:
            try:
                result = subprocess.run(
                    copy_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    logger.info("Policy файл установлен: %s", dest)
                    return True
                logger.debug(
                    "Команда %s вернула код %d: %s",
                    copy_cmd[0],
                    result.returncode,
                    result.stderr.strip(),
                )
            except FileNotFoundError:
                logger.debug("%s недоступен.", copy_cmd[0])
            except subprocess.TimeoutExpired:
                logger.warning("Установка policy зависла (%s).", copy_cmd[0])

        logger.error("Не удалось установить polkit policy файл.")
        return False

    # ------------------------------------------------------------------
    # Приватные вспомогательные методы
    # ------------------------------------------------------------------

    def _find_pkexec(self) -> str:
        """Найти pkexec binary.

        Returns:
            Абсолютный путь к pkexec.

        Raises:
            FileNotFoundError: Если pkexec не найден.
        """
        path = shutil.which("pkexec")
        if path:
            return path
        raise FileNotFoundError(
            "pkexec не найден. Установите polkit: sudo apt install policykit-1"
        )

    def _find_snx(self) -> Path:
        """Найти SNX binary.

        Returns:
            Путь к SNX binary.

        Raises:
            FileNotFoundError: Если SNX binary не найден.
        """
        for candidate in self._SNX_PATHS:
            if candidate.exists() and candidate.is_file():
                return candidate

        found = shutil.which("snx")
        if found:
            return Path(found)

        raise FileNotFoundError(
            "SNX binary не найден. Загрузите snx с портала VPN и разместите "
            "по пути /usr/bin/snx, затем выполните: chmod +x /usr/bin/snx"
        )
