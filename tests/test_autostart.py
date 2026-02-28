"""Tests for snxui.system.autostart.AutostartManager.

Используется tmp_path фикстура pytest для изоляции файловой системы.
Реальный ~/.config/autostart не затрагивается.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch, PropertyMock

import pytest

from snxui.system.autostart import AutostartManager, AUTOSTART_CONTENT


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture()
def mgr(tmp_path: Path) -> AutostartManager:
    """AutostartManager с перенаправленным autostart_dir во временный каталог."""
    m = AutostartManager()
    autostart_dir = tmp_path / "autostart"
    # Перенаправляем свойства через patch
    with patch.object(
        type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir
    ), patch.object(
        type(m), "autostart_file", new_callable=PropertyMock,
        return_value=autostart_dir / "snxui.desktop"
    ):
        yield m


# ---------------------------------------------------------------------------
# Вспомогательная фикстура без контекстного менеджера (для прямых тестов)
# ---------------------------------------------------------------------------


def _make_manager(tmp_path: Path) -> tuple[AutostartManager, Path, Path]:
    """Создать менеджер и пути, не используя контекстный менеджер yield."""
    autostart_dir = tmp_path / "autostart"
    autostart_file = autostart_dir / "snxui.desktop"
    m = AutostartManager()
    return m, autostart_dir, autostart_file


# ---------------------------------------------------------------------------
# Свойства autostart_dir и autostart_file
# ---------------------------------------------------------------------------


class TestProperties:
    def test_autostart_dir_is_under_home_config(self) -> None:
        """autostart_dir должен быть ~/.config/autostart/ когда XDG_CONFIG_HOME не задан."""
        m = AutostartManager()
        # Isolate from any XDG_CONFIG_HOME that might be set in the test environment.
        env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
        with patch.dict("os.environ", env, clear=True):
            expected = Path.home() / ".config" / "autostart"
            assert m.autostart_dir == expected

    def test_autostart_dir_respects_xdg_config_home(self, tmp_path: Path) -> None:
        """autostart_dir должен использовать XDG_CONFIG_HOME если он задан.

        XDG Base Directory Specification requires $XDG_CONFIG_HOME/autostart.
        Before the fix, AutostartManager hardcoded ~/.config regardless of the
        environment variable, inconsistent with profile_manager._xdg_config_home().
        """
        m = AutostartManager()
        with patch.dict("os.environ", {"XDG_CONFIG_HOME": str(tmp_path)}):
            assert m.autostart_dir == tmp_path / "autostart"

    def test_autostart_file_is_desktop_file(self) -> None:
        """autostart_file должен заканчиваться на snxui.desktop."""
        m = AutostartManager()
        assert m.autostart_file.name == "snxui.desktop"
        assert m.autostart_file.parent == m.autostart_dir


# ---------------------------------------------------------------------------
# enable()
# ---------------------------------------------------------------------------


class TestEnable:
    def test_enable_creates_desktop_file(self, tmp_path: Path) -> None:
        """enable() создаёт .desktop файл."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            result = m.enable()

        assert result is True
        assert autostart_file.exists()

    def test_enable_creates_parent_directory(self, tmp_path: Path) -> None:
        """enable() создаёт каталог autostart если его нет."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        assert not autostart_dir.exists()

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            m.enable()

        assert autostart_dir.exists()

    def test_enable_writes_correct_content(self, tmp_path: Path) -> None:
        """enable() записывает корректный .desktop контент."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            m.enable()

        content = autostart_file.read_text(encoding="utf-8")
        assert "[Desktop Entry]" in content
        assert "Type=Application" in content
        assert "snxui" in content.lower()
        assert "X-GNOME-Autostart-enabled=true" in content

    def test_enable_is_idempotent(self, tmp_path: Path) -> None:
        """Повторный вызов enable() не приводит к ошибке."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            assert m.enable() is True
            assert m.enable() is True

        assert autostart_file.exists()

    def test_enable_returns_false_on_oserror(self, tmp_path: Path) -> None:
        """enable() возвращает False если не удаётся записать файл."""
        m = AutostartManager()
        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=tmp_path), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock,
                          return_value=tmp_path / "snxui.desktop"), \
             patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            result = m.enable()
        assert result is False


# ---------------------------------------------------------------------------
# disable()
# ---------------------------------------------------------------------------


class TestDisable:
    def test_disable_removes_existing_file(self, tmp_path: Path) -> None:
        """disable() удаляет существующий .desktop файл."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        autostart_file.write_text(AUTOSTART_CONTENT)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            result = m.disable()

        assert result is True
        assert not autostart_file.exists()

    def test_disable_returns_true_when_file_absent(self, tmp_path: Path) -> None:
        """disable() возвращает True если файл уже не существует."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            result = m.disable()

        assert result is True

    def test_disable_returns_false_on_oserror(self, tmp_path: Path) -> None:
        """disable() возвращает False при OSError."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        autostart_file.write_text(AUTOSTART_CONTENT)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file), \
             patch("pathlib.Path.unlink", side_effect=OSError("permission denied")):
            result = m.disable()

        assert result is False


# ---------------------------------------------------------------------------
# is_enabled()
# ---------------------------------------------------------------------------


class TestIsEnabled:
    def test_returns_false_when_file_absent(self, tmp_path: Path) -> None:
        """is_enabled() возвращает False если файл отсутствует."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            assert m.is_enabled() is False

    def test_returns_true_when_file_exists(self, tmp_path: Path) -> None:
        """is_enabled() возвращает True если файл существует без Hidden=true."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        autostart_file.write_text(AUTOSTART_CONTENT)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            assert m.is_enabled() is True

    def test_returns_false_when_hidden_true(self, tmp_path: Path) -> None:
        """is_enabled() возвращает False если файл содержит Hidden=true."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        content = AUTOSTART_CONTENT.replace("Hidden=false", "Hidden=true")
        autostart_file.write_text(content)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            assert m.is_enabled() is False

    def test_returns_false_on_read_error(self, tmp_path: Path) -> None:
        """is_enabled() возвращает False если файл нечитаем."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        autostart_file.write_text(AUTOSTART_CONTENT)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file), \
             patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            assert m.is_enabled() is False

    def test_case_insensitive_hidden_check(self, tmp_path: Path) -> None:
        """Hidden=True (с заглавной) тоже должно распознаваться."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        content = "[Desktop Entry]\nHidden=True\nType=Application\n"
        autostart_file.write_text(content)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            assert m.is_enabled() is False


# ---------------------------------------------------------------------------
# toggle()
# ---------------------------------------------------------------------------


class TestToggle:
    def test_toggle_enables_when_disabled(self, tmp_path: Path) -> None:
        """toggle() включает автозапуск если был выключен."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            new_state = m.toggle()

        assert new_state is True
        assert autostart_file.exists()

    def test_toggle_disables_when_enabled(self, tmp_path: Path) -> None:
        """toggle() выключает автозапуск если был включён."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)
        autostart_dir.mkdir(parents=True)
        autostart_file.write_text(AUTOSTART_CONTENT)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            new_state = m.toggle()

        assert new_state is False
        assert not autostart_file.exists()

    def test_double_toggle_restores_state(self, tmp_path: Path) -> None:
        """Двойной toggle() возвращает исходное состояние."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            state1 = m.toggle()  # False -> True
            state2 = m.toggle()  # True -> False

        assert state1 is True
        assert state2 is False


# ---------------------------------------------------------------------------
# Полный цикл enable/disable/is_enabled
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    def test_enable_disable_cycle(self, tmp_path: Path) -> None:
        """Полный цикл: enable -> is_enabled True -> disable -> is_enabled False."""
        m, autostart_dir, autostart_file = _make_manager(tmp_path)

        with patch.object(type(m), "autostart_dir", new_callable=PropertyMock, return_value=autostart_dir), \
             patch.object(type(m), "autostart_file", new_callable=PropertyMock, return_value=autostart_file):
            assert m.is_enabled() is False

            m.enable()
            assert m.is_enabled() is True

            m.disable()
            assert m.is_enabled() is False

    def test_content_contains_exec_minimized(self, tmp_path: Path) -> None:
        """Контент .desktop должен содержать --minimized флаг."""
        assert "--minimized" in AUTOSTART_CONTENT

    def test_content_has_gnome_autostart_key(self, tmp_path: Path) -> None:
        """Контент должен содержать X-GNOME-Autostart-enabled=true."""
        assert "X-GNOME-Autostart-enabled=true" in AUTOSTART_CONTENT
