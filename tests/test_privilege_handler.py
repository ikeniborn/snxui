"""Tests for snxui.system.privilege_handler.

Все subprocess и shutil вызовы мокируются — тесты не требуют pkexec или SNX.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from snxui.system.privilege_handler import PrivilegeHandler, _MIN_POLKIT_VERSION


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture()
def handler() -> PrivilegeHandler:
    return PrivilegeHandler()


# ---------------------------------------------------------------------------
# is_polkit_available()
# ---------------------------------------------------------------------------


class TestIsPolkitAvailable:
    def test_returns_true_when_pkexec_found(self, handler: PrivilegeHandler) -> None:
        with patch("shutil.which", return_value="/usr/bin/pkexec"):
            assert handler.is_polkit_available() is True

    def test_returns_false_when_pkexec_not_found(self, handler: PrivilegeHandler) -> None:
        with patch("shutil.which", return_value=None):
            assert handler.is_polkit_available() is False

    def test_calls_which_with_pkexec(self, handler: PrivilegeHandler) -> None:
        with patch("shutil.which", return_value="/usr/bin/pkexec") as mock_which:
            handler.is_polkit_available()
            mock_which.assert_called_once_with("pkexec")


# ---------------------------------------------------------------------------
# check_polkit_version()
# ---------------------------------------------------------------------------


class TestCheckPolkitVersion:
    def _make_run_result(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        result = MagicMock()
        result.stdout = stdout
        result.stderr = stderr
        result.returncode = returncode
        return result

    def test_returns_version_string(self, handler: PrivilegeHandler) -> None:
        result = self._make_run_result(stdout="pkexec version 0.120\n")
        with patch("subprocess.run", return_value=result):
            version = handler.check_polkit_version()
        assert version == "0.120"

    def test_returns_version_from_stderr(self, handler: PrivilegeHandler) -> None:
        """Некоторые дистрибутивы выводят версию в stderr."""
        result = self._make_run_result(stderr="pkexec version 0.119\n")
        with patch("subprocess.run", return_value=result):
            version = handler.check_polkit_version()
        assert version == "0.119"

    def test_returns_none_when_pkexec_not_found(self, handler: PrivilegeHandler) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError):
            version = handler.check_polkit_version()
        assert version is None

    def test_returns_none_on_timeout(self, handler: PrivilegeHandler) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pkexec", 5)):
            version = handler.check_polkit_version()
        assert version is None

    def test_returns_none_when_version_not_parseable(self, handler: PrivilegeHandler) -> None:
        result = self._make_run_result(stdout="pkexec: unexpected output\n")
        with patch("subprocess.run", return_value=result):
            version = handler.check_polkit_version()
        assert version is None

    def test_logs_warning_for_old_version(self, handler: PrivilegeHandler) -> None:
        """Версия < 0.119 должна вызывать warning лога."""
        result = self._make_run_result(stdout="pkexec version 0.105\n")
        with patch("subprocess.run", return_value=result):
            import logging
            with patch.object(logging.getLogger("snxui.system.privilege_handler"), "warning") as mock_warn:
                handler.check_polkit_version()
                mock_warn.assert_called()

    def test_no_warning_for_safe_version(self, handler: PrivilegeHandler) -> None:
        """Версия >= 0.119 не должна вызывать warning лога."""
        result = self._make_run_result(stdout="pkexec version 0.120\n")
        with patch("subprocess.run", return_value=result):
            import logging
            with patch.object(logging.getLogger("snxui.system.privilege_handler"), "warning") as mock_warn:
                handler.check_polkit_version()
                mock_warn.assert_not_called()

    def test_version_124_ok(self, handler: PrivilegeHandler) -> None:
        """Версия 124 (как в системе) должна быть ок."""
        result = self._make_run_result(stdout="pkexec version 124\n")
        with patch("subprocess.run", return_value=result):
            version = handler.check_polkit_version()
        assert version == "124"

    def test_min_polkit_version_constant(self) -> None:
        """Минимальная версия должна быть (0, 119)."""
        assert _MIN_POLKIT_VERSION == (0, 119)


# ---------------------------------------------------------------------------
# run_snx_privileged()
# ---------------------------------------------------------------------------


class TestRunSnxPrivileged:
    def test_builds_correct_command(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """Команда должна быть: pkexec /path/to/snx <args>"""
        fake_snx = tmp_path / "snx"
        fake_snx.touch()

        mock_popen = MagicMock()
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/pkexec" if x == "pkexec" else None), \
             patch.object(PrivilegeHandler, "_find_snx", return_value=fake_snx), \
             patch("subprocess.Popen", return_value=mock_popen) as popen_mock:
            proc = handler.run_snx_privileged(["-s", "vpn.example.com", "-u", "alice"])

        popen_mock.assert_called_once()
        cmd = popen_mock.call_args[0][0]
        assert cmd[0] == "/usr/bin/pkexec"
        assert str(fake_snx) in cmd
        assert "-s" in cmd
        assert "vpn.example.com" in cmd
        assert "-u" in cmd
        assert "alice" in cmd

    def test_returns_popen_object(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """run_snx_privileged возвращает Popen объект."""
        fake_snx = tmp_path / "snx"
        fake_snx.touch()

        mock_popen = MagicMock(spec=subprocess.Popen)
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/pkexec" if x == "pkexec" else None), \
             patch.object(PrivilegeHandler, "_find_snx", return_value=fake_snx), \
             patch("subprocess.Popen", return_value=mock_popen):
            proc = handler.run_snx_privileged(["-d"])

        assert proc is mock_popen

    def test_raises_when_pkexec_not_found(self, handler: PrivilegeHandler) -> None:
        """FileNotFoundError если pkexec отсутствует."""
        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="pkexec"):
                handler.run_snx_privileged([])

    def test_raises_when_snx_not_found(self, handler: PrivilegeHandler) -> None:
        """FileNotFoundError если SNX binary отсутствует."""
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/pkexec" if x == "pkexec" else None), \
             patch.object(Path, "exists", return_value=False), \
             patch.object(Path, "is_file", return_value=False):
            with pytest.raises(FileNotFoundError, match="SNX binary"):
                handler.run_snx_privileged([])

    def test_popen_uses_pipes(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """Popen должен использовать PIPE для stdin/stdout/stderr."""
        fake_snx = tmp_path / "snx"
        fake_snx.touch()

        with patch("shutil.which", side_effect=lambda x: "/usr/bin/pkexec" if x == "pkexec" else None), \
             patch.object(PrivilegeHandler, "_find_snx", return_value=fake_snx), \
             patch("subprocess.Popen") as popen_mock:
            handler.run_snx_privileged(["-d"])

        kwargs = popen_mock.call_args[1]
        assert kwargs["stdin"] == subprocess.PIPE
        assert kwargs["stdout"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.PIPE


# ---------------------------------------------------------------------------
# install_policy()
# ---------------------------------------------------------------------------


class TestInstallPolicy:
    def test_returns_false_when_policy_file_missing(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        non_existent = tmp_path / "missing.policy"
        assert handler.install_policy(non_existent) is False

    def test_installs_via_pkexec(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """При наличии pkexec — использует pkexec cp."""
        policy_file = tmp_path / "com.snxui.policy"
        policy_file.write_text("<policy/>")

        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result) as run_mock:
            result = handler.install_policy(policy_file)

        assert result is True
        run_mock.assert_called()
        cmd = run_mock.call_args[0][0]
        assert "pkexec" in cmd or "sudo" in cmd

    def test_falls_back_to_sudo(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """При ошибке pkexec — пробует sudo cp."""
        policy_file = tmp_path / "com.snxui.policy"
        policy_file.write_text("<policy/>")

        def run_side_effect(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "pkexec":
                result.returncode = 1
                result.stderr = "not authorized"
            else:
                result.returncode = 0
                result.stderr = ""
            return result

        with patch("subprocess.run", side_effect=run_side_effect):
            result = handler.install_policy(policy_file)

        assert result is True

    def test_returns_false_when_all_methods_fail(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """Если все методы установки не сработали — возвращает False."""
        policy_file = tmp_path / "com.snxui.policy"
        policy_file.write_text("<policy/>")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "permission denied"
        with patch("subprocess.run", return_value=mock_result):
            result = handler.install_policy(policy_file)

        assert result is False

    def test_returns_false_when_pkexec_and_sudo_not_found(
        self, handler: PrivilegeHandler, tmp_path: Path
    ) -> None:
        """Если pkexec и sudo не найдены — возвращает False."""
        policy_file = tmp_path / "com.snxui.policy"
        policy_file.write_text("<policy/>")

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = handler.install_policy(policy_file)

        assert result is False


# ---------------------------------------------------------------------------
# _find_snx() private method
# ---------------------------------------------------------------------------


class TestFindSnx:
    def test_finds_snx_at_usr_bin(self, handler: PrivilegeHandler, tmp_path: Path) -> None:
        """Находит SNX binary по стандартному пути."""
        fake_snx = tmp_path / "snx"
        fake_snx.touch()

        original_paths = handler._SNX_PATHS[:]
        handler._SNX_PATHS = [fake_snx]
        try:
            result = handler._find_snx()
            assert result == fake_snx
        finally:
            handler._SNX_PATHS = original_paths

    def test_falls_back_to_which(self, handler: PrivilegeHandler) -> None:
        """Если стандартные пути не дают результат — использует shutil.which."""
        with patch.object(Path, "exists", return_value=False), \
             patch("shutil.which", side_effect=lambda x: "/custom/snx" if x == "snx" else None):
            result = handler._find_snx()
            assert str(result) == "/custom/snx"

    def test_raises_when_not_found(self, handler: PrivilegeHandler) -> None:
        """FileNotFoundError если SNX нигде не найден."""
        with patch.object(Path, "exists", return_value=False), \
             patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="SNX binary"):
                handler._find_snx()


# ---------------------------------------------------------------------------
# Константы и атрибуты класса
# ---------------------------------------------------------------------------


class TestPolkitActions:
    def test_polkit_action_constant(self, handler: PrivilegeHandler) -> None:
        assert handler.POLKIT_ACTION == "com.snxui.connect"

    def test_polkit_disconnect_action_constant(self, handler: PrivilegeHandler) -> None:
        assert handler.POLKIT_DISCONNECT_ACTION == "com.snxui.disconnect"
