"""Tests for snxui.core.snx_backend.

pexpect.spawn and subprocess calls are mocked throughout so these tests run
without an actual SNX installation or network access.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from snxui.core.snx_backend import (
    SNXBackend,
    _RE_PASSWORD,
    _RE_CONNECTED,
    _RE_AUTH_FAILED,
    _RE_CONN_FAILED,
    _RE_ALREADY,
    _RE_DISCONNECTED,
    _RE_OFFICE_IP,
    _SNX_SEARCH_PATHS,
)
from snxui.core.types import ConnectionState, Profile


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def profile() -> Profile:
    return Profile(name="Test", server="vpn.example.com", username="bob")


@pytest.fixture()
def backend() -> SNXBackend:
    b = SNXBackend()
    # Point directly to a fake binary so _find_snx_binary() doesn't search disk.
    b._snx_binary = "/fake/snx"
    return b


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------


class TestRegexPatterns:
    @pytest.mark.parametrize("text", [
        "Password:",
        "password:",
        "Enter password:",
        "Enter Password:",
    ])
    def test_password_prompt(self, text: str) -> None:
        assert _RE_PASSWORD.search(text)

    @pytest.mark.parametrize("text", [
        "SNX - Connected.",
        "Tunnel is up",
        "Connection established",
        "Session parameters:",
    ])
    def test_connected(self, text: str) -> None:
        assert _RE_CONNECTED.search(text)

    @pytest.mark.parametrize("text", [
        "Authentication failed",
        "Invalid password",
        "Access denied",
        "Login failed",
    ])
    def test_auth_failed(self, text: str) -> None:
        assert _RE_AUTH_FAILED.search(text)

    @pytest.mark.parametrize("text", [
        "Connection failed",
        "Cannot connect",
    ])
    def test_conn_failed(self, text: str) -> None:
        assert _RE_CONN_FAILED.search(text)

    @pytest.mark.parametrize("text", [
        "already connected",
        "SNX is already running",
    ])
    def test_already(self, text: str) -> None:
        assert _RE_ALREADY.search(text)

    @pytest.mark.parametrize("text", [
        "SNX disconnected",
        "Disconnected successfully",
        "Session terminated",
    ])
    def test_disconnected(self, text: str) -> None:
        assert _RE_DISCONNECTED.search(text)

    def test_office_ip_extraction(self) -> None:
        text = "    Office Mode IP      : 10.200.0.5\n"
        m = _RE_OFFICE_IP.search(text)
        assert m is not None
        assert m.group(1) == "10.200.0.5"


# ---------------------------------------------------------------------------
# _find_snx_binary
# ---------------------------------------------------------------------------


class TestFindSnxBinary:
    def test_returns_cached_binary(self, backend: SNXBackend) -> None:
        backend._snx_binary = "/already/cached"
        assert backend._find_snx_binary() == "/already/cached"

    def test_finds_from_search_paths(self, tmp_path: Path) -> None:
        fake_snx = tmp_path / "snx"
        fake_snx.touch()
        b = SNXBackend()
        b._snx_binary = None
        # Temporarily prepend the fake binary to the global search path list.
        _SNX_SEARCH_PATHS.insert(0, fake_snx)
        try:
            result = b._find_snx_binary()
            assert result == str(fake_snx)
        finally:
            _SNX_SEARCH_PATHS.remove(fake_snx)
            b._snx_binary = None

    def test_raises_when_not_found(self) -> None:
        b = SNXBackend()
        b._snx_binary = None
        with patch("shutil.which", return_value=None), \
             patch.object(Path, "exists", return_value=False):
            with pytest.raises(FileNotFoundError, match="SNX binary not found"):
                b._find_snx_binary()


# ---------------------------------------------------------------------------
# _build_args
# ---------------------------------------------------------------------------


class TestBuildArgs:
    def test_minimal_args(self, backend: SNXBackend, profile: Profile) -> None:
        args = backend._build_args(profile)
        assert "-s" in args
        assert "vpn.example.com" in args
        assert "-u" in args
        assert "bob" in args

    def test_custom_port(self, backend: SNXBackend, profile: Profile) -> None:
        profile.ssl_port = 8443
        args = backend._build_args(profile)
        assert "-p" in args
        assert "8443" in args

    def test_default_port_not_in_args(self, backend: SNXBackend, profile: Profile) -> None:
        args = backend._build_args(profile)
        assert "-p" not in args

    def test_certificate_included(self, backend: SNXBackend, profile: Profile) -> None:
        profile.certificate = "/home/user/cert.pem"
        args = backend._build_args(profile)
        assert "-c" in args
        assert "/home/user/cert.pem" in args

    def test_no_reauth_flag(self, backend: SNXBackend, profile: Profile) -> None:
        profile.reauth = False
        args = backend._build_args(profile)
        assert "-n" in args

    def test_cipher_included(self, backend: SNXBackend, profile: Profile) -> None:
        profile.cipher = "AES256"
        args = backend._build_args(profile)
        assert "-Z" in args
        assert "AES256" in args


# ---------------------------------------------------------------------------
# _parse_office_ip
# ---------------------------------------------------------------------------


class TestParseOfficeIP:
    def test_parses_ip(self) -> None:
        text = "Office Mode IP      : 192.168.1.100"
        assert SNXBackend._parse_office_ip(text) == "192.168.1.100"

    def test_returns_none_on_no_match(self) -> None:
        assert SNXBackend._parse_office_ip("no ip here") is None


# ---------------------------------------------------------------------------
# connect() — mocked pexpect
# ---------------------------------------------------------------------------


def _make_child_mock(expect_side_effects: list) -> MagicMock:
    """Build a mock pexpect child with pre-programmed expect() return values."""
    child = MagicMock()
    child.expect.side_effect = expect_side_effects
    child.before = ""
    child.after = ""
    child.close.return_value = None
    child.sendline.return_value = None
    return child


class TestConnect:
    def _patch_pexpect(self, child_mock):
        return patch("snxui.core.snx_backend.pexpect.spawn", return_value=child_mock)

    def _patch_tunsnx(self, exists: bool):
        return patch.object(SNXBackend, "_tunsnx_exists", return_value=exists)

    def _patch_monitor(self):
        return patch.object(SNXBackend, "_start_monitor")

    def test_connect_success(self, backend: SNXBackend, profile: Profile) -> None:
        child = _make_child_mock([0, 0])  # password prompt, then connected
        child.before = "Office Mode IP      : 10.1.1.1\n"
        child.after = "SNX - Connected.\n"

        with self._patch_pexpect(child), self._patch_tunsnx(False), self._patch_monitor():
            result = backend.connect(profile, "password123")

        assert result is True
        assert backend._status.state == ConnectionState.CONNECTED

    def test_connect_auth_failed(self, backend: SNXBackend, profile: Profile) -> None:
        child = _make_child_mock([0, 1])  # password prompt, then auth failed

        with self._patch_pexpect(child), self._patch_monitor():
            result = backend.connect(profile, "wrongpass")

        assert result is False
        assert backend._status.state == ConnectionState.ERROR
        assert "Authentication" in (backend._status.error_message or "")

    def test_connect_already_connected(self, backend: SNXBackend, profile: Profile) -> None:
        child = _make_child_mock([1])  # already connected pattern at first expect

        with self._patch_pexpect(child):
            with patch.object(SNXBackend, "get_status") as mock_get:
                from snxui.core.types import ConnectionStatus
                mock_get.return_value = ConnectionStatus(
                    state=ConnectionState.CONNECTED,
                    ip_address="10.0.0.1",
                )
                result = backend.connect(profile, "any")

        assert result is True

    def test_connect_connection_failed_before_prompt(self, backend: SNXBackend, profile: Profile) -> None:
        child = _make_child_mock([2])  # conn failed before password prompt

        with self._patch_pexpect(child):
            result = backend.connect(profile, "pass")

        assert result is False
        assert backend._status.state == ConnectionState.ERROR

    def test_connect_timeout(self, backend: SNXBackend, profile: Profile) -> None:
        child = _make_child_mock([4])  # TIMEOUT at password prompt

        with self._patch_pexpect(child):
            result = backend.connect(profile, "pass")

        assert result is False

    def test_connect_raises_when_pexpect_missing(self, profile: Profile) -> None:
        b = SNXBackend()
        b._snx_binary = "/fake/snx"
        with patch("snxui.core.snx_backend.pexpect", None):
            with pytest.raises(RuntimeError, match="pexpect is required"):
                b.connect(profile, "pass")

    def test_connect_calls_status_callback(self, backend: SNXBackend, profile: Profile) -> None:
        child = _make_child_mock([0, 0])
        child.before = ""
        child.after = "SNX - Connected."

        statuses: list[ConnectionState] = []

        def cb(s):
            statuses.append(s.state)

        with self._patch_pexpect(child), self._patch_tunsnx(False), self._patch_monitor():
            backend.connect(profile, "pass", status_callback=cb)

        assert ConnectionState.CONNECTING in statuses
        assert ConnectionState.CONNECTED in statuses

    def test_connect_passes_compiled_regex_to_expect(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """connect() must pass compiled regex objects — not .pattern strings — to
        pexpect.expect().

        pexpect.expect() accepts either string patterns or compiled regex objects.
        When passed a *string*, pexpect recompiles it with ``re.DOTALL`` only,
        silently dropping ``re.IGNORECASE``.  Patterns like ``_RE_AUTH_FAILED``
        (compiled with IGNORECASE) would then fail to match SNX output in
        unexpected casing, e.g. ``"authentication failed"`` vs
        ``"Authentication failed"``.

        Passing the compiled regex object directly preserves the original flags.
        """
        import re as _re

        child = _make_child_mock([0, 0])
        child.before = ""
        child.after = "SNX - Connected."

        with self._patch_pexpect(child), self._patch_tunsnx(False), self._patch_monitor():
            backend.connect(profile, "pass")

        # Every expect() call must receive compiled regex objects, not strings.
        for call in child.expect.call_args_list:
            patterns = call[0][0]
            for p in patterns:
                assert not isinstance(p, str), (
                    f"pexpect.expect() received a raw string pattern {p!r}. "
                    "Pass compiled regex objects so re.IGNORECASE is preserved."
                )


# ---------------------------------------------------------------------------
# disconnect() — mocked pexpect
# ---------------------------------------------------------------------------


class TestDisconnect:
    def _patch_pexpect(self, child_mock):
        return patch("snxui.core.snx_backend.pexpect.spawn", return_value=child_mock)

    def test_disconnect_success(self, backend: SNXBackend) -> None:
        child = _make_child_mock([0])  # disconnected confirmation

        with self._patch_pexpect(child), \
             patch.object(SNXBackend, "_stop_monitor"):
            result = backend.disconnect()

        assert result is True
        assert backend._status.state == ConnectionState.DISCONNECTED

    def test_disconnect_success_via_tunsnx_gone(self, backend: SNXBackend) -> None:
        """EOF response but tunsnx is gone — still success."""
        child = _make_child_mock([1])  # EOF

        with self._patch_pexpect(child), \
             patch.object(SNXBackend, "_stop_monitor"), \
             patch.object(SNXBackend, "_tunsnx_exists", return_value=False):
            result = backend.disconnect()

        assert result is True

    def test_disconnect_raises_when_pexpect_missing(self, backend: SNXBackend) -> None:
        with patch("snxui.core.snx_backend.pexpect", None):
            with pytest.raises(RuntimeError, match="pexpect is required"):
                backend.disconnect()


# ---------------------------------------------------------------------------
# get_status() — mocked ip commands
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_connected_when_tunsnx_exists(self, backend: SNXBackend) -> None:
        with patch.object(SNXBackend, "_tunsnx_exists", return_value=True), \
             patch.object(SNXBackend, "_get_tunsnx_ip", return_value="10.5.5.5"):
            status = backend.get_status()
        assert status.state == ConnectionState.CONNECTED
        assert status.ip_address == "10.5.5.5"
        assert status.interface == "tunsnx"

    def test_disconnected_when_no_tunsnx(self, backend: SNXBackend) -> None:
        with patch.object(SNXBackend, "_tunsnx_exists", return_value=False):
            status = backend.get_status()
        assert status.state == ConnectionState.DISCONNECTED

    def test_connected_to_disconnected_on_drop(self, backend: SNXBackend) -> None:
        """If state was CONNECTED but tunsnx disappears, status becomes DISCONNECTED."""
        backend._status.state = ConnectionState.CONNECTED
        with patch.object(SNXBackend, "_tunsnx_exists", return_value=False):
            status = backend.get_status()
        assert status.state == ConnectionState.DISCONNECTED


# ---------------------------------------------------------------------------
# _tunsnx_exists / _get_tunsnx_ip (integration-style with mocked subprocess)
# ---------------------------------------------------------------------------


class TestTunsnxHelpers:
    def test_tunsnx_exists_true(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            assert SNXBackend._tunsnx_exists() is True

    def test_tunsnx_exists_false(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        with patch("subprocess.run", return_value=mock_result):
            assert SNXBackend._tunsnx_exists() is False

    def test_tunsnx_exists_subprocess_error(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.SubprocessError):
            assert SNXBackend._tunsnx_exists() is False

    def test_get_tunsnx_ip(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "    inet 10.200.0.5/24 brd 10.200.0.255 scope global tunsnx\n"
        with patch("subprocess.run", return_value=mock_result):
            assert SNXBackend._get_tunsnx_ip() == "10.200.0.5"

    def test_get_tunsnx_ip_none_on_failure(self) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            assert SNXBackend._get_tunsnx_ip() is None
