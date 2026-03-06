"""Tests for snxui.core.snx_rs_backend.

subprocess calls (snx-rs, snxctl) are mocked throughout so these tests run
without snx-rs installed or network access.
"""

from __future__ import annotations

import base64
import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

from snxui.core.snx_rs_backend import SNXRsBackend
from snxui.core.types import ConnectionState, ConnectionStatus, Profile, TunnelType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def profile() -> Profile:
    return Profile(
        name="Test",
        server="vpn.example.com",
        username="alice",
        login_type="vpn_ssl_vpn",
        backend="snx_rs",
    )


@pytest.fixture()
def backend() -> SNXRsBackend:
    return SNXRsBackend()


# ---------------------------------------------------------------------------
# _parse_status
# ---------------------------------------------------------------------------


class TestParseStatus:
    def test_connected_with_ip(self, backend: SNXRsBackend) -> None:
        output = "Status: Connected\nIP address: 10.200.0.5\nInterface: tunsnx0"
        status = backend._parse_status(output)
        assert status.state == ConnectionState.CONNECTED
        assert status.ip_address == "10.200.0.5"

    def test_connected_no_ip(self, backend: SNXRsBackend) -> None:
        status = backend._parse_status("Status: Connected")
        assert status.state == ConnectionState.CONNECTED
        assert status.ip_address is None

    def test_disconnected(self, backend: SNXRsBackend) -> None:
        status = backend._parse_status("Status: Disconnected")
        assert status.state == ConnectionState.DISCONNECTED

    def test_not_connected(self, backend: SNXRsBackend) -> None:
        status = backend._parse_status("not connected")
        assert status.state == ConnectionState.DISCONNECTED

    def test_connecting(self, backend: SNXRsBackend) -> None:
        status = backend._parse_status("Status: Connecting...")
        assert status.state == ConnectionState.CONNECTING

    def test_error(self, backend: SNXRsBackend) -> None:
        status = backend._parse_status("Error: authentication failed")
        assert status.state == ConnectionState.ERROR
        assert "authentication failed" in status.error_message.lower()

    def test_empty_output_is_disconnected(self, backend: SNXRsBackend) -> None:
        status = backend._parse_status("")
        assert status.state == ConnectionState.DISCONNECTED

    def test_disconnected_takes_priority_over_connected(self, backend: SNXRsBackend) -> None:
        # "not connected" contains "connected" as a substring — make sure we
        # return DISCONNECTED, not CONNECTED.
        status = backend._parse_status("Status: not connected")
        assert status.state == ConnectionState.DISCONNECTED


# ---------------------------------------------------------------------------
# _build_config
# ---------------------------------------------------------------------------


class TestBuildConfig:
    def test_basic_config(self, backend: SNXRsBackend, profile: Profile) -> None:
        config = backend._build_config(profile)
        assert "server-name = vpn.example.com" in config
        assert "user-name = alice" in config
        assert "login-type = vpn_ssl_vpn" in config
        assert "tunnel-type = ssl" in config
        assert "transport-type = auto" in config
        assert "ignore-server-cert = false" in config
        assert "no-keychain = true" in config

    def test_ipsec_tunnel(self, backend: SNXRsBackend, profile: Profile) -> None:
        profile.tunnel_type = TunnelType.IPSEC
        config = backend._build_config(profile)
        assert "tunnel-type = ipsec" in config

    def test_transport_type(self, backend: SNXRsBackend, profile: Profile) -> None:
        profile.transport_type = "udp"
        config = backend._build_config(profile)
        assert "transport-type = udp" in config

    def test_ignore_cert(self, backend: SNXRsBackend, profile: Profile) -> None:
        profile.ignore_server_cert = True
        config = backend._build_config(profile)
        assert "ignore-server-cert = true" in config

    def test_no_login_type_skips_line(self, backend: SNXRsBackend, profile: Profile) -> None:
        profile.login_type = ""
        config = backend._build_config(profile)
        assert "login-type" not in config

    def test_config_ends_with_newline(self, backend: SNXRsBackend, profile: Profile) -> None:
        config = backend._build_config(profile)
        assert config.endswith("\n")

    def test_with_password(self, backend: SNXRsBackend, profile: Profile) -> None:
        config = backend._build_config(profile, password="secret")
        expected = f"password = {base64.b64encode(b'secret').decode()}"
        assert expected in config

    def test_with_mfa_code(self, backend: SNXRsBackend, profile: Profile) -> None:
        config = backend._build_config(profile, mfa_code="123456")
        assert "mfa-code = 123456" in config

    def test_no_password_by_default(self, backend: SNXRsBackend, profile: Profile) -> None:
        config = backend._build_config(profile)
        assert "password" not in config

    def test_no_mfa_by_default(self, backend: SNXRsBackend, profile: Profile) -> None:
        config = backend._build_config(profile)
        assert "mfa-code" not in config


class TestWriteConfig:
    """_write_config must create the file with 0o600 permissions atomically."""

    def test_creates_file_with_restricted_permissions(
        self, backend: SNXRsBackend, profile: Profile, tmp_path: "Path"
    ) -> None:
        """Config file must be created owner-only (0o600), not world-readable."""
        import os
        import stat
        from unittest.mock import patch as _patch

        config_path = tmp_path / "snx-rs.conf"
        with _patch("snxui.core.snx_rs_backend._CONFIG_PATH", config_path):
            backend._write_config(profile, password="s3cr3t")

        assert config_path.exists()
        mode = stat.S_IMODE(os.stat(config_path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_password_not_in_config_after_cleanup_write(
        self, backend: SNXRsBackend, profile: Profile, tmp_path: "Path"
    ) -> None:
        """Second call without password must overwrite and remove credentials."""
        from unittest.mock import patch as _patch

        config_path = tmp_path / "snx-rs.conf"
        with _patch("snxui.core.snx_rs_backend._CONFIG_PATH", config_path):
            backend._write_config(profile, password="s3cr3t")
            assert "password" in config_path.read_text()
            # Cleanup write (no password)
            backend._write_config(profile)
            assert "password" not in config_path.read_text()


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_returns_cached_when_snxctl_not_found(self, backend: SNXRsBackend) -> None:
        with patch("shutil.which", return_value=None):
            status = backend.get_status()
        assert status.state == ConnectionState.DISCONNECTED

    def test_probes_snxctl(self, backend: SNXRsBackend) -> None:
        mock_result = MagicMock()
        mock_result.stdout = "Status: Connected\nIP address: 192.168.1.1"
        mock_result.stderr = ""
        with patch("shutil.which", return_value="/usr/bin/snxctl"), \
             patch("subprocess.run", return_value=mock_result):
            status = backend.get_status()
        assert status.state == ConnectionState.CONNECTED
        assert status.ip_address == "192.168.1.1"

    def test_falls_back_to_cached_on_timeout(self, backend: SNXRsBackend) -> None:
        with patch("shutil.which", return_value="/usr/bin/snxctl"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired([], 5)):
            status = backend.get_status()
        assert status.state == ConnectionState.DISCONNECTED


# ---------------------------------------------------------------------------
# disconnect
# ---------------------------------------------------------------------------


class TestDisconnect:
    def test_success(self, backend: SNXRsBackend) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Disconnected."
        mock_result.stderr = ""
        with patch("shutil.which", return_value="/usr/bin/snxctl"), \
             patch("subprocess.run", return_value=mock_result) as mock_run:
            result = backend.disconnect()
        assert result is True
        mock_run.assert_called_once_with(
            ["/usr/bin/snxctl", "disconnect"],
            capture_output=True, text=True, timeout=15,
        )

    def test_snxctl_not_found(self, backend: SNXRsBackend) -> None:
        with patch("shutil.which", return_value=None):
            result = backend.disconnect()
        assert result is False
        assert backend.get_cached_status().state == ConnectionState.ERROR

    def test_nonzero_returncode_returns_false(self, backend: SNXRsBackend) -> None:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "daemon not running"
        with patch("shutil.which", return_value="/usr/bin/snxctl"), \
             patch("subprocess.run", return_value=mock_result):
            result = backend.disconnect()
        assert result is False
        assert backend.get_cached_status().state == ConnectionState.ERROR

    def test_subprocess_error(self, backend: SNXRsBackend) -> None:
        with patch("shutil.which", return_value="/usr/bin/snxctl"), \
             patch("subprocess.run", side_effect=OSError("pipe broken")):
            result = backend.disconnect()
        assert result is False


# ---------------------------------------------------------------------------
# connect — success path
# ---------------------------------------------------------------------------


class TestConnectSuccess:
    def test_connect_without_mfa(self, backend: SNXRsBackend, profile: Profile) -> None:
        """Full connect flow with no MFA."""
        statuses: list[ConnectionStatus] = []

        poll_result = MagicMock()
        poll_result.stdout = "Status: Connected\nIP address: 10.0.0.1"
        poll_result.stderr = ""

        # subprocess.run is only called for snxctl status polls; snxctl connect
        # is handled by the mocked _snxctl_connect.
        run_calls = [MagicMock(stdout="", stderr=""), poll_result]

        with patch("snxui.core.snx_rs_backend.shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("snxui.core.snx_rs_backend.subprocess.run", side_effect=run_calls), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._write_config"), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._ensure_daemon", return_value=True), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._snxctl_connect"), \
             patch("snxui.core.snx_rs_backend.time.sleep"), \
             patch("snxui.core.snx_rs_backend.time.monotonic", side_effect=[0.0, 0.0, 1.0]):
            result = backend.connect(
                profile, "secret",
                status_callback=statuses.append,
                two_factor_callback=None,
            )

        assert result is True
        assert any(s.state == ConnectionState.CONNECTED for s in statuses)

    def test_connect_calls_mfa_callback(
        self, backend: SNXRsBackend, profile: Profile
    ) -> None:
        """two_factor_callback is called; mfa-code is passed to _write_config and _snxctl_connect."""
        mfa_calls: list[str] = []

        def _mfa(prompt: str) -> str:
            mfa_calls.append(prompt)
            return "123456"

        poll_result = MagicMock(stdout="Status: Connected\nIP address: 10.0.0.2", stderr="")

        with patch("snxui.core.snx_rs_backend.shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("snxui.core.snx_rs_backend.subprocess.run", return_value=poll_result), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._write_config") as mock_write, \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._ensure_daemon", return_value=True), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._snxctl_connect") as mock_snxctl, \
             patch("snxui.core.snx_rs_backend.time.sleep"), \
             patch("snxui.core.snx_rs_backend.time.monotonic", side_effect=[0.0, 0.0, 1.0]):
            result = backend.connect(
                profile, "secret",
                status_callback=None,
                two_factor_callback=_mfa,
            )

        assert result is True
        assert mfa_calls, "MFA callback was not called"
        # Verify mfa-code was passed to _write_config (first call: profile, password, mfa_code).
        first_write_args = mock_write.call_args_list[0][0]
        assert "123456" in first_write_args
        # Verify mfa-code was also forwarded to _snxctl_connect for PTY injection.
        snxctl_call_args = mock_snxctl.call_args[0]
        assert "123456" in snxctl_call_args

    def test_connect_mfa_cancel_returns_false(
        self, backend: SNXRsBackend, profile: Profile
    ) -> None:
        """Returning None from two_factor_callback aborts the connection."""
        with patch("snxui.core.snx_rs_backend.shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._write_config"), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._ensure_daemon", return_value=True):
            result = backend.connect(
                profile, "secret",
                two_factor_callback=lambda _prompt: None,
            )
        assert result is False

    def test_connect_snxctl_failure_returns_false(
        self, backend: SNXRsBackend, profile: Profile
    ) -> None:
        """RuntimeError from _snxctl_connect → connect returns False."""
        with patch("snxui.core.snx_rs_backend.shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._write_config"), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._ensure_daemon", return_value=True), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._snxctl_connect",
                   side_effect=RuntimeError("auth failed")):
            result = backend.connect(profile, "bad_password")
        assert result is False

    def test_connect_snxctl_not_found_returns_false(
        self, backend: SNXRsBackend, profile: Profile
    ) -> None:
        with patch("snxui.core.snx_rs_backend.shutil.which", return_value=None), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._write_config"), \
             patch("snxui.core.snx_rs_backend.SNXRsBackend._ensure_daemon", return_value=True):
            result = backend.connect(profile, "secret")
        assert result is False


# ---------------------------------------------------------------------------
# _snxctl_connect
# ---------------------------------------------------------------------------


class TestSnxctlConnect:
    """pexpect.spawn is patched globally; mock_child controls PTY interaction."""

    @staticmethod
    def _make_child(expect_side_effect, exitstatus=0, before=""):
        child = MagicMock()
        child.before = before
        child.exitstatus = exitstatus
        child.isalive.return_value = False
        child.match = MagicMock()
        child.match.group.return_value = "code"
        if isinstance(expect_side_effect, list):
            child.expect.side_effect = expect_side_effect
        else:
            child.expect.return_value = expect_side_effect
        return child

    def test_success_no_mfa(self, backend: SNXRsBackend) -> None:
        """snxctl connect exits 0 without MFA prompt → success."""
        child = self._make_child(expect_side_effect=1)  # 1 = EOF
        with patch("pexpect.spawn", return_value=child):
            backend._snxctl_connect("/usr/bin/snxctl", mfa_code=None)
        child.sendline.assert_not_called()

    def test_injects_mfa_when_prompted(self, backend: SNXRsBackend) -> None:
        """Daemon MFA prompt → mfa_code is sent, then EOF → success."""
        child = self._make_child(
            expect_side_effect=[0, 1],  # 0 = MFA prompt, 1 = EOF
            before="Enter your one-time password",
        )
        with patch("pexpect.spawn", return_value=child):
            backend._snxctl_connect("/usr/bin/snxctl", mfa_code="654321")
        child.sendline.assert_called_once_with("654321")

    def test_raises_when_prompted_without_mfa(self, backend: SNXRsBackend) -> None:
        """Daemon MFA prompt but no code available → RuntimeError."""
        child = self._make_child(expect_side_effect=0, before="Enter code")
        with patch("pexpect.spawn", return_value=child):
            with pytest.raises(RuntimeError, match="no MFA code"):
                backend._snxctl_connect("/usr/bin/snxctl", mfa_code=None)

    def test_raises_on_nonzero_exit(self, backend: SNXRsBackend) -> None:
        """snxctl connect exits non-zero → RuntimeError."""
        child = self._make_child(
            expect_side_effect=1, exitstatus=1, before="authentication failed"
        )
        with patch("pexpect.spawn", return_value=child):
            with pytest.raises(RuntimeError, match="authentication failed"):
                backend._snxctl_connect("/usr/bin/snxctl", mfa_code=None)

    def test_mfa_pattern_does_not_match_descriptive_text(self) -> None:
        """Regex pattern must NOT match 'password' in descriptive text without trailing : or ?."""
        import re
        # Mirror the pattern from snx_rs_backend._snxctl_connect().
        pattern = re.compile(
            r"(?i)\b(password|code|pin|otp|token|one.time|passcode|"
            r"verification|enter|factor)\s*[:\?]"
        )
        # Should NOT match descriptive text (no colon/question mark after keyword).
        assert not pattern.search("please provide password to authenticate")
        assert not pattern.search("Additional authentication required, please provide password")
        # SHOULD match actual prompts.
        assert pattern.search("Password:")
        assert pattern.search("Enter code:")
        assert pattern.search("OTP?")
        assert pattern.search("One-time password:")


# ---------------------------------------------------------------------------
# _ensure_daemon
# ---------------------------------------------------------------------------


class TestEnsureDaemon:
    def test_daemon_already_running(self, backend: SNXRsBackend) -> None:
        status_result = MagicMock(returncode=0, stdout="Status: Disconnected", stderr="")
        with patch("snxui.core.snx_rs_backend.shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("subprocess.run", return_value=status_result):
            result = backend._ensure_daemon()
        assert result is True

    def test_daemon_not_running_launches_it(self, backend: SNXRsBackend) -> None:
        # Status check fails (daemon not up), then Popen is called to start snx-rs.
        status_result = MagicMock(returncode=1, stdout="", stderr="not running")
        with patch("snxui.core.snx_rs_backend.shutil.which", side_effect=lambda x: f"/usr/bin/{x}"), \
             patch("subprocess.run", return_value=status_result), \
             patch("subprocess.Popen") as mock_popen, \
             patch("snxui.core.snx_rs_backend.time.sleep"):
            result = backend._ensure_daemon()
        assert result is True
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        # snx-rs uses "-m command" (daemon mode), not "--daemon".
        assert "-m" in cmd
        assert "command" in cmd

    def test_snx_rs_not_found_returns_false(self, backend: SNXRsBackend) -> None:
        with patch("snxui.core.snx_rs_backend.shutil.which", return_value=None):
            result = backend._ensure_daemon()
        assert result is False


# ---------------------------------------------------------------------------
# BackendFactory integration
# ---------------------------------------------------------------------------


class TestBackendFactory:
    def test_creates_snx_rs_backend_when_requested(self) -> None:
        from snxui.core.vpn_backend import BackendFactory

        profile = Profile(
            name="Test", server="vpn.example.com", username="alice", backend="snx_rs",
        )
        with patch("snxui.core.vpn_backend.detect_snx_rs", return_value=True):
            b = BackendFactory.create(profile)
        assert isinstance(b, SNXRsBackend)

    def test_raises_if_snx_rs_requested_but_not_installed(self) -> None:
        from snxui.core.vpn_backend import BackendFactory

        profile = Profile(
            name="Test", server="vpn.example.com", username="alice", backend="snx_rs",
        )
        with patch("snxui.core.vpn_backend.detect_snx_rs", return_value=False), \
             pytest.raises(RuntimeError, match="snx-rs/snxctl is not found"):
            BackendFactory.create(profile)

    def test_auto_uses_python_ssl(self) -> None:
        """'auto' now resolves to PythonSSLBackend — no snx-rs or snx binary needed."""
        from snxui.core.vpn_backend import BackendFactory
        from snxui.core.ssl_tunnel_backend import PythonSSLBackend

        profile = Profile(
            name="Test", server="vpn.example.com", username="alice", backend="auto",
        )
        b = BackendFactory.create(profile)
        assert isinstance(b, PythonSSLBackend)

    def test_snx_backend_creates_snx_binary_backend(self) -> None:
        from snxui.core.vpn_backend import BackendFactory
        from snxui.core.snx_backend import SNXBinaryBackend

        profile = Profile(
            name="Test", server="vpn.example.com", username="alice", backend="snx",
        )
        b = BackendFactory.create(profile)
        assert isinstance(b, SNXBinaryBackend)
