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
    _RE_2FA_ANY,
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

    def test_ca_list_included_in_cert_mode(self, backend: SNXBackend, profile: Profile) -> None:
        """CA dir (-l) is passed only when certificate auth is used.

        Some SNX builds (e.g. 800008409) scan the -l directory for *client*
        certificates and incorrectly report "cannot use both user/pass and
        certificate auth" when -l is combined with -u.  We therefore omit
        -l in username/password mode.
        """
        profile.certificate = "/home/user/cert.pem"
        profile.ca_list = "/etc/custom/certs"
        args = backend._build_args(profile)
        assert "-l" in args
        assert "/etc/custom/certs" in args

    def test_ca_list_not_passed_in_username_mode(self, backend: SNXBackend, profile: Profile) -> None:
        """CA dir is NOT passed in username/password mode to avoid SNX build 800008409 bug."""
        profile.certificate = None
        profile.ca_list = "/etc/custom/certs"
        args = backend._build_args(profile)
        assert "-l" not in args

    def test_empty_ca_list_not_in_args(self, backend: SNXBackend, profile: Profile) -> None:
        """When ca_list is cleared, -l must be absent from the SNX command line."""
        profile.certificate = "/home/user/cert.pem"
        profile.ca_list = ""
        args = backend._build_args(profile)
        assert "-l" not in args

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
        child = _make_child_mock([0, 3])  # password prompt, then auth failed (idx=3)

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

    def test_connect_success_stores_ip_in_status(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """After a successful connect, ip_address must be stored in the status.

        connect() calls _parse_office_ip(full_output) where full_output =
        child.before + child.after.  The parsed IP must end up in
        backend._status.ip_address.  Previously test_connect_success only
        checked the state, leaving the IP-extraction integration path
        unverified.
        """
        child = _make_child_mock([0, 0])
        child.before = "Office Mode IP      : 10.1.1.1\n"
        child.after = "SNX - Connected.\n"

        with self._patch_pexpect(child), self._patch_tunsnx(False), self._patch_monitor():
            result = backend.connect(profile, "password123")

        assert result is True
        assert backend._status.ip_address == "10.1.1.1"

    def test_connect_pexpect_exception_sets_error_status(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """A pexpect exception during connect sets ERROR state and returns False.

        Covers the ``except pexpect.exceptions.ExceptionPexpect`` handler in
        ``connect()``.  This path fires when the PTY itself errors (TTY
        allocation failure, child process crash, etc.) rather than when SNX
        outputs a recognisable failure pattern.
        """
        import pexpect as _pexpect

        child = _make_child_mock([])
        child.expect.side_effect = _pexpect.exceptions.ExceptionPexpect("PTY error")

        with self._patch_pexpect(child):
            result = backend.connect(profile, "pass")

        assert result is False
        assert backend._status.state == ConnectionState.ERROR
        assert "pexpect error" in (backend._status.error_message or "")

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

    def test_disconnect_failure_when_tunsnx_still_up(self, backend: SNXBackend) -> None:
        """EOF response but tunsnx is still up — disconnect failed.

        Covers _verify_disconnect_result() returning False: this is the backend
        path that triggers get_cached_status() in the UI (Round 6 fix).
        """
        child = _make_child_mock([1])  # EOF, no explicit disconnect confirmation

        with self._patch_pexpect(child), \
             patch.object(SNXBackend, "_stop_monitor"), \
             patch.object(SNXBackend, "_tunsnx_exists", return_value=True):
            result = backend.disconnect()

        assert result is False
        assert backend._status.state == ConnectionState.ERROR
        assert "Disconnect may not have succeeded" in (backend._status.error_message or "")

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

    def test_get_status_updates_ip_preserves_other_fields(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """When already CONNECTED, get_status() updates IP without mutating the object.

        Covers the ``else`` branch at the end of get_status()'s lock block,
        previously the only place that mutated ConnectionStatus in-place.
        """
        import time
        from snxui.core.types import ConnectionStatus

        ts = time.time()
        with backend._lock:
            backend._status = ConnectionStatus(
                state=ConnectionState.CONNECTED,
                profile=profile,
                ip_address="10.0.0.1",
                interface="tunsnx",
                connected_at=ts,
            )

        with patch.object(SNXBackend, "_tunsnx_exists", return_value=True), \
             patch.object(SNXBackend, "_get_tunsnx_ip", return_value="10.0.0.2"):
            snapshot = backend.get_status()

        # IP must be updated.
        assert snapshot.ip_address == "10.0.0.2"
        # All other fields must be preserved.
        assert snapshot.state == ConnectionState.CONNECTED
        assert snapshot.profile is profile
        assert snapshot.connected_at == ts
        assert snapshot.interface == "tunsnx"
        # Snapshot must be a distinct object from self._status.
        assert snapshot is not backend._status


# ---------------------------------------------------------------------------
# get_cached_status() — no subprocess calls
# ---------------------------------------------------------------------------


class TestGetCachedStatus:
    def test_returns_cached_snapshot_without_probing_tunsnx(
        self, backend: SNXBackend
    ) -> None:
        """get_cached_status() must NOT call _tunsnx_exists or _get_tunsnx_ip."""
        from snxui.core.types import ConnectionStatus

        with backend._lock:
            backend._status = ConnectionStatus(
                state=ConnectionState.ERROR,
                error_message="Disconnect failed",
            )

        with patch.object(SNXBackend, "_tunsnx_exists") as mock_probe, \
             patch.object(SNXBackend, "_get_tunsnx_ip") as mock_ip:
            snapshot = backend.get_cached_status()

        mock_probe.assert_not_called()
        mock_ip.assert_not_called()
        assert snapshot.state == ConnectionState.ERROR
        assert snapshot.error_message == "Disconnect failed"
        # Must be a copy, not the same object.
        assert snapshot is not backend._status

    def test_preserves_all_fields(self, backend: SNXBackend, profile: Profile) -> None:
        """get_cached_status() copies all ConnectionStatus fields faithfully."""
        import time
        from snxui.core.types import ConnectionStatus

        ts = time.time()
        with backend._lock:
            backend._status = ConnectionStatus(
                state=ConnectionState.CONNECTED,
                profile=profile,
                ip_address="10.1.2.3",
                interface="tunsnx",
                connected_at=ts,
            )

        snapshot = backend.get_cached_status()

        assert snapshot.state == ConnectionState.CONNECTED
        assert snapshot.profile is profile
        assert snapshot.ip_address == "10.1.2.3"
        assert snapshot.interface == "tunsnx"
        assert snapshot.connected_at == ts


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


# ---------------------------------------------------------------------------
# _monitor_connection — monitor loop logic
# ---------------------------------------------------------------------------


def _make_connected_backend() -> "tuple[SNXBackend, Profile]":
    """Return an SNXBackend with CONNECTED status at 10.0.0.1."""
    from snxui.core.types import ConnectionStatus
    backend = SNXBackend()
    backend._snx_binary = "/fake/snx"
    profile = Profile(name="Work", server="vpn.example.com", username="alice")
    backend._status = ConnectionStatus(
        state=ConnectionState.CONNECTED,
        profile=profile,
        ip_address="10.0.0.1",
    )
    return backend, profile


class TestMonitorConnection:
    """Direct unit tests for _monitor_connection loop paths."""

    def test_stop_event_exits_without_callback(self) -> None:
        """If _monitor_stop is already set (wait returns True), loop body never runs."""
        backend, profile = _make_connected_backend()
        callback = MagicMock()

        with patch.object(backend._monitor_stop, "wait", return_value=True):
            with patch.object(SNXBackend, "_tunsnx_exists") as mock_probe:
                backend._monitor_connection(profile, callback)

        mock_probe.assert_not_called()
        callback.assert_not_called()

    def test_tunnel_gone_dispatches_disconnected(self) -> None:
        """When _tunsnx_exists() returns False, callback is called with DISCONNECTED."""
        backend, profile = _make_connected_backend()
        callback = MagicMock()

        # One iteration: wait returns False (not stopped) → body runs → tunnel gone → break.
        with patch.object(backend._monitor_stop, "wait", side_effect=[False]):
            with patch.object(SNXBackend, "_tunsnx_exists", return_value=False):
                backend._monitor_connection(profile, callback)

        callback.assert_called_once()
        snapshot = callback.call_args[0][0]
        assert snapshot.state == ConnectionState.DISCONNECTED
        assert "dropped unexpectedly" in snapshot.error_message

    def test_ip_change_dispatches_connected_with_new_ip(self) -> None:
        """When the tunnel IP changes, callback is invoked with the new IP."""
        backend, profile = _make_connected_backend()
        callback = MagicMock()

        # First wait → False (run body); second wait → True (stop).
        with patch.object(backend._monitor_stop, "wait", side_effect=[False, True]):
            with patch.object(SNXBackend, "_tunsnx_exists", return_value=True):
                with patch.object(SNXBackend, "_get_tunsnx_ip", return_value="10.0.0.99"):
                    backend._monitor_connection(profile, callback)

        callback.assert_called_once()
        snapshot = callback.call_args[0][0]
        assert snapshot.state == ConnectionState.CONNECTED
        assert snapshot.ip_address == "10.0.0.99"

    def test_no_ip_change_no_callback(self) -> None:
        """When IP hasn't changed, callback is not invoked."""
        backend, profile = _make_connected_backend()
        callback = MagicMock()

        # IP returned equals the current ip_address ("10.0.0.1") → no callback.
        with patch.object(backend._monitor_stop, "wait", side_effect=[False, True]):
            with patch.object(SNXBackend, "_tunsnx_exists", return_value=True):
                with patch.object(SNXBackend, "_get_tunsnx_ip", return_value="10.0.0.1"):
                    backend._monitor_connection(profile, callback)

        callback.assert_not_called()


# ---------------------------------------------------------------------------
# _update_status — internal status snapshot helper
# ---------------------------------------------------------------------------


class TestUpdateStatus:
    """Tests for the _update_status internal helper."""

    def test_returns_independent_copy(self) -> None:
        """The returned snapshot must be a different object from self._status."""
        backend = SNXBackend()
        profile = Profile(name="W", server="s", username="u")
        with backend._lock:
            snapshot = backend._update_status(
                ConnectionState.CONNECTED,
                profile=profile,
                ip_address="10.1.1.1",
            )
        assert snapshot is not backend._status
        assert snapshot.state == ConnectionState.CONNECTED
        assert snapshot.ip_address == "10.1.1.1"

    def test_updates_internal_state(self) -> None:
        """After _update_status, self._status reflects the new state."""
        backend = SNXBackend()
        with backend._lock:
            backend._update_status(ConnectionState.ERROR, error_message="oops")
        assert backend._status.state == ConnectionState.ERROR
        assert backend._status.error_message == "oops"


# ---------------------------------------------------------------------------
# _invoke_callback — static callback dispatcher
# ---------------------------------------------------------------------------


class TestInvokeCallback:
    """Tests for the _invoke_callback static helper."""

    def test_calls_callback_with_snapshot(self) -> None:
        """_invoke_callback passes the snapshot to the callback."""
        from snxui.core.types import ConnectionStatus
        profile = Profile(name="W", server="s", username="u")
        snapshot = ConnectionStatus(state=ConnectionState.CONNECTED, profile=profile)
        callback = MagicMock()
        SNXBackend._invoke_callback(callback, snapshot)
        callback.assert_called_once_with(snapshot)

    def test_none_callback_is_noop(self) -> None:
        """_invoke_callback with None callback does not raise."""
        from snxui.core.types import ConnectionStatus
        profile = Profile(name="W", server="s", username="u")
        snapshot = ConnectionStatus(state=ConnectionState.DISCONNECTED, profile=profile)
        SNXBackend._invoke_callback(None, snapshot)  # must not raise

    def test_exception_in_callback_is_swallowed(self) -> None:
        """An exception raised by the callback must not propagate."""
        from snxui.core.types import ConnectionStatus
        profile = Profile(name="W", server="s", username="u")
        snapshot = ConnectionStatus(state=ConnectionState.DISCONNECTED, profile=profile)
        bad_cb = MagicMock(side_effect=RuntimeError("boom"))
        SNXBackend._invoke_callback(bad_cb, snapshot)  # must not raise


# ---------------------------------------------------------------------------
# connect() 2FA — two-factor authentication loop
# ---------------------------------------------------------------------------


class TestConnect2FA:
    """Tests for the 2FA interaction loop in SNXBackend.connect()."""

    def _patch_pexpect(self, child_mock):
        return patch("snxui.core.snx_backend.pexpect.spawn", return_value=child_mock)

    def _patch_monitor(self):
        return patch.object(SNXBackend, "_start_monitor")

    def _patch_tunsnx(self, exists: bool = False):
        return patch.object(SNXBackend, "_tunsnx_exists", return_value=exists)

    def test_rsa_securid_then_connected(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """2FA prompt (idx=1) → sendline(code) → connected (idx=0)."""
        # expect calls: [password_prompt=0, 2fa=1, connected=0]
        child = _make_child_mock([0, 1, 0])
        child.before = ""
        child.after = "SNX - Connected."

        two_factor_callback = MagicMock(return_value="123456")

        with self._patch_pexpect(child), self._patch_tunsnx(), self._patch_monitor():
            result = backend.connect(
                profile, "pass",
                two_factor_callback=two_factor_callback,
            )

        assert result is True
        assert backend._status.state == ConnectionState.CONNECTED
        # sendline must have been called with the 2FA code
        child.sendline.assert_any_call("123456")

    def test_otp_prompt_then_connected(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """Generic OTP prompt resolves to successful connection."""
        child = _make_child_mock([0, 1, 0])
        child.before = ""
        child.after = "SNX - Connected."

        two_factor_callback = MagicMock(return_value="654321")

        with self._patch_pexpect(child), self._patch_tunsnx(), self._patch_monitor():
            result = backend.connect(
                profile, "pass",
                two_factor_callback=two_factor_callback,
            )

        assert result is True
        child.sendline.assert_any_call("654321")

    def test_challenge_response_prompt_passed_to_callback(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """The full prompt text must be passed to two_factor_callback."""
        child = _make_child_mock([0, 1, 0])
        child.before = "Challenge: DEADBEEF\n"
        child.after = ""  # after idx=5 expect

        received_prompts: list[str] = []

        def _cb(prompt_text: str):
            received_prompts.append(prompt_text)
            return "RESP"

        with self._patch_pexpect(child), self._patch_tunsnx(), self._patch_monitor():
            result = backend.connect(profile, "pass", two_factor_callback=_cb)

        assert result is True
        # The callback must have received a non-empty prompt
        assert len(received_prompts) == 1
        assert received_prompts[0]  # prompt_text is not empty

    def test_2fa_cancelled(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """When callback returns None, connection fails with 'cancelled' message."""
        child = _make_child_mock([0, 1])
        child.before = "Enter SecurID PASSCODE:"
        child.after = ""

        two_factor_callback = MagicMock(return_value=None)

        with self._patch_pexpect(child):
            result = backend.connect(
                profile, "pass",
                two_factor_callback=two_factor_callback,
            )

        assert result is False
        assert backend._status.state == ConnectionState.ERROR
        assert "cancelled" in (backend._status.error_message or "").lower()

    def test_2fa_no_callback_returns_configure_message(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """When SNX requests 2FA but no callback is provided, error must mention Configure."""
        child = _make_child_mock([0, 1])
        child.before = "Enter SecurID PASSCODE:"
        child.after = ""

        with self._patch_pexpect(child):
            result = backend.connect(profile, "pass")  # no two_factor_callback

        assert result is False
        assert backend._status.state == ConnectionState.ERROR
        assert "Configure 2FA" in (backend._status.error_message or "")

    def test_2fa_loop_limit(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """After _2FA_LOOP_LIMIT (3) rounds, connection is aborted."""
        # password_prompt=0, then 4 2FA prompts — loop limit (3) kicks in after 3
        child = _make_child_mock([0, 1, 1, 1, 1])
        child.before = "OTP:"
        child.after = ""

        call_count = 0

        def _always_code(prompt_text: str):
            nonlocal call_count
            call_count += 1
            return "000000"

        with self._patch_pexpect(child):
            result = backend.connect(profile, "pass", two_factor_callback=_always_code)

        assert result is False
        assert backend._status.state == ConnectionState.ERROR
        # Callback must be called at most _2FA_LOOP_LIMIT (3) times
        assert call_count <= 3

    def test_backward_compat_no_2fa_callback(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """Without two_factor_callback and no 2FA prompt, connect succeeds as before."""
        child = _make_child_mock([0, 0])
        child.before = "Office Mode IP      : 10.1.1.1\n"
        child.after = "SNX - Connected.\n"

        with self._patch_pexpect(child), self._patch_tunsnx(), self._patch_monitor():
            result = backend.connect(profile, "password123")

        assert result is True
        assert backend._status.state == ConnectionState.CONNECTED

    def test_second_password_prompt_treated_as_otp(
        self, backend: SNXBackend, profile: Profile
    ) -> None:
        """Second 'password:' prompt (idx=2) is treated as an OTP request."""
        # password_prompt=0, second_password=2 (OTP), connected=0
        child = _make_child_mock([0, 2, 0])
        child.before = "Please enter your password:"
        child.after = "SNX - Connected."

        two_factor_callback = MagicMock(return_value="123456")

        with self._patch_pexpect(child), self._patch_tunsnx(), self._patch_monitor():
            result = backend.connect(
                profile, "pass",
                two_factor_callback=two_factor_callback,
            )

        assert result is True
        child.sendline.assert_any_call("123456")

    def test_2fa_regex_exported(self) -> None:
        """_RE_2FA_ANY must be importable from snx_backend for tests/validation."""
        assert _RE_2FA_ANY is not None
        assert _RE_2FA_ANY.search("OTP:")
        assert not _RE_2FA_ANY.search("Password:")
