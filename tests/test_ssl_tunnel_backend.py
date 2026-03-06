"""Tests for PythonSSLBackend and SSLTunnel.

All external dependencies (ssl.SSLSocket, os.open, fcntl.ioctl, subprocess,
select.select, CCCAuth) are mocked — no actual network connections or root
privileges are required.

TUN interface setup flow (new polkit-based approach):
  create_tun()    — validates interface name only, no OS calls
  configure_net() — invokes pkexec + snxui-net-helper, then os.open + ioctl
  _teardown_net() — invokes pkexec + snxui-net-helper destroy (best-effort)
"""

from __future__ import annotations

import fcntl
import os
import struct
import threading
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

from snxui.core.ssl_tunnel import (
    SSLTunnel,
    TunnelConfig,
    _range_to_cidr,
)
from snxui.core.ssl_tunnel_backend import PythonSSLBackend
from snxui.core.types import ConnectionState, Profile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_profile(**kwargs: object) -> Profile:
    defaults: dict = dict(
        server="vpn.example.com",
        username="testuser",
        ssl_port=443,
        login_type="",
        ignore_server_cert=False,
        backend="python_ssl",
    )
    defaults.update(kwargs)
    return Profile(**defaults)


def _slim_frame(ftype: int, payload: bytes) -> bytes:
    """Build a SLIM frame as bytes (for use as mock recv data).

    Mirrors the wire format: [4B BE uint32 length][4B BE uint32 type][payload].
    Control frames (type=1) include a null terminator counted in the length.
    """
    if ftype == 1:  # SLIM_CONTROL — null terminator included in length
        wire_payload = payload + b"\x00"
    else:
        wire_payload = payload
    return struct.pack(">II", len(wire_payload), ftype) + wire_payload


def _make_mock_ssl_sock(*frame_chunks: bytes) -> MagicMock:
    """Return a mock SSLSocket whose recv() delivers *frame_chunks* in order."""
    import ssl as _ssl
    mock = MagicMock(spec=_ssl.SSLSocket)
    mock.pending.return_value = 0
    mock.fileno.return_value = 10

    chunks = list(frame_chunks)
    pos = [0]
    buf = b"".join(chunks)

    def fake_recv(n: int) -> bytes:
        chunk = buf[pos[0]: pos[0] + n]
        pos[0] += n
        return chunk

    mock.recv.side_effect = fake_recv
    return mock


def _make_tunnel(keepalive_timeout: int = 4) -> SSLTunnel:
    """Create an SSLTunnel with a mock ssl_sock and real pipes (for stop)."""
    import ssl as _ssl

    tunnel = SSLTunnel.__new__(SSLTunnel)
    tunnel._ssl_sock = MagicMock(spec=_ssl.SSLSocket)
    tunnel._ssl_sock.pending.return_value = 0
    tunnel._ssl_sock.fileno.return_value = 10
    tunnel._tun_fd = 5          # fake TUN fd
    tunnel._iface_name = "tunsnx"
    tunnel._config = TunnelConfig(
        assigned_ip="10.0.0.1",
        keepalive_timeout=keepalive_timeout,
    )
    tunnel._stopped = False
    tunnel._lock = threading.Lock()
    # Real pipes so stop() → write() actually signals the loop
    r, w = os.pipe()
    tunnel._pipe_r = r
    tunnel._pipe_w = w
    return tunnel


def _close_tunnel_pipes(tunnel: SSLTunnel) -> None:
    for attr in ("_pipe_r", "_pipe_w"):
        fd = getattr(tunnel, attr, -1)
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        setattr(tunnel, attr, -1)


# ---------------------------------------------------------------------------
# TestSlimFraming
# ---------------------------------------------------------------------------


class TestSlimFraming:
    """Tests for _send_slim, _recv_slim, and _recv_exact."""

    def setup_method(self) -> None:
        self.tunnel = _make_tunnel()

    def teardown_method(self) -> None:
        _close_tunnel_pipes(self.tunnel)

    def test_send_slim_encodes_header_correctly(self) -> None:
        """_send_slim sends [4B payload_len][4B type][payload+\\x00] for control frames."""
        payload = b"hello world"
        self.tunnel._send_slim(1, payload)
        # Control frame: null terminator appended; length counts the null
        wire = payload + b"\x00"
        expected = struct.pack(">II", len(wire), 1) + wire
        self.tunnel._ssl_sock.sendall.assert_called_once_with(expected)

    def test_send_slim_data_frame(self) -> None:
        """_send_slim type=2 sends [4B payload_len][4B type][payload] without null."""
        packet = b"\x45\x00\x00\x28" + b"\x00" * 36
        self.tunnel._send_slim(2, packet)
        expected = struct.pack(">II", len(packet), 2) + packet
        self.tunnel._ssl_sock.sendall.assert_called_once_with(expected)

    def test_send_slim_empty_payload(self) -> None:
        """_send_slim control frame with empty payload sends just the null terminator."""
        self.tunnel._send_slim(1, b"")
        # Null terminator only → length=1, type=1
        expected = struct.pack(">II", 1, 1) + b"\x00"
        self.tunnel._ssl_sock.sendall.assert_called_once_with(expected)

    def test_recv_slim_returns_type_and_payload(self) -> None:
        """_recv_slim decodes header and returns (ftype, payload)."""
        payload = b"test payload"
        frame = _slim_frame(1, payload)
        # Deliver header then payload separately to simulate fragmentation
        self.tunnel._ssl_sock.recv.side_effect = [frame[:8], frame[8:]]
        ftype, result = self.tunnel._recv_slim()
        assert ftype == 1
        assert result == payload

    def test_recv_slim_data_frame(self) -> None:
        """_recv_slim returns type=2 for data frames."""
        packet = b"\x45" * 40
        frame = _slim_frame(2, packet)
        self.tunnel._ssl_sock.recv.side_effect = [frame[:8], frame[8:]]
        ftype, result = self.tunnel._recv_slim()
        assert ftype == 2
        assert result == packet

    def test_recv_exact_handles_fragmented_tls_reads(self) -> None:
        """_recv_exact reassembles data from small recv() chunks."""
        data = b"fragmented data here ABCDEFGH"
        # Deliver in 4-byte chunks
        chunks = [data[i: i + 4] for i in range(0, len(data), 4)]
        self.tunnel._ssl_sock.recv.side_effect = chunks
        result = self.tunnel._recv_exact(len(data))
        assert result == data

    def test_recv_exact_raises_eof_on_connection_close(self) -> None:
        """_recv_exact raises EOFError when peer closes the connection."""
        self.tunnel._ssl_sock.recv.return_value = b""
        with pytest.raises(EOFError):
            self.tunnel._recv_exact(8)


# ---------------------------------------------------------------------------
# TestClientHello
# ---------------------------------------------------------------------------


class TestClientHello:
    """Tests for the SLIM ClientHello S-expression builder.

    Format based on snx-rs proto.rs ``ClientHello`` / ``ClientHelloData``:
    - Outer wrapper: ``(client_hello ...)`` (NOT ``CCCclientRequest``)
    - No RequestHeader or session_id
    - ``OM`` block for office_mode (serde rename)
    - ``optional.client_type = "4"``
    """

    def test_outer_wrapper_is_client_hello(self) -> None:
        """Outer wrapper must be (client_hello ...) per snx-rs proto.rs."""
        hello = SSLTunnel._build_client_hello("myactivekey123")
        assert hello.startswith("(client_hello")
        assert "CCCclientRequest" not in hello

    def test_no_request_header(self) -> None:
        """SLIM ClientHello has no RequestHeader or session_id."""
        hello = SSLTunnel._build_client_hello("key")
        assert "RequestHeader" not in hello
        assert "session_id" not in hello

    def test_cookie_field_present(self) -> None:
        """client_hello contains the active_key in a :cookie field."""
        hello = SSLTunnel._build_client_hello("myactivekey123")
        assert ":cookie" in hello
        assert "myactivekey123" in hello

    def test_optional_client_type_is_4(self) -> None:
        """client_hello optional :client_type is "4" (snx-rs wire format)."""
        hello = SSLTunnel._build_client_hello("key")
        assert ':client_type ("4")' in hello
        assert "TRAC" not in hello

    def test_protocol_version_1(self) -> None:
        """client_hello sets :protocol_version to 1 and :protocol_minor_version to 1."""
        hello = SSLTunnel._build_client_hello("key")
        assert ":protocol_version (1)" in hello
        assert ":protocol_minor_version (1)" in hello
        assert "100" not in hello

    def test_office_mode_uses_OM_field_name(self) -> None:
        """office_mode is serialized as :OM (snx-rs proto.rs serde rename)."""
        hello = SSLTunnel._build_client_hello("key")
        assert ":OM" in hello
        assert "0.0.0.0" in hello
        assert "office_mode" not in hello

    def test_active_key_embedded_verbatim(self) -> None:
        """The exact active_key value appears in the hello."""
        key = "abc1234567890def"
        hello = SSLTunnel._build_client_hello(key)
        assert f'"{key}"' in hello


# ---------------------------------------------------------------------------
# TestHelloReplyParsing
# ---------------------------------------------------------------------------


class TestHelloReplyParsing:
    """Tests for _parse_hello_reply."""

    def setup_method(self) -> None:
        self.tunnel = _make_tunnel()

    def teardown_method(self) -> None:
        _close_tunnel_pipes(self.tunnel)

    def _make_reply(
        self,
        ipaddr: str = "10.20.30.40",
        from_ip: Optional[str] = None,
        to_ip: Optional[str] = None,
        dns_primary: Optional[str] = None,
        dns_secondary: Optional[str] = None,
        keepalive: int = 20,
    ) -> str:
        range_block = ""
        if from_ip and to_ip:
            range_block = (
                f' :range (\n'
                f'  :from ("{from_ip}")\n'
                f'  :to ("{to_ip}")\n'
                f' )\n'
            )

        dns_block = ""
        if dns_primary:
            dns_block = (
                " :optional (\n"
                "  :dns (\n"
                f'   :primary ("{dns_primary}")\n'
            )
            if dns_secondary:
                dns_block += f'   :secondary ("{dns_secondary}")\n'
            dns_block += "  )\n )\n"

        return (
            "(CCCserverResponse\n"
            " :ResponseData (\n"
            "  :office_mode (\n"
            f'   :ipaddr ("{ipaddr}")\n'
            "  )\n"
            f"  :timeouts (:keepalive ({keepalive}))\n"
            f"{range_block}"
            f"{dns_block}"
            " )\n"
            ")\n"
        )

    def test_parses_assigned_ip(self) -> None:
        reply = self._make_reply(ipaddr="192.168.100.5")
        config = self.tunnel._parse_hello_reply(reply)
        assert config.assigned_ip == "192.168.100.5"

    def test_raises_on_missing_ip(self) -> None:
        reply = "(CCCserverResponse :ResponseData ())"
        with pytest.raises(RuntimeError, match="IP"):
            self.tunnel._parse_hello_reply(reply)

    def test_raises_when_ip_is_zero(self) -> None:
        reply = self._make_reply(ipaddr="0.0.0.0")
        with pytest.raises(RuntimeError):
            self.tunnel._parse_hello_reply(reply)

    def test_parses_routes_list(self) -> None:
        reply = self._make_reply(
            ipaddr="10.0.0.1",
            from_ip="10.0.0.0",
            to_ip="10.0.255.255",
        )
        config = self.tunnel._parse_hello_reply(reply)
        assert len(config.routes) == 1
        network, prefix = config.routes[0]
        assert network == "10.0.0.0"
        assert prefix == "16"

    def test_parses_dns_servers(self) -> None:
        reply = self._make_reply(
            ipaddr="10.1.2.3",
            dns_primary="8.8.8.8",
            dns_secondary="8.8.4.4",
        )
        config = self.tunnel._parse_hello_reply(reply)
        assert "8.8.8.8" in config.dns_servers
        assert "8.8.4.4" in config.dns_servers

    def test_empty_routes_returns_empty_list(self) -> None:
        reply = self._make_reply(ipaddr="10.1.2.3")
        config = self.tunnel._parse_hello_reply(reply)
        assert config.routes == []

    def test_parses_keepalive_timeout(self) -> None:
        reply = self._make_reply(ipaddr="10.1.2.3", keepalive=30)
        config = self.tunnel._parse_hello_reply(reply)
        assert config.keepalive_timeout == 30

    def test_default_keepalive_when_zero(self) -> None:
        """keepalive <= 0 in response falls back to 20 seconds."""
        reply = self._make_reply(ipaddr="10.1.2.3", keepalive=0)
        config = self.tunnel._parse_hello_reply(reply)
        assert config.keepalive_timeout == 20

    def test_no_dns_when_not_in_reply(self) -> None:
        reply = self._make_reply(ipaddr="10.1.2.3")
        config = self.tunnel._parse_hello_reply(reply)
        assert config.dns_servers == []

    def test_single_dns_server(self) -> None:
        reply = self._make_reply(ipaddr="10.1.2.3", dns_primary="1.1.1.1")
        config = self.tunnel._parse_hello_reply(reply)
        assert config.dns_servers == ["1.1.1.1"]

    def test_dns_from_OM_block(self) -> None:
        """DNS servers from :OM :dns_servers (snx-rs OfficeMode.dns_servers)."""
        reply = (
            "(hello_reply\n"
            " :OM (\n"
            '  :ipaddr ("10.5.6.7")\n'
            "  :dns_servers (\n"
            '   : ("8.8.8.8")\n'
            '   : ("8.8.4.4")\n'
            "  )\n"
            " )\n"
            " :timeouts (:keepalive (20))\n"
            ")\n"
        )
        config = self.tunnel._parse_hello_reply(reply)
        assert config.assigned_ip == "10.5.6.7"
        assert "8.8.8.8" in config.dns_servers
        assert "8.8.4.4" in config.dns_servers

    def test_OM_format_reply(self) -> None:
        """hello_reply with :OM format (snx-rs wire format) parses correctly."""
        reply = (
            "(hello_reply\n"
            " :OM (\n"
            '  :ipaddr ("10.99.0.1")\n'
            "  :keep_address (true)\n"
            " )\n"
            " :timeouts (:keepalive (30))\n"
            ")\n"
        )
        config = self.tunnel._parse_hello_reply(reply)
        assert config.assigned_ip == "10.99.0.1"
        assert config.keepalive_timeout == 30


# ---------------------------------------------------------------------------
# TestRangeToCidr
# ---------------------------------------------------------------------------


class TestRangeToCidr:
    """Tests for the _range_to_cidr helper."""

    def test_class_a_range(self) -> None:
        network, prefix = _range_to_cidr("10.0.0.0", "10.255.255.255")
        assert network == "10.0.0.0"
        assert prefix == "8"

    def test_class_c_range(self) -> None:
        network, prefix = _range_to_cidr("192.168.1.0", "192.168.1.255")
        assert network == "192.168.1.0"
        assert prefix == "24"

    def test_class_b_subnet(self) -> None:
        network, prefix = _range_to_cidr("10.0.0.0", "10.0.255.255")
        assert network == "10.0.0.0"
        assert prefix == "16"

    def test_host_route(self) -> None:
        network, prefix = _range_to_cidr("10.0.0.5", "10.0.0.5")
        assert network == "10.0.0.5"
        assert prefix == "32"

    def test_from_equals_to_is_host_route(self) -> None:
        network, prefix = _range_to_cidr("172.16.0.1", "172.16.0.1")
        assert prefix == "32"

    def test_returns_string_prefix(self) -> None:
        _, prefix = _range_to_cidr("10.0.0.0", "10.255.255.255")
        assert isinstance(prefix, str)

    def test_invalid_from_ip_returns_none(self) -> None:
        """Invalid from_ip yields None — untrusted data never reaches subprocess."""
        assert _range_to_cidr("not_an_ip", "10.0.0.255") is None

    def test_invalid_to_ip_returns_none(self) -> None:
        """Invalid to_ip yields None."""
        assert _range_to_cidr("10.0.0.0", "bogus") is None

    def test_injection_attempt_returns_none(self) -> None:
        """Shell metacharacters in IP are rejected (return None, not passed on)."""
        assert _range_to_cidr("10.0.0.0; rm -rf /", "10.0.0.255") is None
        assert _range_to_cidr("10.0.0.0", "$(reboot)") is None


# ---------------------------------------------------------------------------
# TestSSLTunnelInputValidation
# ---------------------------------------------------------------------------


class TestSSLTunnelInputValidation:
    """Tests for gateway-supplied data validation before subprocess use."""

    # ------------------------------------------------------------------
    # create_tun — validation only, no OS calls
    # ------------------------------------------------------------------

    def test_create_tun_rejects_shell_metacharacters(self) -> None:
        """create_tun raises ValueError for interface names with shell metacharacters."""
        tunnel = SSLTunnel()
        with pytest.raises(ValueError, match="Invalid TUN interface name"):
            tunnel.create_tun("tunsnx; rm -rf /")

    def test_create_tun_rejects_empty_name(self) -> None:
        """create_tun raises ValueError for an empty interface name."""
        tunnel = SSLTunnel()
        with pytest.raises(ValueError, match="Invalid TUN interface name"):
            tunnel.create_tun("")

    def test_create_tun_rejects_name_too_long(self) -> None:
        """create_tun raises ValueError for interface names longer than 15 chars."""
        tunnel = SSLTunnel()
        with pytest.raises(ValueError, match="Invalid TUN interface name"):
            tunnel.create_tun("a" * 16)

    def test_create_tun_accepts_valid_name_no_os_calls(self) -> None:
        """create_tun succeeds for valid names without any OS calls."""
        from snxui.core.ssl_tunnel import _IFACE_RE

        assert _IFACE_RE.match("tunsnx") is not None
        assert _IFACE_RE.match("tun0") is not None
        assert _IFACE_RE.match("vpn-0") is not None
        assert _IFACE_RE.match("a" * 15) is not None  # max length

        # create_tun must NOT call os.open or fcntl.ioctl
        with patch("snxui.core.ssl_tunnel.os.open") as mock_open, \
             patch("snxui.core.ssl_tunnel.fcntl.ioctl") as mock_ioctl:
            tunnel = SSLTunnel()
            ret = tunnel.create_tun("tunsnx")
            assert ret == 0
            assert tunnel._iface_name == "tunsnx"
            mock_open.assert_not_called()
            mock_ioctl.assert_not_called()

    def test_create_tun_returns_zero(self) -> None:
        """create_tun returns 0 (placeholder — real fd is set by configure_net)."""
        tunnel = SSLTunnel()
        assert tunnel.create_tun("tun0") == 0

    # ------------------------------------------------------------------
    # configure_net — pkexec + os.open + ioctl
    # ------------------------------------------------------------------

    def test_configure_net_rejects_invalid_ip(self) -> None:
        """configure_net raises ValueError when assigned_ip is not a valid IPv4."""
        tunnel = _make_tunnel()
        config = TunnelConfig(assigned_ip="not_an_ip")
        with pytest.raises(ValueError, match="invalid IP"):
            tunnel.configure_net(config, "tunsnx")
        _close_tunnel_pipes(tunnel)

    def test_configure_net_rejects_ip_with_injection(self) -> None:
        """configure_net raises ValueError for IP strings containing shell chars."""
        tunnel = _make_tunnel()
        config = TunnelConfig(assigned_ip="10.0.0.1; reboot")
        with pytest.raises(ValueError, match="invalid IP"):
            tunnel.configure_net(config, "tunsnx")
        _close_tunnel_pipes(tunnel)

    def test_configure_net_rejects_invalid_iface(self) -> None:
        """configure_net raises ValueError for an invalid interface name."""
        tunnel = _make_tunnel()
        config = TunnelConfig(assigned_ip="10.0.0.1")
        with pytest.raises(ValueError, match="Invalid interface name"):
            tunnel.configure_net(config, "tun; rm -rf /")
        _close_tunnel_pipes(tunnel)

    def test_configure_net_calls_pkexec_helper(self) -> None:
        """configure_net invokes pkexec + snxui-net-helper with correct args."""
        from snxui.core.ssl_tunnel import _NET_HELPER

        tunnel = _make_tunnel()
        config = TunnelConfig(
            assigned_ip="10.0.0.5",
            routes=[("10.0.0.0", "8"), ("192.168.1.0", "24")],
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "OK"
        mock_result.stderr = ""

        with patch("snxui.core.ssl_tunnel.subprocess.run", return_value=mock_result) as mock_run, \
             patch("snxui.core.ssl_tunnel.os.open", return_value=42), \
             patch("snxui.core.ssl_tunnel.fcntl.ioctl"), \
             patch("snxui.core.ssl_tunnel.os.getuid", return_value=1000):
            tunnel.configure_net(config, "tunsnx")

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "pkexec"
        assert cmd[1] == _NET_HELPER
        assert cmd[2] == "create"
        assert cmd[3] == "tunsnx"
        assert cmd[4] == "1000"       # uid
        assert cmd[5] == "10.0.0.5"  # assigned_ip
        assert "10.0.0.0/8" in cmd
        assert "192.168.1.0/24" in cmd
        _close_tunnel_pipes(tunnel)

    def test_configure_net_opens_tun_fd_after_helper(self) -> None:
        """configure_net opens /dev/net/tun and stores the fd after pkexec succeeds."""
        tunnel = _make_tunnel()
        config = TunnelConfig(assigned_ip="10.0.0.5")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "OK"
        mock_result.stderr = ""

        with patch("snxui.core.ssl_tunnel.subprocess.run", return_value=mock_result), \
             patch("snxui.core.ssl_tunnel.os.open", return_value=99) as mock_open, \
             patch("snxui.core.ssl_tunnel.fcntl.ioctl"), \
             patch("snxui.core.ssl_tunnel.os.getuid", return_value=1000):
            tunnel.configure_net(config, "tunsnx")

        mock_open.assert_called_once_with("/dev/net/tun", os.O_RDWR)
        assert tunnel._tun_fd == 99
        _close_tunnel_pipes(tunnel)

    def test_configure_net_raises_permission_error_on_pkexec_failure(self) -> None:
        """configure_net raises PermissionError when pkexec returns non-zero."""
        tunnel = _make_tunnel()
        config = TunnelConfig(assigned_ip="10.0.0.5")
        mock_result = MagicMock()
        mock_result.returncode = 126   # pkexec: not authorized
        mock_result.stdout = ""
        mock_result.stderr = "Not authorized"

        with patch("snxui.core.ssl_tunnel.subprocess.run", return_value=mock_result), \
             patch("snxui.core.ssl_tunnel.os.getuid", return_value=1000):
            with pytest.raises(PermissionError, match="VPN network setup failed"):
                tunnel.configure_net(config, "tunsnx")
        _close_tunnel_pipes(tunnel)

    def test_configure_net_closes_fd_on_ioctl_failure(self) -> None:
        """configure_net closes the TUN fd when TUNSETIFF ioctl fails."""
        tunnel = _make_tunnel()
        config = TunnelConfig(assigned_ip="10.0.0.5")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "OK"
        mock_result.stderr = ""

        closed_fds: list[int] = []

        with patch("snxui.core.ssl_tunnel.subprocess.run", return_value=mock_result), \
             patch("snxui.core.ssl_tunnel.os.open", return_value=77), \
             patch("snxui.core.ssl_tunnel.os.close", side_effect=closed_fds.append), \
             patch("snxui.core.ssl_tunnel.fcntl.ioctl", side_effect=OSError("ioctl failed")), \
             patch("snxui.core.ssl_tunnel.os.getuid", return_value=1000):
            with pytest.raises(OSError):
                tunnel.configure_net(config, "tunsnx")

        assert 77 in closed_fds
        _close_tunnel_pipes(tunnel)

    # ------------------------------------------------------------------
    # _teardown_net — pkexec destroy
    # ------------------------------------------------------------------

    def test_teardown_net_calls_pkexec_destroy(self) -> None:
        """_teardown_net invokes pkexec + snxui-net-helper destroy."""
        from snxui.core.ssl_tunnel import _NET_HELPER

        tunnel = _make_tunnel()
        with patch("snxui.core.ssl_tunnel.subprocess.run") as mock_run:
            tunnel._teardown_net()

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "pkexec"
        assert cmd[1] == _NET_HELPER
        assert cmd[2] == "destroy"
        assert cmd[3] == "tunsnx"
        _close_tunnel_pipes(tunnel)

    def test_teardown_net_no_op_when_no_iface(self) -> None:
        """_teardown_net does nothing when no interface name is set."""
        tunnel = SSLTunnel()
        with patch("snxui.core.ssl_tunnel.subprocess.run") as mock_run:
            tunnel._teardown_net()
        mock_run.assert_not_called()

    def test_teardown_net_ignores_subprocess_errors(self) -> None:
        """_teardown_net swallows exceptions from pkexec (best-effort teardown)."""
        tunnel = _make_tunnel()
        with patch("snxui.core.ssl_tunnel.subprocess.run", side_effect=OSError("gone")):
            tunnel._teardown_net()   # must not raise
        _close_tunnel_pipes(tunnel)

    # ------------------------------------------------------------------
    # Keepalive timeout capping (unchanged)
    # ------------------------------------------------------------------

    def test_keepalive_timeout_capped_at_max(self) -> None:
        """Excessively large keepalive_timeout from gateway is capped."""
        from snxui.core.ssl_tunnel import _MAX_KEEPALIVE_SECS

        tunnel = _make_tunnel()
        reply = (
            "(hello_reply\n"
            " :OM (\n"
            '  :ipaddr ("10.1.2.3")\n'
            " )\n"
            f" :timeouts (:keepalive ({_MAX_KEEPALIVE_SECS + 9999}))\n"
            ")\n"
        )
        config = tunnel._parse_hello_reply(reply)
        assert config.keepalive_timeout == _MAX_KEEPALIVE_SECS
        _close_tunnel_pipes(tunnel)

    def test_keepalive_timeout_normal_value_unchanged(self) -> None:
        """Normal keepalive_timeout is not capped."""
        tunnel = _make_tunnel()
        reply = (
            "(hello_reply\n"
            " :OM (\n"
            '  :ipaddr ("10.1.2.3")\n'
            " )\n"
            " :timeouts (:keepalive (30))\n"
            ")\n"
        )
        config = tunnel._parse_hello_reply(reply)
        assert config.keepalive_timeout == 30
        _close_tunnel_pipes(tunnel)


# ---------------------------------------------------------------------------
# TestPacketLoop
# ---------------------------------------------------------------------------


class TestPacketLoop:
    """Tests for SSLTunnel.run_packet_loop."""

    def setup_method(self) -> None:
        self.tunnel = _make_tunnel(keepalive_timeout=4)

    def teardown_method(self) -> None:
        _close_tunnel_pipes(self.tunnel)

    @patch("snxui.core.ssl_tunnel.subprocess.run")
    def test_stop_exits_loop(self, _mock_run: object) -> None:
        """Calling stop() (or writing to pipe_w) causes the loop to exit."""
        with patch("snxui.core.ssl_tunnel.select.select") as mock_select:
            # Return pipe_r as readable immediately → loop breaks
            mock_select.return_value = ([self.tunnel._pipe_r], [], [])
            self.tunnel.run_packet_loop()
        # If we reach here the loop exited cleanly (no hang)

    @patch("snxui.core.ssl_tunnel.subprocess.run")
    def test_tun_to_ssl_forwards_ip_packet(self, _mock_run: object) -> None:
        """Packets read from TUN are forwarded as SLIM type=2 to SSL."""
        ip_packet = b"\x45\x00\x00\x14" + b"\x00" * 16

        with patch("snxui.core.ssl_tunnel.select.select") as mock_select, \
             patch("snxui.core.ssl_tunnel.os.read", return_value=ip_packet):

            call_count = [0]

            def fake_select(rlist: list, wlist: list, xlist: list, timeout: float):
                call_count[0] += 1
                if call_count[0] == 1:
                    return ([self.tunnel._tun_fd], [], [])
                # Signal stop on the second iteration
                return ([self.tunnel._pipe_r], [], [])

            mock_select.side_effect = fake_select
            self.tunnel.run_packet_loop()

        sent = self.tunnel._ssl_sock.sendall.call_args[0][0]
        payload_len, ftype = struct.unpack(">II", sent[:8])  # LENGTH first, TYPE second
        assert ftype == 2           # _SLIM_DATA
        assert sent[8:] == ip_packet

    @patch("snxui.core.ssl_tunnel.subprocess.run")
    def test_ssl_to_tun_forwards_ip_packet(self, _mock_run: object) -> None:
        """IP packets received from SSL are written to the TUN device."""
        ip_packet = b"\x45\x00\x00\x28" + b"\x00" * 36
        frame = _slim_frame(2, ip_packet)

        data = frame
        pos = [0]

        def fake_recv(n: int) -> bytes:
            chunk = data[pos[0]: pos[0] + n]
            pos[0] += n
            return chunk

        self.tunnel._ssl_sock.recv.side_effect = fake_recv

        written: list[tuple[int, bytes]] = []

        with patch("snxui.core.ssl_tunnel.select.select") as mock_select, \
             patch("snxui.core.ssl_tunnel.os.write") as mock_write:

            mock_write.side_effect = lambda fd, d: written.append((fd, d))

            call_count = [0]

            def fake_select(rlist: list, wlist: list, xlist: list, timeout: float):
                call_count[0] += 1
                if call_count[0] == 1:
                    return ([self.tunnel._ssl_sock.fileno()], [], [])
                return ([self.tunnel._pipe_r], [], [])

            mock_select.side_effect = fake_select
            self.tunnel.run_packet_loop()

        tun_writes = [d for (fd, d) in written if fd == self.tunnel._tun_fd]
        assert tun_writes == [ip_packet]

    @patch("snxui.core.ssl_tunnel.subprocess.run")
    def test_keepalive_sent_periodically(self, _mock_run: object) -> None:
        """A keepalive control frame is sent after the keepalive interval."""
        self.tunnel._config = TunnelConfig(
            assigned_ip="10.0.0.1", keepalive_timeout=4
        )
        # keepalive_interval = 4 // 2 = 2 seconds

        sendall_calls: list[bytes] = []
        self.tunnel._ssl_sock.sendall.side_effect = sendall_calls.append

        with patch("snxui.core.ssl_tunnel.select.select") as mock_select, \
             patch("snxui.core.ssl_tunnel.time.monotonic") as mock_time:

            # t=0.0 → last_keepalive set; t=0.0 → timeout; select returns []
            # t=2.0 → interval elapsed → send keepalive; then select returns pipe_r
            times = iter([0.0, 0.0, 2.0, 2.0, 2.0, 2.0])
            mock_time.side_effect = lambda: next(times)

            select_count = [0]

            def fake_select(rlist: list, wlist: list, xlist: list, timeout: float):
                select_count[0] += 1
                if select_count[0] >= 2:
                    return ([self.tunnel._pipe_r], [], [])
                return ([], [], [])

            mock_select.side_effect = fake_select
            self.tunnel.run_packet_loop()

        # At least one SLIM control frame containing "(keepalive" was sent
        # (snx-rs proto.rs KeepaliveRequest: outer wrapper is "(keepalive ...)")
        keepalive_frames = [
            d for d in sendall_calls
            if len(d) >= 8
            and struct.unpack(">II", d[:8])[1] == 1   # type=1 (control) — [1] is TYPE (LENGTH first)
            and b"(keepalive" in d
        ]
        assert len(keepalive_frames) >= 1

    @patch("snxui.core.ssl_tunnel.subprocess.run")
    def test_ssl_pending_drained_without_select_block(
        self, _mock_run: object
    ) -> None:
        """SSL pending data is drained BEFORE select() is called."""
        ip_packet = b"\x45" * 40
        frame = _slim_frame(2, ip_packet)

        data = frame
        pos = [0]

        def fake_recv(n: int) -> bytes:
            chunk = data[pos[0]: pos[0] + n]
            pos[0] += n
            return chunk

        pending_calls = [0]

        def fake_pending() -> int:
            pending_calls[0] += 1
            # First call: data is pending; subsequent calls: nothing
            return len(frame) if pending_calls[0] == 1 else 0

        self.tunnel._ssl_sock.recv.side_effect = fake_recv
        self.tunnel._ssl_sock.pending.side_effect = fake_pending

        with patch("snxui.core.ssl_tunnel.select.select") as mock_select, \
             patch("snxui.core.ssl_tunnel.os.write"):

            mock_select.side_effect = lambda *a, **kw: (
                [self.tunnel._pipe_r], [], []
            )
            self.tunnel.run_packet_loop()

        # pending() was called at least once (before select)
        assert pending_calls[0] >= 1
        # The frame was consumed (recv was called)
        assert self.tunnel._ssl_sock.recv.call_count > 0
        # select was eventually called (after draining)
        assert mock_select.call_count >= 1

    @patch("snxui.core.ssl_tunnel.subprocess.run")
    def test_on_disconnect_callback_called(self, _mock_run: object) -> None:
        """on_disconnect is called when the loop exits."""
        called = []

        with patch("snxui.core.ssl_tunnel.select.select") as mock_select:
            mock_select.return_value = ([self.tunnel._pipe_r], [], [])
            self.tunnel.run_packet_loop(on_disconnect=lambda: called.append(True))

        assert called == [True]


# ---------------------------------------------------------------------------
# TestPythonSSLBackend
# ---------------------------------------------------------------------------


class TestPythonSSLBackend:
    """Tests for PythonSSLBackend.connect / disconnect / get_status."""

    def _make_config(self, ip: str = "10.0.0.5") -> TunnelConfig:
        return TunnelConfig(
            assigned_ip=ip,
            dns_servers=["8.8.8.8"],
            routes=[("10.0.0.0", "8")],
            keepalive_timeout=20,
        )

    def _make_mock_tunnel(
        self, config: Optional[TunnelConfig] = None
    ) -> MagicMock:
        mock = MagicMock()
        mock.connect.return_value = config or self._make_config()
        mock.run_packet_loop.return_value = None
        return mock

    def test_connect_calls_ccc_auth_then_tunnel(self) -> None:
        """connect() authenticates via CCC, then opens the SSL tunnel."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="vpn_ssl")
        mock_tunnel = self._make_mock_tunnel()
        statuses = []

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel", return_value=mock_tunnel), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
                 return_value=[],
             ):
            MockCCC.return_value.authenticate.return_value = "active_key_xyz"
            MockCCC.return_value.credentials_rejected = False

            result = backend.connect(
                profile,
                password="secret",
                status_callback=statuses.append,
            )

        assert result is True
        mock_tunnel.connect.assert_called_once()
        mock_tunnel.create_tun.assert_called_once()
        mock_tunnel.configure_net.assert_called_once()
        mock_tunnel.run_packet_loop.assert_called_once()

        states = [s.state for s in statuses]
        assert ConnectionState.CONNECTING in states
        assert ConnectionState.CONNECTED in states

    def test_connect_returns_false_on_ccc_failure(self) -> None:
        """connect() returns False when CCC authentication yields no active_key."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="vpn_ssl")
        statuses = []

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel"), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
                 return_value=[],
             ):
            MockCCC.return_value.authenticate.return_value = None
            MockCCC.return_value.credentials_rejected = False

            result = backend.connect(
                profile,
                password="wrong",
                status_callback=statuses.append,
            )

        assert result is False
        states = [s.state for s in statuses]
        assert ConnectionState.ERROR in states

    def test_connect_sets_connected_status(self) -> None:
        """CONNECTED status carries the assigned IP and interface name."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="vpn_ssl")
        mock_tunnel = self._make_mock_tunnel(self._make_config(ip="192.168.50.10"))
        statuses = []

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel", return_value=mock_tunnel), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
                 return_value=[],
             ):
            MockCCC.return_value.authenticate.return_value = "key"
            MockCCC.return_value.credentials_rejected = False

            backend.connect(
                profile,
                password="pw",
                status_callback=statuses.append,
            )

        connected = next(s for s in statuses if s.state == ConnectionState.CONNECTED)
        assert connected.ip_address == "192.168.50.10"
        assert connected.interface == "tunsnx"

    def test_disconnect_stops_tunnel(self) -> None:
        """disconnect() calls stop() on the active tunnel."""
        backend = PythonSSLBackend()
        mock_tunnel = MagicMock()
        backend._tunnel = mock_tunnel

        result = backend.disconnect()

        assert result is True
        mock_tunnel.stop.assert_called_once()

    def test_disconnect_when_no_tunnel(self) -> None:
        """disconnect() returns True even when no tunnel is active."""
        backend = PythonSSLBackend()
        assert backend.disconnect() is True

    def test_get_status_returns_cached(self) -> None:
        """get_status() returns the cached status without probing."""
        backend = PythonSSLBackend()
        status = backend.get_status()
        assert status.state == ConnectionState.DISCONNECTED

    def test_get_cached_status_returns_same_as_get_status(self) -> None:
        backend = PythonSSLBackend()
        assert backend.get_cached_status().state == ConnectionState.DISCONNECTED

    def test_auto_discovers_login_type_when_empty(self) -> None:
        """When profile.login_type is empty, discover_login_options is called."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="")   # empty → must auto-discover
        mock_tunnel = self._make_mock_tunnel()

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel", return_value=mock_tunnel), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
             ) as mock_discover:
            mock_discover.return_value = [("vpn_ssl_vpn", "SSL VPN")]
            MockCCC.return_value.authenticate.return_value = "active_key"
            MockCCC.return_value.credentials_rejected = False

            backend.connect(profile, password="pw")

        mock_discover.assert_called_once()
        # CCC auth must have used the discovered realm
        call_kwargs = MockCCC.return_value.authenticate.call_args[1]
        assert call_kwargs.get("realm") == "vpn_ssl_vpn"

    def test_permission_error_on_configure_net_gives_helpful_message(self) -> None:
        """When configure_net raises PermissionError, ERROR status mentions polkit."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="vpn_ssl")
        mock_tunnel = self._make_mock_tunnel()
        mock_tunnel.configure_net.side_effect = PermissionError(
            "VPN network setup failed (pkexec exit 126): Not authorized"
        )
        statuses = []

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel", return_value=mock_tunnel), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
                 return_value=[],
             ):
            MockCCC.return_value.authenticate.return_value = "active_key"
            MockCCC.return_value.credentials_rejected = False

            result = backend.connect(
                profile,
                password="pw",
                status_callback=statuses.append,
            )

        assert result is False
        error_status = next(
            s for s in statuses if s.state == ConnectionState.ERROR
        )
        # Error message must mention authorization and how to fix it
        msg = error_status.error_message or ""
        assert "authorization" in msg.lower() or "polkit" in msg.lower() or "policy" in msg.lower()

    def test_create_tun_invalid_name_gives_error(self) -> None:
        """When create_tun raises ValueError (invalid name), ERROR status is set."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="vpn_ssl")
        mock_tunnel = self._make_mock_tunnel()
        mock_tunnel.create_tun.side_effect = ValueError("Invalid TUN interface name")
        statuses = []

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel", return_value=mock_tunnel), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
                 return_value=[],
             ):
            MockCCC.return_value.authenticate.return_value = "active_key"
            MockCCC.return_value.credentials_rejected = False

            result = backend.connect(
                profile,
                password="pw",
                status_callback=statuses.append,
            )

        assert result is False
        error_status = next(s for s in statuses if s.state == ConnectionState.ERROR)
        assert "Invalid TUN interface name" in (error_status.error_message or "")

    def test_wrong_password_sets_error_with_message(self) -> None:
        """credentials_rejected=True produces a clear wrong-password message."""
        backend = PythonSSLBackend()
        profile = _make_profile(login_type="vpn_ssl")
        statuses = []

        with patch("snxui.core.ccc_auth.CCCAuth") as MockCCC, \
             patch("snxui.core.ssl_tunnel.SSLTunnel"), \
             patch(
                 "snxui.core.ccc_auth.discover_login_options",
                 return_value=[],
             ):
            MockCCC.return_value.authenticate.return_value = None
            MockCCC.return_value.credentials_rejected = True

            backend.connect(
                profile,
                password="wrong",
                status_callback=statuses.append,
            )

        error_status = next(
            s for s in statuses if s.state == ConnectionState.ERROR
        )
        assert "password" in (error_status.error_message or "").lower()
