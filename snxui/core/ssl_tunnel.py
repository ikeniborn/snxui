"""SSL SLIM-framed VPN tunnel for Check Point gateways.

This module implements the SSL SLIM (Simple Layer Interface Module) protocol
used by Check Point SNX VPN for the data channel.  After CCC authentication
yields an ``active_key``, the tunnel is established with:

1. TLS connection to the gateway ssl_port
2. SLIM ClientHello (type=1 control frame, cookie=active_key)
3. SLIM hello_reply → assigned IP, DNS, routes
4. Bidirectional packet loop: TUN ↔ SSL SLIM type=2 frames

SLIM frame format::

    [4B BE uint32 payload_length][4B BE uint32 frame_type][payload]
    frame_type=1 : Control — S-expression UTF-8 + null terminator
    frame_type=2 : Data — raw IP packet

TUN interface setup uses a privileged helper (``snxui-net-helper``) invoked
via ``pkexec``.  The helper creates a user-owned persistent TUN device, which
allows the unprivileged snxui process to open ``/dev/net/tun`` and call
``TUNSETIFF`` without ``CAP_NET_ADMIN``.  No ``setcap`` is required.
"""

from __future__ import annotations

import fcntl
import logging
import math
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# SLIM frame type constants
_SLIM_CONTROL = 1  # S-expression control frame
_SLIM_DATA = 2     # Raw IP packet data frame

# Linux TUN device ioctl constants (from <linux/if_tun.h>)
_TUNSETIFF = 0x400454CA
_IFF_TUN = 0x0001
_IFF_NO_PI = 0x1000   # No packet information prefix

# MTU for the TUN device — Check Point SNX default
_TUN_MTU = 1350
# Maximum IP packet size to read from TUN
_MAX_PACKET = 65536

# Valid Linux interface name: 1–15 alphanumeric chars, hyphens, or underscores.
# Enforced in create_tun() and configure_net() to prevent argument injection.
_IFACE_RE = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")

# Maximum keepalive interval accepted from the gateway (seconds).
# Prevents a hostile gateway from freezing the packet loop indefinitely.
_MAX_KEEPALIVE_SECS = 300

# Maximum SLIM frame payload size (bytes).
# Control frames (S-expressions) and data frames (IP packets) are both bounded
# by this limit.  A well-behaved gateway never exceeds _MAX_PACKET; rejecting
# larger frames prevents memory exhaustion from a misbehaving/malicious gateway.
_MAX_FRAME_SIZE = _MAX_PACKET  # 65536 bytes

# Maximum number of buffered TLS frames drained per packet-loop iteration.
# Prevents an infinite drain loop when the gateway streams data continuously.
_MAX_DRAIN = 64

# TUN ioctl constants (from <linux/if_tun.h>)
# TUNSETPERSIST clears the persistent flag so the interface is destroyed when
# the last file descriptor referencing it is closed.  The holder of an open
# tuntap fd may clear persistence without CAP_NET_ADMIN — no pkexec required.
_TUNSETPERSIST = 0x400454CB

# Path to the privileged helper script installed by 'make install-helper'.
# Invoked via pkexec for TUN interface creation and teardown.
_NET_HELPER = "/usr/lib/snxui/snxui-net-helper"


@dataclass
class TunnelConfig:
    """Network configuration obtained from the SLIM hello_reply.

    Attributes:
        assigned_ip:       Tunnel IP address assigned by the gateway.
        dns_servers:       DNS server addresses pushed by the gateway.
        routes:            List of ``(network, prefix_len)`` tuples to route
                           through the tunnel.
        keepalive_timeout: Server-requested keepalive interval in seconds.
    """

    assigned_ip: str
    dns_servers: list[str] = field(default_factory=list)
    routes: list[tuple[str, str]] = field(default_factory=list)
    keepalive_timeout: int = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _range_to_cidr(from_ip: str, to_ip: str) -> Optional[tuple[str, str]]:
    """Convert an IP range (from, to) to CIDR notation.

    Args:
        from_ip: Start of IP range (e.g. ``"10.0.0.0"``).
        to_ip:   End of IP range (e.g. ``"10.255.255.255"``).

    Returns:
        ``(network, prefix_len)`` tuple, e.g. ``("10.0.0.0", "8")``,
        or ``None`` when either address is not a valid IPv4 address.
        Falls back to a /32 host route for degenerate (from >= to) ranges.
    """
    try:
        f = struct.unpack(">I", socket.inet_aton(from_ip))[0]
        t = struct.unpack(">I", socket.inet_aton(to_ip))[0]
    except OSError:
        logger.warning(
            "Skipping route with invalid IP range: from=%r to=%r", from_ip, to_ip
        )
        return None

    if f >= t:
        return (from_ip, "32")

    size = t - f + 1
    bits = max(0, int(math.log2(size)))
    prefix = 32 - bits

    # Align the network address to the prefix boundary
    mask = (~((1 << bits) - 1)) & 0xFFFFFFFF
    network_int = f & mask
    network = socket.inet_ntoa(struct.pack(">I", network_int))
    return (network, str(prefix))


# ---------------------------------------------------------------------------
# SSLTunnel
# ---------------------------------------------------------------------------


class SSLTunnel:
    """SLIM-framed SSL tunnel to a Check Point VPN gateway.

    Call the methods in sequence::

        tunnel = SSLTunnel()
        config = tunnel.connect(server, port, active_key, ssl_ctx)
        fd     = tunnel.create_tun("tunsnx")
        tunnel.configure_net(config, "tunsnx")
        # In another thread: tunnel.stop()
        tunnel.run_packet_loop(on_disconnect=callback)   # blocks
        tunnel.close()
    """

    def __init__(self) -> None:
        self._ssl_sock: Optional[ssl.SSLSocket] = None
        self._tun_fd: int = -1
        self._iface_name: str = ""
        self._config: Optional[TunnelConfig] = None
        # Pipe pair: write to _pipe_w to stop run_packet_loop
        self._pipe_r: int = -1
        self._pipe_w: int = -1
        self._stopped: bool = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(
        self,
        server: str,
        port: int,
        active_key: str,
        ssl_ctx: Optional[ssl.SSLContext] = None,
        session_id: str = "",
    ) -> TunnelConfig:
        """Open SSL connection and perform the SLIM client_hello / hello_reply.

        Args:
            server:     VPN gateway hostname or IP.
            port:       HTTPS port (typically 443 or from profile.ssl_port).
            active_key: Session token from CCC authentication.
            ssl_ctx:    SSL context; a default (verify-on) context is created
                        when ``None``.
            session_id: Unused — kept for API compatibility.  The SLIM SSL
                        ClientHello does not include a RequestHeader or
                        session_id (per snx-rs ssl.rs / proto.rs).

        Returns:
            :class:`TunnelConfig` with assigned IP, DNS, and routes.

        Raises:
            RuntimeError: On SLIM protocol errors or unexpected response.
            OSError: On socket or TLS errors.
        """
        if ssl_ctx is None:
            ssl_ctx = ssl.create_default_context()

        self._pipe_r, self._pipe_w = os.pipe()

        logger.info("SSL tunnel: connecting to %s:%d", server, port)
        raw_sock = socket.create_connection((server, port), timeout=30)
        self._ssl_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=server)
        logger.debug("SSL tunnel: TLS handshake complete")

        hello_payload = self._build_client_hello(active_key).encode("utf-8")
        self._send_slim(_SLIM_CONTROL, hello_payload)
        logger.debug("SSL tunnel: sent client_hello (%d bytes)", len(hello_payload))

        ftype, reply_payload = self._recv_slim()
        if ftype != _SLIM_CONTROL:
            raise RuntimeError(
                f"SSL tunnel: expected SLIM control frame (type=1), got type={ftype}"
            )

        config = self._parse_hello_reply(
            reply_payload.decode("utf-8", errors="replace")
        )
        self._config = config
        logger.info(
            "SSL tunnel: hello_reply: ip=%s routes=%d dns=%s keepalive=%ds",
            config.assigned_ip, len(config.routes),
            config.dns_servers, config.keepalive_timeout,
        )
        return config

    def create_tun(self, iface_name: str = "tunsnx") -> int:
        """Validate the TUN interface name and save it for later use.

        The actual TUN device is created by the privileged ``snxui-net-helper``
        script (invoked via ``pkexec``) inside :meth:`configure_net`.  This
        method only validates the name and stores it — no OS calls are made.

        Args:
            iface_name: Desired interface name (default ``tunsnx``).

        Returns:
            ``0`` — placeholder; the real TUN file descriptor is set by
            :meth:`configure_net` after the helper creates the device.

        Raises:
            ValueError: When *iface_name* does not match the valid pattern
                (1–15 alphanumeric characters, hyphens, or underscores).
        """
        if not _IFACE_RE.match(iface_name):
            raise ValueError(
                f"Invalid TUN interface name {iface_name!r}: "
                "must be 1–15 alphanumeric characters, hyphens, or underscores."
            )
        self._iface_name = iface_name
        logger.debug("SSL tunnel: TUN interface name validated: %r", iface_name)
        return 0

    def configure_net(self, config: TunnelConfig, iface: str) -> None:
        """Configure the VPN network interface via the privileged helper.

        Steps:

        1. Validates *config.assigned_ip* and *iface* against known-good patterns.
        2. Invokes ``pkexec /usr/lib/snxui/snxui-net-helper create …`` to:

           * Delete any stale interface with the same name.
           * Create a persistent user-owned TUN device via ``ip tuntap add``.
           * Assign the IP address and bring the interface up.
           * Add all VPN routes.
           * Configure DNS via ``resolvectl`` when ``dns_servers`` is non-empty.

        3. Opens ``/dev/net/tun`` and calls ``TUNSETIFF`` — allowed without
           ``CAP_NET_ADMIN`` because the device is owned by the current user.
        4. Stores the resulting file descriptor in ``self._tun_fd``.

        Args:
            config: :class:`TunnelConfig` returned by :meth:`connect`.
            iface:  Interface name (e.g. ``"tunsnx"``).

        Raises:
            ValueError: When *assigned_ip* or *iface* fails validation.
            PermissionError: When ``pkexec`` is cancelled or the helper fails.
            OSError: When opening ``/dev/net/tun`` or calling ``TUNSETIFF`` fails.
        """
        # Validate gateway-supplied values before passing to subprocess args.
        try:
            socket.inet_aton(config.assigned_ip)
        except OSError:
            raise ValueError(
                f"Gateway assigned an invalid IP address: {config.assigned_ip!r}"
            )
        if not _IFACE_RE.match(iface):
            raise ValueError(f"Invalid interface name: {iface!r}")

        route_args = [f"{net}/{prefix}" for net, prefix in config.routes]

        valid_dns: list[str] = []
        for dns in config.dns_servers:
            try:
                socket.inet_aton(dns)
                valid_dns.append(dns)
            except OSError:
                logger.warning(
                    "configure_net: ignoring invalid DNS server IP: %r", dns
                )
        dns_args = ["--dns"] + valid_dns if valid_dns else []

        cmd = [
            "pkexec", _NET_HELPER, "create", iface,
            str(os.getuid()), config.assigned_ip,
        ] + route_args + dns_args

        logger.info(
            "TUN interface %s: invoking helper via pkexec (ip=%s routes=%d dns=%d)",
            iface, config.assigned_ip, len(config.routes), len(valid_dns),
        )
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise PermissionError(
                f"VPN network setup failed (pkexec exit {result.returncode}): {detail}"
            )

        logger.debug("Helper output: %s", result.stdout.strip())

        # Open the user-owned persistent TUN device — no CAP_NET_ADMIN needed.
        fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack(
            "16sH22s",
            iface.encode()[:15],
            _IFF_TUN | _IFF_NO_PI,
            b"\x00" * 22,
        )
        try:
            fcntl.ioctl(fd, _TUNSETIFF, ifr)
        except OSError:
            os.close(fd)
            raise

        self._tun_fd = fd
        logger.info(
            "TUN interface %s configured (fd=%d, ip=%s routes=%d)",
            iface, fd, config.assigned_ip, len(config.routes),
        )

    def run_packet_loop(
        self,
        on_disconnect: Optional[Callable[[], None]] = None,
    ) -> None:
        """Run the bidirectional IP packet forwarding loop.

        Blocks until :meth:`stop` is called or the SSL connection drops.
        Keepalives are sent every ``keepalive_timeout // 2`` seconds.

        Call :meth:`close` after this method returns to free resources.

        Args:
            on_disconnect: Callback invoked once after the loop exits.
        """
        if self._ssl_sock is None:
            raise RuntimeError(
                "SSLTunnel.run_packet_loop called before connect()"
            )
        if self._tun_fd < 0:
            raise RuntimeError(
                "SSLTunnel.run_packet_loop called before configure_net()"
            )

        config = self._config
        keepalive_interval = (config.keepalive_timeout // 2) if config else 10
        if keepalive_interval <= 0:
            keepalive_interval = 10

        last_keepalive = time.monotonic()
        ssl_fd = self._ssl_sock.fileno()
        logger.info(
            "SSL tunnel: packet loop started (keepalive_interval=%ds)",
            keepalive_interval,
        )

        try:
            while True:
                # Drain data buffered inside the TLS layer BEFORE select().
                # ssl.SSLSocket.pending() counts already-decrypted bytes — the
                # underlying socket fd may not be readable even when data is
                # ready, so we must drain first.
                # Limit iterations to avoid an infinite loop if the gateway
                # streams data continuously without pausing.
                for _ in range(_MAX_DRAIN):
                    if self._ssl_sock.pending() <= 0:
                        break
                    try:
                        ftype, payload = self._recv_slim()
                        self._handle_incoming(ftype, payload)
                    except (EOFError, OSError, ssl.SSLError) as exc:
                        logger.info(
                            "SSL tunnel: connection closed during pending drain: %s",
                            exc,
                        )
                        return

                now = time.monotonic()
                timeout = max(0.1, keepalive_interval - (now - last_keepalive))

                try:
                    readable, _, _ = select.select(
                        [self._tun_fd, ssl_fd, self._pipe_r], [], [], timeout
                    )
                except OSError as exc:
                    logger.error("SSL tunnel: select error: %s", exc)
                    break

                if self._pipe_r in readable:
                    logger.info("SSL tunnel: stop signal received")
                    break

                if self._tun_fd in readable:
                    try:
                        packet = os.read(self._tun_fd, _MAX_PACKET)
                        if packet:
                            self._send_slim(_SLIM_DATA, packet)
                    except OSError as exc:
                        logger.error("SSL tunnel: TUN read error: %s", exc)
                        break

                if ssl_fd in readable:
                    try:
                        ftype, payload = self._recv_slim()
                        self._handle_incoming(ftype, payload)
                    except (EOFError, OSError, ssl.SSLError) as exc:
                        logger.info(
                            "SSL tunnel: connection closed: %s", exc
                        )
                        break

                # Send keepalive when the interval has elapsed
                now = time.monotonic()
                if now - last_keepalive >= keepalive_interval:
                    kp = self._build_keepalive().encode()
                    try:
                        self._send_slim(_SLIM_CONTROL, kp)
                        logger.debug("SSL tunnel: keepalive sent")
                    except OSError as exc:
                        logger.error(
                            "SSL tunnel: keepalive send failed: %s", exc
                        )
                        break
                    last_keepalive = now

        finally:
            logger.info("SSL tunnel: packet loop exited")
            self._teardown_net()
            if on_disconnect:
                try:
                    on_disconnect()
                except Exception:
                    logger.exception("Exception in on_disconnect callback")

    def stop(self) -> None:
        """Signal the packet loop to exit.

        Thread-safe — may be called from any thread.
        """
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        if self._pipe_w >= 0:
            try:
                os.write(self._pipe_w, b"\x00")
            except OSError:
                pass

    def close(self) -> None:
        """Close all resources: SSL socket, TUN fd, and pipes.

        Call after :meth:`run_packet_loop` returns.
        """
        self.stop()
        if self._ssl_sock is not None:
            try:
                self._ssl_sock.close()
            except OSError:
                pass
            self._ssl_sock = None
        if self._tun_fd >= 0:
            try:
                os.close(self._tun_fd)
            except OSError:
                pass
            self._tun_fd = -1
        for fd_attr in ("_pipe_r", "_pipe_w"):
            fd = getattr(self, fd_attr)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_attr, -1)

    # ------------------------------------------------------------------
    # SLIM protocol helpers
    # ------------------------------------------------------------------

    def _send_slim(self, ftype: int, payload: bytes) -> None:
        """Encode and send one SLIM frame.

        Frame: ``[4B BE uint32 payload_len][4B BE uint32 type][payload]``

        Control frames (type=1) append a null terminator that is included
        in the length field — matching snx-rs ``codec.rs`` behaviour.

        Args:
            ftype:   Frame type (1 = control, 2 = data).
            payload: Raw bytes to send (without null terminator).
        """
        if self._ssl_sock is None:
            raise RuntimeError("_send_slim called before connect()")
        if ftype == _SLIM_CONTROL:
            payload = payload + b"\x00"
        header = struct.pack(">II", len(payload), ftype)
        self._ssl_sock.sendall(header + payload)

    def _recv_slim(self) -> tuple[int, bytes]:
        """Receive one SLIM frame from the SSL connection.

        Frame: ``[4B BE uint32 payload_len][4B BE uint32 type][payload]``

        Null terminators on control frames are stripped before returning.

        Returns:
            ``(frame_type, payload)`` tuple.

        Raises:
            EOFError: When the peer closes the connection mid-frame.
        """
        header = self._recv_exact(8)
        length, ftype = struct.unpack(">II", header)
        if length > _MAX_FRAME_SIZE:
            raise RuntimeError(
                f"SLIM frame too large: {length} bytes (max {_MAX_FRAME_SIZE}). "
                "Possible protocol error or malicious gateway."
            )
        payload = self._recv_exact(length)
        if ftype == _SLIM_CONTROL:
            payload = payload.removesuffix(b"\x00")
        return ftype, payload

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes, handling TLS record fragmentation.

        Args:
            n: Number of bytes required.

        Returns:
            Exactly *n* bytes.

        Raises:
            EOFError: When the peer closes the connection before *n* bytes
                      are received.
        """
        buf = bytearray()
        while len(buf) < n:
            chunk = self._ssl_sock.recv(n - len(buf))  # type: ignore[union-attr]
            if not chunk:
                raise EOFError(
                    f"SSL connection closed "
                    f"(received {len(buf)}/{n} bytes)"
                )
            buf.extend(chunk)
        return bytes(buf)

    def _handle_incoming(self, ftype: int, payload: bytes) -> None:
        """Process one incoming SLIM frame from the gateway.

        * ``type=2`` (data): write the raw IP packet to the TUN device.
        * ``type=1`` (control): log for diagnostics (keepalive replies, etc).
        """
        if ftype == _SLIM_DATA:
            if self._tun_fd >= 0 and payload:
                try:
                    os.write(self._tun_fd, payload)
                except OSError as exc:
                    logger.debug("SSL tunnel: TUN write error: %s", exc)
        elif ftype == _SLIM_CONTROL:
            logger.debug(
                "SSL tunnel: control frame (%d bytes): %r",
                len(payload), payload[:80],
            )
        else:
            logger.debug(
                "SSL tunnel: unknown frame type=%d len=%d", ftype, len(payload)
            )

    # ------------------------------------------------------------------
    # Protocol builders / parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_client_hello(active_key: str) -> str:
        """Build the SLIM SSL ClientHello S-expression.

        This is the first message sent after TLS handshake over the SLIM
        control channel.  The format is completely different from CCC HTTP
        ClientHello — based on snx-rs ``proto.rs`` ``ClientHello`` struct:

        * Outer wrapper: ``(client_hello ...)`` — NOT ``(CCCclientRequest)``
        * No ``RequestHeader`` or ``session_id`` in the SLIM frame
        * ``office_mode`` is serialized as ``OM`` (serde rename in proto.rs)
        * ``optional.client_type = "4"`` (numeric string)
        * ``cookie`` = deobfuscated ``active_key`` from CCC auth

        Args:
            active_key: Plaintext session token from CCC authentication.
        """
        # Escape active_key for S-expression safety (quoted string context).
        escaped_key = (
            active_key
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        return (
            "(client_hello\n"
            " :client_version (1)\n"
            " :protocol_version (1)\n"
            " :protocol_minor_version (1)\n"
            " :OM (\n"
            "  :ipaddr (\"0.0.0.0\")\n"
            "  :keep_address (false)\n"
            " )\n"
            " :optional (\n"
            "  :client_type (\"4\")\n"
            " )\n"
            f" :cookie (\"{escaped_key}\")\n"
            ")\n"
        )

    def _parse_hello_reply(self, payload: str) -> TunnelConfig:
        """Parse a SLIM hello_reply control frame.

        Extracts:

        * Assigned IP from ``:OM (:ipaddr ...)`` (snx-rs) or ``:office_mode`` (fallback)
        * Keepalive from ``:timeouts (:keepalive ...)`` or ``:keepalive``
        * DNS servers from ``:OM (:dns_servers ...)`` or ``:optional (:dns ...)``
        * Routes from ``:range (:from ... :to ...)`` blocks

        Args:
            payload: UTF-8 decoded body of the SLIM control frame.

        Returns:
            :class:`TunnelConfig`.

        Raises:
            RuntimeError: When no valid IP address is found.
        """
        from .ccc_auth import (  # noqa: PLC0415
            _extract_sexp_block,
            _sexp_int,
            _sexp_str,
            _split_sexp_items,
        )

        logger.debug(
            "SSL hello_reply (%d bytes): %r", len(payload), payload[:400]
        )

        # ── Assigned IP ──────────────────────────────────────────────────
        # In the SLIM protocol, office_mode is serialized as "OM" (proto.rs
        # serde rename).  Fall back to "office_mode" for older gateways.
        office_block = (
            _extract_sexp_block(payload, "OM")
            or _extract_sexp_block(payload, "office_mode")
        )
        if office_block:
            assigned_ip = _sexp_str(office_block, "ipaddr")
        else:
            assigned_ip = _sexp_str(payload, "ipaddr")

        if not assigned_ip or assigned_ip == "0.0.0.0":
            raise RuntimeError(
                "SSL hello_reply: server did not assign an IP address. "
                f"Response preview: {payload[:200]!r}"
            )

        # ── Keepalive timeout ─────────────────────────────────────────────
        timeouts_block = _extract_sexp_block(payload, "timeouts")
        if timeouts_block:
            keepalive_timeout = _sexp_int(timeouts_block, "keepalive")
        else:
            keepalive_timeout = _sexp_int(payload, "keepalive")
        if keepalive_timeout <= 0:
            keepalive_timeout = 20
        elif keepalive_timeout > _MAX_KEEPALIVE_SECS:
            logger.warning(
                "SSL hello_reply: keepalive_timeout=%d exceeds max %d s — capping",
                keepalive_timeout, _MAX_KEEPALIVE_SECS,
            )
            keepalive_timeout = _MAX_KEEPALIVE_SECS

        # ── DNS servers ───────────────────────────────────────────────────
        dns_servers = self._parse_dns_servers(office_block, payload)

        # ── Routes ────────────────────────────────────────────────────────
        routes: list[tuple[str, str]] = []
        range_block = _extract_sexp_block(payload, "range")
        if range_block:
            # Determine format: a *list* of range items (each is a parenthesised
            # block with its own :from/:to) vs. a *single* range (:from/:to are
            # direct children of range_block).
            items = _split_sexp_items(range_block)
            list_items = [
                it for it in items
                if _sexp_str(it, "from") and _sexp_str(it, "to")
            ]
            if list_items:
                for item in list_items:
                    from_ip = _sexp_str(item, "from")
                    to_ip = _sexp_str(item, "to")
                    cidr = _range_to_cidr(from_ip, to_ip)
                    if cidr is not None:
                        routes.append(cidr)
            else:
                # Single range — :from/:to are direct children of range_block
                from_ip = _sexp_str(range_block, "from")
                to_ip = _sexp_str(range_block, "to")
                if from_ip and to_ip:
                    cidr = _range_to_cidr(from_ip, to_ip)
                    if cidr is not None:
                        routes.append(cidr)

        logger.info(
            "SSL hello_reply parsed: ip=%s routes=%d dns=%s keepalive=%ds",
            assigned_ip, len(routes), dns_servers, keepalive_timeout,
        )
        return TunnelConfig(
            assigned_ip=assigned_ip,
            dns_servers=dns_servers,
            routes=routes,
            keepalive_timeout=keepalive_timeout,
        )

    @staticmethod
    def _build_keepalive() -> str:
        """Build a SLIM keepalive S-expression.

        Per snx-rs ``keepalive.rs`` ``KeepaliveRequestData``, ``id`` is
        always ``"0"`` — the gateway does not use it as a sequence counter.

        Format::

            (keepalive
             :id ("0")
            )
        """
        return "(keepalive\n :id (\"0\")\n)\n"

    @staticmethod
    def _parse_dns_servers(
        office_block: Optional[str],
        payload: str,
    ) -> list[str]:
        """Extract DNS server addresses from a SLIM hello_reply payload.

        Tries three formats in order of preference:

        1. ``:OM :dns_servers`` — snx-rs ``OfficeMode.dns_servers`` list
        2. ``:optional :dns :primary/:secondary`` — older gateway format
        3. ``:optional :dns-servers`` list — oldest format

        Args:
            office_block: Parsed ``:OM`` or ``:office_mode`` block, or ``None``.
            payload:      Full hello_reply payload string.

        Returns:
            Up to 4 DNS server address strings (empty list if none found).
        """
        from .ccc_auth import _extract_sexp_block, _sexp_str, _split_sexp_items  # noqa: PLC0415

        # 1. OM.dns_servers (snx-rs OfficeMode format).
        if office_block:
            om_dns_block = _extract_sexp_block(office_block, "dns_servers")
            if om_dns_block:
                servers: list[str] = []
                for item in _split_sexp_items(om_dns_block)[:4]:
                    addr = item.strip().strip('"')
                    if addr:
                        servers.append(addr)
                return servers

        # 2. optional.dns :primary/:secondary (older format).
        optional_block = _extract_sexp_block(payload, "optional")
        if not optional_block:
            return []

        dns_block = _extract_sexp_block(optional_block, "dns")
        if dns_block:
            servers = []
            primary = _sexp_str(dns_block, "primary")
            secondary = _sexp_str(dns_block, "secondary")
            if primary:
                servers.append(primary)
            if secondary and secondary != primary:
                servers.append(secondary)
            return servers

        # 3. optional.dns-servers list (oldest format).
        dns_block2 = _extract_sexp_block(optional_block, "dns-servers")
        if dns_block2:
            servers = []
            for item in _split_sexp_items(dns_block2)[:4]:
                addr = _sexp_str(item, "ipaddr") or item.strip().strip('"')
                if addr:
                    servers.append(addr)
            return servers

        return []

    # ------------------------------------------------------------------
    # Network teardown
    # ------------------------------------------------------------------

    def _teardown_net(self) -> None:
        """Clear the TUN persistent flag so the interface is removed when the fd closes.

        Called from the ``finally`` block of :meth:`run_packet_loop` while
        ``self._tun_fd`` is still open.  :meth:`close` closes the fd
        immediately after, which causes the kernel to destroy the interface
        automatically — removing all associated routes and per-interface DNS
        configuration (systemd-resolved monitors interface events).

        No ``pkexec`` is needed: the holder of an open tuntap fd may call
        ``TUNSETPERSIST 0`` without ``CAP_NET_ADMIN``.  This avoids the polkit
        password prompt that the previous ``pkexec destroy`` approach triggered.

        Errors are logged but never re-raised — teardown must not mask the
        original disconnect reason.
        """
        if self._tun_fd < 0:
            return
        logger.info(
            "SSL tunnel: clearing persistent flag on %r (interface removed on fd close)",
            self._iface_name,
        )
        try:
            fcntl.ioctl(self._tun_fd, _TUNSETPERSIST, struct.pack("I", 0))
        except OSError as exc:
            logger.warning(
                "SSL tunnel: TUNSETPERSIST 0 failed for %r: %s",
                self._iface_name, exc,
            )
