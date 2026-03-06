"""Pure Python SSL VPN backend — no external binaries required.

This backend authenticates via the CCC protocol
(:mod:`snxui.core.ccc_auth`) to obtain an ``active_key``, then establishes
a SLIM-framed SSL tunnel using :class:`~snxui.core.ssl_tunnel.SSLTunnel`
— the same approach used by snx-rs but implemented entirely in Python.

**Profile setting:** ``backend = "python_ssl"``

**Requirements:**

* ``snxui-net-helper`` installed at ``/usr/lib/snxui/snxui-net-helper``
  (root:root, mode 0755) — run ``make install-helper``.
* ``com.snxui.policy`` polkit action installed — run ``make install-policy``.

No ``CAP_NET_ADMIN`` capability or ``setcap`` is needed.  TUN interface
setup is performed by the helper via ``pkexec`` (one polkit prompt per
desktop session, thanks to ``auth_admin_keep``).
"""

from __future__ import annotations

import dataclasses
import logging
import ssl
import threading
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .ssl_tunnel import SSLTunnel as _SSLTunnel

from .types import ConnectionState, ConnectionStatus, Profile, TwoFactorCallback
from .vpn_backend import VPNBackend

logger = logging.getLogger(__name__)

# TUN interface name created by this backend
_TUN_IFACE = "tunsnx"


class PythonSSLBackend(VPNBackend):
    """VPN backend: CCC auth → SLIM SSL tunnel (pure Python, no binaries).

    Instantiate once per connection attempt.  :meth:`connect` blocks until
    the tunnel terminates (or errors) and is designed to run in a daemon
    background thread — exactly as :class:`~snxui.ui.home_page.HomePage`
    does for all backends.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status = ConnectionStatus(state=ConnectionState.DISCONNECTED)
        self._tunnel: Optional[_SSLTunnel] = None  # SSLTunnel, imported lazily

    # ------------------------------------------------------------------
    # VPNBackend interface
    # ------------------------------------------------------------------

    def connect(
        self,
        profile: Profile,
        password: str,
        status_callback: Optional[Callable[[ConnectionStatus], None]] = None,
        two_factor_callback: Optional[TwoFactorCallback] = None,
    ) -> bool:
        """Connect using CCC auth and a pure Python SSL SLIM tunnel.

        Designed to run in a daemon background thread.

        Args:
            profile:             Connection profile (server, user, ssl_port, …).
            password:            Plaintext password (never logged).
            status_callback:     Called on each state change (thread-safe).
            two_factor_callback: Called for MFA prompts; returns code or None.

        Returns:
            ``True`` when a connection was successfully established and later
            closed cleanly.  ``False`` on authentication or tunnel errors.
        """
        def _notify(status: ConnectionStatus) -> None:
            with self._lock:
                self._status = status
            if status_callback:
                try:
                    status_callback(status)
                except Exception:
                    logger.exception("Exception in status callback")

        _notify(ConnectionStatus(state=ConnectionState.CONNECTING, profile=profile))
        try:
            return self._do_connect(profile, password, _notify, two_factor_callback)
        except Exception as exc:
            logger.exception("PythonSSLBackend.connect failed: %s", exc)
            _notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=str(exc),
            ))
            return False

    def disconnect(self) -> bool:
        """Stop the active SSL tunnel.

        Thread-safe: signals the packet loop to exit via the stop pipe.

        Returns:
            ``True`` always (stop is best-effort).
        """
        with self._lock:
            tunnel = self._tunnel
        if tunnel is not None:
            try:
                tunnel.stop()
            except Exception as exc:
                logger.warning("PythonSSLBackend: tunnel.stop() error: %s", exc)
        with self._lock:
            self._status = ConnectionStatus(state=ConnectionState.DISCONNECTED)
        return True

    def get_status(self) -> ConnectionStatus:
        """Return the current connection status (cached, no system probing)."""
        with self._lock:
            return self._status

    def get_cached_status(self) -> Optional[ConnectionStatus]:
        """Return the last cached :class:`ConnectionStatus`."""
        with self._lock:
            return self._status

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _do_connect(
        self,
        profile: Profile,
        password: str,
        notify: Callable[[ConnectionStatus], None],
        two_factor_callback: Optional[TwoFactorCallback],
    ) -> bool:
        """Core connection logic — runs in the background thread.

        Sequence:

        1. Auto-discover ``login_type`` when the profile has none.
        2. CCC authentication → ``active_key``.
        3. Open SSL tunnel + SLIM handshake → :class:`TunnelConfig`.
        4. Create TUN device (requires ``CAP_NET_ADMIN``).
        5. Configure network (ip addr + ip route).
        6. Notify ``CONNECTED``.
        7. Run packet loop (blocks until disconnect or error).

        Returns ``True`` on clean completion, ``False`` on error.
        """
        from .ccc_auth import CCCAuth, discover_login_options  # noqa: PLC0415
        from .ssl_tunnel import SSLTunnel  # noqa: PLC0415

        # 1. Auto-discover login_type when not set in the profile.
        if not profile.login_type:
            options = discover_login_options(
                profile.server,
                port=profile.ssl_port,
                verify_ssl=not profile.ignore_server_cert,
            )
            if options:
                discovered = options[0][0]
                logger.info(
                    "PythonSSLBackend: auto-discovered login_type=%r "
                    "(available: %s)",
                    discovered,
                    ", ".join(f"{id_!r}" for id_, _ in options),
                )
                profile = dataclasses.replace(profile, login_type=discovered)
            else:
                logger.warning(
                    "PythonSSLBackend: could not auto-discover login_type for %s "
                    "— proceeding without it (connection may fail).",
                    profile.server,
                )

        # 2. CCC authentication → active_key.
        ccc = CCCAuth(
            server=profile.server,
            port=profile.ssl_port,
            verify_ssl=not profile.ignore_server_cert,
        )
        active_key = ccc.authenticate(
            username=profile.username,
            password=password,
            realm=profile.login_type,
            otp_callback=two_factor_callback,
        )
        if not active_key:
            if ccc.credentials_rejected:
                err = "CCC authentication failed: wrong username or password."
            else:
                err = "CCC authentication failed — no active_key obtained."
            logger.error("PythonSSLBackend: %s", err)
            notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=err,
            ))
            return False

        # tcpt_port from connectivity_info overrides profile.ssl_port for the SLIM tunnel.
        # Many Check Point gateways advertise a different port for the data tunnel
        # (TCPT = TCP Tunneling) than for CCC auth.  Fallback: profile.ssl_port.
        tunnel_port = ccc.tcpt_port or profile.ssl_port
        logger.info(
            "PythonSSLBackend: CCC auth succeeded, active_key=%.12s… "
            "(tcpt_port=%d, profile.ssl_port=%d → using port=%d)",
            active_key, ccc.tcpt_port, profile.ssl_port, tunnel_port,
        )

        # 3. TLS context.
        ssl_ctx = ssl.create_default_context()
        if profile.ignore_server_cert:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        # 4. Connect the SSL tunnel (TLS handshake + SLIM client_hello).
        tunnel = SSLTunnel()
        with self._lock:
            self._tunnel = tunnel

        try:
            config = tunnel.connect(
                server=profile.server,
                port=tunnel_port,
                active_key=active_key,
                ssl_ctx=ssl_ctx,
                session_id=ccc.session_id,
            )
        except Exception as exc:
            err = f"SSL tunnel connect failed: {exc}"
            logger.error("PythonSSLBackend: %s", err)
            notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=err,
            ))
            tunnel.close()
            with self._lock:
                self._tunnel = None
            return False

        # 5. Validate TUN interface name (no OS calls at this stage).
        try:
            tunnel.create_tun(_TUN_IFACE)
        except ValueError as exc:
            err = f"Invalid TUN interface name: {exc}"
            logger.error("PythonSSLBackend: %s", err)
            notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=err,
            ))
            tunnel.close()
            with self._lock:
                self._tunnel = None
            return False

        # 6. Configure network via pkexec + snxui-net-helper, then open TUN fd.
        try:
            tunnel.configure_net(config, _TUN_IFACE)
        except PermissionError as exc:
            err = (
                "VPN network setup requires authorization.\n"
                "Ensure the snxui net-helper and polkit policy are installed:\n"
                "  sudo install -Dm755 snxui/helpers/snxui-net-helper "
                "/usr/lib/snxui/snxui-net-helper\n"
                "  sudo install -Dm644 snxui/data/com.snxui.policy "
                "/usr/share/polkit-1/actions/com.snxui.policy\n"
                f"Details: {exc}"
            )
            logger.error("PythonSSLBackend: %s", err)
            notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=err,
            ))
            tunnel.close()
            with self._lock:
                self._tunnel = None
            return False
        except (OSError, ValueError, RuntimeError) as exc:
            err = f"Network configuration failed: {exc}"
            logger.error("PythonSSLBackend: %s", err)
            notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=err,
            ))
            tunnel.close()
            with self._lock:
                self._tunnel = None
            return False

        # 7. Detect split-tunnel mode and notify CONNECTED.
        # Full-tunnel via single 0.0.0.0/0 route OR via the classic two-/1
        # pattern (0.0.0.0/1 + 128.0.0.0/1 together cover the entire address
        # space and are functionally equivalent to a default route).
        route_set = {(net, prefix) for net, prefix in config.routes}
        has_default_route = (
            ("0.0.0.0", "0") in route_set
            or (("0.0.0.0", "1") in route_set and ("128.0.0.0", "1") in route_set)
        )
        conn_warning = (
            None if has_default_route else
            "Split-tunnel mode: only corporate routes go through VPN — other traffic uses your ISP"
        )
        notify(ConnectionStatus(
            state=ConnectionState.CONNECTED,
            profile=profile,
            ip_address=config.assigned_ip,
            interface=_TUN_IFACE,
            warning=conn_warning,
        ))

        # 8. Run packet loop — blocks until disconnect or error.
        def _on_disconnect() -> None:
            notify(ConnectionStatus(
                state=ConnectionState.DISCONNECTED,
                profile=profile,
            ))

        tunnel.run_packet_loop(on_disconnect=_on_disconnect)

        # Cleanup after loop exits (_teardown_net already called inside loop).
        tunnel.close()
        with self._lock:
            self._tunnel = None

        return True
