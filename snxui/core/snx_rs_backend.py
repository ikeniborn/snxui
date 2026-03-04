"""snx-rs backend — integrates with the snx-rs daemon (snx-rs / snxctl).

snx-rs is a Rust reimplementation of Check Point SNX that uses the CCC
protocol natively.  It supports both SSL and IPSec tunnels and performs the
full authentication (including RADIUS MultiChallenge) internally, so only a
single OTP is ever required.

See: https://github.com/ancwrd1/snx-rs

Requirements:
    snx-rs  — snx-rs daemon binary, must be in PATH.
    snxctl  — snx-rs control CLI, must be in PATH.

The config file ``~/.config/snx-rs/snx-rs.conf`` is (re-)written before each
connect attempt.  The password is stored temporarily in the config file
(base64-encoded, file mode 0o600) and removed after a successful connection.
The snxd daemon reads the config when processing the ``snxctl connect``
command; the password is never passed as a CLI argument.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .types import ConnectionState, ConnectionStatus, Profile, TunnelType, TwoFactorCallback
from .vpn_backend import VPNBackend

logger = logging.getLogger(__name__)

# Path to the snx-rs configuration file.
_CONFIG_PATH = Path.home() / ".config" / "snx-rs" / "snx-rs.conf"

# Seconds to wait for the daemon to reach the Connected state.
_CONNECT_TIMEOUT = 60
# Seconds between snxctl status polls.
_POLL_INTERVAL = 2
# Seconds given to the daemon to start before the first status check.
_DAEMON_START_DELAY = 1.5


class SNXRsBackend(VPNBackend):
    """VPN backend that drives the snx-rs daemon (snx-rs) via snxctl.

    Instantiate once per connect/disconnect cycle.  The underlying daemon
    (``snx-rs -m command``) is long-lived and persists between connections;
    only ``snxctl connect`` / ``snxctl disconnect`` are called per session.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status = ConnectionStatus(state=ConnectionState.DISCONNECTED)

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
        """Connect using snx-rs daemon.

        This method is designed to run in a background thread (called by
        :class:`~snxui.ui.home_page.HomePage`).

        Args:
            profile: Connection profile with server/user/backend settings.
            password: Plaintext password — written temporarily to the config
                file (base64-encoded, 0o600) and removed after connect.
            status_callback: Called on each status change (thread-safe).
            two_factor_callback: Called when an MFA code is required; returns
                the code string or ``None`` to abort.

        Returns:
            ``True`` on successful connection, ``False`` otherwise.
        """
        def _notify(status: ConnectionStatus) -> None:
            with self._lock:
                self._status = status
            if status_callback:
                try:
                    status_callback(status)
                except Exception:
                    logger.exception("Exception in status callback.")

        _notify(ConnectionStatus(state=ConnectionState.CONNECTING, profile=profile))
        try:
            return self._do_connect(profile, password, _notify, two_factor_callback)
        except Exception as exc:
            logger.exception("SNXRsBackend.connect failed: %s", exc)
            _notify(ConnectionStatus(
                state=ConnectionState.ERROR,
                profile=profile,
                error_message=str(exc),
            ))
            return False

    def disconnect(self) -> bool:
        """Disconnect via ``snxctl disconnect``.

        Returns:
            ``True`` if the command succeeded (or was not needed).
        """
        snxctl = shutil.which("snxctl")
        if not snxctl:
            logger.error("snxctl not found in PATH — cannot disconnect.")
            with self._lock:
                self._status = ConnectionStatus(
                    state=ConnectionState.ERROR,
                    error_message="snxctl not found in PATH.",
                )
            return False

        try:
            result = subprocess.run(
                [snxctl, "disconnect"],
                capture_output=True, text=True, timeout=15,
            )
            logger.debug(
                "snxctl disconnect: rc=%d stdout=%r stderr=%r",
                result.returncode, result.stdout, result.stderr,
            )
        except Exception as exc:
            logger.exception("snxctl disconnect failed: %s", exc)
            with self._lock:
                self._status = ConnectionStatus(
                    state=ConnectionState.ERROR,
                    error_message=f"snxctl disconnect failed: {exc}",
                )
            return False

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "snxctl disconnect failed").strip()
            logger.warning("snxctl disconnect exited with %d: %s", result.returncode, err)
            with self._lock:
                self._status = ConnectionStatus(
                    state=ConnectionState.ERROR,
                    error_message=err,
                )
            return False

        with self._lock:
            self._status = ConnectionStatus(state=ConnectionState.DISCONNECTED)
        return True

    def get_status(self) -> ConnectionStatus:
        """Probe snxctl for the current state.

        Falls back to the cached value if snxctl is unavailable or times out.
        """
        snxctl = shutil.which("snxctl")
        if not snxctl:
            with self._lock:
                return self._status
        try:
            result = subprocess.run(
                [snxctl, "status"],
                capture_output=True, text=True, timeout=5,
            )
            return self._parse_status(result.stdout + result.stderr)
        except Exception:
            logger.debug("snxctl status probe failed", exc_info=True)
            with self._lock:
                return self._status

    def get_cached_status(self) -> Optional[ConnectionStatus]:
        """Return the last cached :class:`ConnectionStatus` without probing."""
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
        """Core connection logic — called from :meth:`connect` in a thread."""
        # 1. Verify snxctl is available.
        snxctl = shutil.which("snxctl")
        if not snxctl:
            raise RuntimeError(
                "snxctl not found in PATH. "
                "Install snx-rs: https://github.com/ancwrd1/snx-rs"
            )

        # 2. Ensure snx-rs daemon is running.
        if not self._ensure_daemon():
            raise RuntimeError(
                "Failed to start snx-rs daemon. "
                "Check that snx-rs is installed and the snx-rs.service is enabled."
            )

        # 3. Obtain MFA code if two_factor_callback is configured.
        mfa_code: Optional[str] = None
        if two_factor_callback is not None:
            mfa_code = two_factor_callback("Enter authentication code:")
            if mfa_code is None:
                # User cancelled the MFA dialog.
                raise RuntimeError("Authentication cancelled by user.")

        # 4. Write config with password (mfa_code also written as a hint for
        #    servers that support it via config; will be re-injected via PTY too).
        self._write_config(profile, password, mfa_code)

        try:
            # 5. Run snxctl connect with a PTY so the daemon can prompt
            #    interactively when needed.  If a MFA prompt appears, *mfa_code*
            #    is injected automatically.
            self._snxctl_connect(snxctl, mfa_code)
        finally:
            # Security cleanup: remove password from config.
            try:
                self._write_config(profile)
            except Exception:
                pass

        # 6. Poll snxctl status until Connected or timeout.
        deadline = time.monotonic() + _CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(_POLL_INTERVAL)
            status = self.get_status()
            if status.state == ConnectionState.CONNECTED:
                status.profile = profile
                notify(status)
                return True
            if status.state == ConnectionState.ERROR:
                raise RuntimeError(status.error_message or "snx-rs reported an error.")

        raise RuntimeError(
            f"Connection timed out: snx-rs did not reach Connected state "
            f"within {_CONNECT_TIMEOUT} seconds."
        )

    def _write_config(
        self,
        profile: Profile,
        password: Optional[str] = None,
        mfa_code: Optional[str] = None,
    ) -> None:
        """Write ``~/.config/snx-rs/snx-rs.conf`` for *profile*.

        When *password* is provided it is included (base64-encoded) so the
        daemon can authenticate without interactive input.  After a successful
        connection :meth:`_do_connect` calls this method again WITHOUT a
        password to remove credentials from disk.
        """
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        config_text = self._build_config(profile, password, mfa_code)
        # Use os.open with mode 0o600 so the file is created with owner-only
        # permissions from the start — avoids the TOCTOU window between
        # write_text() and chmod() where the password could be world-readable.
        fd = os.open(str(_CONFIG_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(config_text)
        logger.debug("Wrote snx-rs config to %s", _CONFIG_PATH)

    def _build_config(
        self,
        profile: Profile,
        password: Optional[str] = None,
        mfa_code: Optional[str] = None,
    ) -> str:
        """Return the config file content for *profile* (also used by tests)."""
        lines: list[str] = [
            f"server-name = {profile.server}",
            f"user-name = {profile.username}",
        ]
        if profile.login_type:
            lines.append(f"login-type = {profile.login_type}")

        tunnel_val = "ipsec" if profile.tunnel_type == TunnelType.IPSEC else "ssl"
        lines.append(f"tunnel-type = {tunnel_val}")

        transport = profile.transport_type or "auto"
        lines.append(f"transport-type = {transport}")

        lines.append(f"ignore-server-cert = {'true' if profile.ignore_server_cert else 'false'}")

        if password:
            encoded = base64.b64encode(password.encode()).decode()
            lines.append(f"password = {encoded}")

        if mfa_code:
            lines.append(f"mfa-code = {mfa_code}")

        # Prevent snx-rs from interacting with the OS keychain; snxui manages
        # credentials itself via its own keyring (credential_store.py).
        lines.append("no-keychain = true")

        return "\n".join(lines) + "\n"

    def _snxctl_connect(self, snxctl: str, mfa_code: Optional[str] = None) -> None:
        """Run ``snxctl connect`` with a PTY, injecting *mfa_code* if prompted.

        The snx-rs daemon in command mode reads user input through the TTY of
        the ``snxctl`` process.  Running snxctl without a TTY (plain
        ``subprocess.run``) causes the error "No attached TTY to get user
        input" when RADIUS multi-factor authentication is required.

        This method spawns snxctl via :mod:`pexpect` to provide a PTY, then
        monitors the output for an authentication prompt.  If one is detected,
        *mfa_code* is injected automatically.

        Args:
            snxctl: Absolute path to the ``snxctl`` binary.
            mfa_code: One-time password to inject if the daemon prompts for it.

        Raises:
            RuntimeError: If the connection fails or times out.
        """
        import pexpect  # imported lazily — not needed for disconnect/status

        logger.debug("snxctl connect: spawning with PTY (mfa_code provided=%s)", bool(mfa_code))
        child = pexpect.spawn(snxctl, ["connect"], encoding="utf-8", timeout=_CONNECT_TIMEOUT)
        _mfa_remaining = mfa_code  # consume at most once

        try:
            while True:
                idx = child.expect(
                    [
                        # Prompt patterns from snx-rs / RADIUS server messages.
                        # Require a trailing `:` or `?` so we match actual input prompts
                        # (e.g. "Password:") but NOT descriptive text ("provide password to authenticate").
                        r"(?i)\b(password|code|pin|otp|token|one.time|passcode|"
                        r"verification|enter|factor)\s*[:\?]",
                        pexpect.EOF,
                        pexpect.TIMEOUT,
                    ],
                    timeout=_CONNECT_TIMEOUT,
                )
                if idx == 0:
                    prompt_text = (child.before or "") + (child.match.group(0) if child.match else "")
                    logger.debug("snxctl connect: MFA prompt — %r", prompt_text.strip()[-120:])
                    if _mfa_remaining:
                        child.sendline(_mfa_remaining)
                        _mfa_remaining = None
                    else:
                        raise RuntimeError(
                            "snx-rs daemon requested authentication input but "
                            "no MFA code is available.  Configure two_factor_method."
                        )
                elif idx == 1:
                    # Process exited — check return code below.
                    break
                else:
                    raise RuntimeError(
                        f"snxctl connect timed out after {_CONNECT_TIMEOUT} seconds."
                    )
        except pexpect.EOF:
            pass
        except pexpect.TIMEOUT:
            raise RuntimeError(f"snxctl connect timed out after {_CONNECT_TIMEOUT} seconds.")
        finally:
            if child.isalive():
                child.close()

        output = (child.before or "").strip()
        rc = child.exitstatus
        logger.debug("snxctl connect: rc=%r output=%r", rc, output[:500] if output else "")

        if rc != 0:
            err = output or "snxctl connect failed"
            raise RuntimeError(err)

    def _ensure_daemon(self) -> bool:
        """Ensure the snx-rs daemon (``snx-rs -m command``) is running.

        Checks whether the daemon is responsive via ``snxctl status``.  If not,
        attempts to start it via ``systemctl start snx-rs`` (packaged install)
        or by launching ``snx-rs -m command`` directly as a background process.

        Returns:
            ``True`` when the daemon is ready (either already running or
            successfully launched).
        """
        snxctl = shutil.which("snxctl")
        if not snxctl:
            logger.error("snxctl not found in PATH")
            return False

        # Quick status check — if it responds, the daemon is already up.
        try:
            result = subprocess.run(
                [snxctl, "status"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                logger.debug("snx-rs daemon is already running.")
                return True
        except Exception:
            pass

        # Daemon not responsive — try to start via systemd (packaged installs).
        logger.info("snx-rs daemon not running, attempting to start via systemctl...")
        try:
            subprocess.run(
                ["systemctl", "start", "snx-rs"],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            pass

        # Fall back to launching snx-rs directly as a background process.
        snx_rs = shutil.which("snx-rs")
        if not snx_rs:
            logger.error("snx-rs not found in PATH")
            return False

        try:
            subprocess.Popen(
                [snx_rs, "-m", "command"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.exception("Failed to start snx-rs daemon: %s", exc)
            return False

        # Give the daemon a moment to initialise.
        time.sleep(_DAEMON_START_DELAY)
        return True

    def _parse_status(self, output: str) -> ConnectionStatus:
        """Parse ``snxctl status`` output into a :class:`ConnectionStatus`.

        snx-rs status output typically looks like::

            Status: Connected
            IP address: 10.200.0.5
            Interface: tunsnx0

        or::

            Status: Disconnected
        """
        output_lower = output.lower()

        # Extract tunnel IP if present.
        ip_address: Optional[str] = None
        ip_match = re.search(
            r'(?:ip\s+address|ip|office\s+mode\s+ip)\s*[:\=]\s*'
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            output_lower,
        )
        if ip_match:
            ip_address = ip_match.group(1)

        # Extract interface name if present (e.g. "Interface: tunsnx0").
        # Use original output (not lowercased) to preserve case of iface name.
        interface: Optional[str] = None
        iface_match = re.search(r'interface\s*[:\=]\s*(\S+)', output, re.IGNORECASE)
        if iface_match:
            interface = iface_match.group(1).strip()

        # Determine state from keywords — order matters: check "disconnected"
        # before "connected" to avoid false positives in "not connected" messages.
        if "disconnected" in output_lower or "not connected" in output_lower:
            return ConnectionStatus(state=ConnectionState.DISCONNECTED)
        if "connected" in output_lower:
            return ConnectionStatus(
                state=ConnectionState.CONNECTED,
                ip_address=ip_address,
                interface=interface,
            )
        if "connecting" in output_lower:
            return ConnectionStatus(state=ConnectionState.CONNECTING)
        if "error" in output_lower or "failed" in output_lower:
            return ConnectionStatus(
                state=ConnectionState.ERROR,
                error_message=output.strip(),
            )
        # Unknown / empty output — treat as disconnected.
        return ConnectionStatus(state=ConnectionState.DISCONNECTED)
