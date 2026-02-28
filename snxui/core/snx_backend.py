"""SNX backend — pexpect-based TTY automation for Check Point SNX VPN.

SNX requires an interactive TTY to accept the password; it cannot receive
credentials via stdin pipe or environment variables.  :mod:`pexpect` spawns
the binary in a pseudo-TTY (PTY) which satisfies this requirement.

Typical SNX interaction flow::

    $ snx -s vpn.example.com -u alice
    Check Point SNX ...
    Password: ****
    SNX - Connected.
    Session parameters:
        Office Mode IP      : 10.200.0.5
        ...

The backend spawns this process, feeds the password at the prompt, then
waits for one of several known success/failure patterns.  A background
monitor thread periodically checks the ``tunsnx`` interface to detect
unexpected disconnections.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

try:
    import pexpect
except ImportError:
    pexpect = None  # type: ignore[assignment]
    logger.warning(
        "pexpect is not installed. SNX automation will not be available. "
        "Install with: pip install pexpect"
    )

from .types import ConnectionState, ConnectionStatus, Profile

# ---------------------------------------------------------------------------
# Regex patterns for SNX output
# ---------------------------------------------------------------------------

# Password prompt
_RE_PASSWORD = re.compile(r"[Pp]assword\s*:|Enter\s+password\s*:", re.IGNORECASE)

# Successful connection
_RE_CONNECTED = re.compile(
    r"SNX\s*-\s*Connected|Tunnel\s+is\s+up|Connection\s+established|"
    r"Session\s+parameters",
    re.IGNORECASE,
)

# Authentication / connection failure
_RE_AUTH_FAILED = re.compile(
    r"Authentication\s+failed|Invalid\s+password|Access\s+denied|"
    r"Login\s+failed",
    re.IGNORECASE,
)
_RE_CONN_FAILED = re.compile(
    r"Connection\s+failed|Cannot\s+connect|No\s+route\s+to\s+host|"
    r"SNX\s+failed",
    re.IGNORECASE,
)

# Already running / connected
_RE_ALREADY = re.compile(
    r"already\s+connected|SNX\s+is\s+already\s+running",
    re.IGNORECASE,
)

# Office Mode IP line (captured after connect)
_RE_OFFICE_IP = re.compile(r"Office\s+Mode\s+IP\s*:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)

# Disconnection confirmation
_RE_DISCONNECTED = re.compile(
    r"SNX\s+disconnected|Disconnected\s+successfully|Session\s+terminated",
    re.IGNORECASE,
)

# Candidate SNX binary locations (in order of preference)
_SNX_SEARCH_PATHS: list[Path] = [
    Path("/usr/bin/snx"),
    Path("/usr/local/bin/snx"),
    Path.home() / "Downloads" / "snx",
    Path.home() / "snx",
]

# Timeout constants (seconds)
_CONNECT_TIMEOUT = 60
_PASSWORD_TIMEOUT = 30
_DISCONNECT_TIMEOUT = 15
_MONITOR_INTERVAL = 5


# ---------------------------------------------------------------------------
# SNXBackend
# ---------------------------------------------------------------------------


class SNXBackend:
    """High-level interface for establishing and monitoring SNX VPN connections.

    Only one connection is supported at a time per instance.  The backend is
    intentionally synchronous (no async/await) for Phase 1; UI callbacks are
    dispatched from a background thread.

    Example::

        backend = SNXBackend()
        ok = backend.connect(profile, password, callback=on_status_change)
        # ...
        backend.disconnect()
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status = ConnectionStatus()
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop = threading.Event()
        self._snx_binary: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(
        self,
        profile: Profile,
        password: str,
        status_callback: Optional[Callable[[ConnectionStatus], None]] = None,
    ) -> bool:
        """Connect to the VPN using *profile* and *password*.

        Spawns SNX in a PTY, waits for the password prompt, sends the
        password, then waits for a success or failure indicator.

        Args:
            profile: The :class:`~snxui.core.types.Profile` to use.
            password: Plaintext password (handled in PTY, never logged).
            status_callback: Optional callable invoked whenever the
                :class:`~snxui.core.types.ConnectionStatus` changes.  Called
                from the monitor thread — ensure it is thread-safe.

        Returns:
            ``True`` on successful connection, ``False`` otherwise.

        Raises:
            FileNotFoundError: If the SNX binary cannot be located.
            RuntimeError: If pexpect is not installed.
        """
        if pexpect is None:
            raise RuntimeError(
                "pexpect is required for SNX automation. "
                "Install it with: pip install pexpect"
            )

        binary = self._find_snx_binary()

        with self._lock:
            self._update_status(
                ConnectionState.CONNECTING,
                profile=profile,
                callback=status_callback,
            )

        args = self._build_args(profile)
        cmd = f"{binary} {' '.join(args)}"
        logger.info("Launching SNX: %s", cmd)

        child = None  # Initialise before try so except can safely close it.
        try:
            child = pexpect.spawn(
                binary,
                args,
                encoding="utf-8",
                timeout=_CONNECT_TIMEOUT,
                echo=False,
            )

            # Wait for the password prompt.
            # Pass compiled regex objects directly so that pexpect uses them
            # as-is (preserving re.IGNORECASE).  Passing .pattern strings
            # causes pexpect to recompile with re.DOTALL only, silently
            # dropping the IGNORECASE flag — SNX output like
            # "authentication failed" (all-lowercase) would then go
            # unmatched and be treated as an unexpected EOF/TIMEOUT.
            idx = child.expect(
                [
                    _RE_PASSWORD,
                    _RE_ALREADY,
                    _RE_CONN_FAILED,
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ],
                timeout=_PASSWORD_TIMEOUT,
            )

            if idx == 1:
                # Already connected — treat as success.
                logger.info("SNX reports already connected.")
                status = self.get_status()
                with self._lock:
                    self._update_status(
                        ConnectionState.CONNECTED,
                        profile=profile,
                        ip_address=status.ip_address,
                        interface=status.interface,
                        connected_at=time.time(),
                        callback=status_callback,
                    )
                child.close()
                return True

            if idx in (2, 3, 4):
                output = getattr(child, "before", "") or ""
                logger.error("SNX connection failed before password prompt. Output: %r", output)
                with self._lock:
                    self._update_status(
                        ConnectionState.ERROR,
                        profile=profile,
                        error_message="Connection failed before password prompt.",
                        callback=status_callback,
                    )
                child.close()
                return False

            # idx == 0: password prompt received — send password.
            logger.debug("Password prompt received, sending credentials.")
            child.sendline(password)

            # Wait for success or failure.
            idx2 = child.expect(
                [
                    _RE_CONNECTED,
                    _RE_AUTH_FAILED,
                    _RE_CONN_FAILED,
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ],
                timeout=_CONNECT_TIMEOUT,
            )

            full_output = (child.before or "") + (child.after or "")

            if idx2 == 0:
                # Success — try to parse the Office Mode IP.
                ip_address = self._parse_office_ip(full_output)
                logger.info("SNX connected. Office IP: %s", ip_address or "unknown")
                with self._lock:
                    self._update_status(
                        ConnectionState.CONNECTED,
                        profile=profile,
                        ip_address=ip_address,
                        interface="tunsnx",
                        connected_at=time.time(),
                        callback=status_callback,
                    )
                child.close()
                self._start_monitor(profile, status_callback)
                return True

            # Failure paths
            error_map = {
                1: "Authentication failed — check username and password.",
                2: "Connection failed — check server address and network.",
                3: "Unexpected SNX process termination.",
                4: "SNX timed out waiting for connection confirmation.",
            }
            error_msg = error_map.get(idx2, "Unknown SNX error.")
            logger.error("SNX connect failed (idx=%d): %s. Output: %r", idx2, error_msg, full_output)
            with self._lock:
                self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message=error_msg,
                    callback=status_callback,
                )
            child.close()
            return False

        except pexpect.exceptions.ExceptionPexpect as exc:
            logger.exception("pexpect error during connect: %s", exc)
            # Close the PTY child if it was successfully spawned before the
            # exception.  Without this, the snx process and its PTY file
            # descriptor would leak on every pexpect error.
            if child is not None:
                try:
                    child.close()
                except Exception:
                    pass
            with self._lock:
                self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message=f"pexpect error: {exc}",
                    callback=status_callback,
                )
            return False

    def disconnect(self) -> bool:
        """Disconnect the active SNX VPN session.

        Runs ``snx -d`` and waits for confirmation.

        Returns:
            ``True`` if disconnection was confirmed, ``False`` otherwise.

        Raises:
            FileNotFoundError: If the SNX binary cannot be located.
            RuntimeError: If pexpect is not installed.
        """
        if pexpect is None:
            raise RuntimeError("pexpect is required. Install with: pip install pexpect")

        binary = self._find_snx_binary()
        logger.info("Disconnecting SNX via: %s -d", binary)

        self._stop_monitor()

        child = None  # Initialise before try so except can safely close it.
        try:
            child = pexpect.spawn(
                binary,
                ["-d"],
                encoding="utf-8",
                timeout=_DISCONNECT_TIMEOUT,
                echo=False,
            )
            idx = child.expect(
                [
                    _RE_DISCONNECTED,
                    pexpect.EOF,
                    pexpect.TIMEOUT,
                ],
                timeout=_DISCONNECT_TIMEOUT,
            )
            child.close()

            if idx == 0:
                logger.info("SNX disconnected successfully.")
                with self._lock:
                    self._update_status(ConnectionState.DISCONNECTED)
                return True

            # EOF / TIMEOUT — check if tunsnx is actually gone.
            if not self._tunsnx_exists():
                logger.info("tunsnx gone after snx -d (no explicit confirmation).")
                with self._lock:
                    self._update_status(ConnectionState.DISCONNECTED)
                return True

            logger.warning("SNX disconnect command returned unexpectedly (idx=%d).", idx)
            with self._lock:
                self._update_status(
                    ConnectionState.ERROR,
                    error_message="Disconnect may not have succeeded — check SNX status.",
                )
            return False

        except pexpect.exceptions.ExceptionPexpect as exc:
            logger.exception("pexpect error during disconnect: %s", exc)
            if child is not None:
                try:
                    child.close()
                except Exception:
                    pass
            with self._lock:
                self._update_status(
                    ConnectionState.ERROR,
                    error_message=f"Disconnect error: {exc}",
                )
            return False

    def get_status(self) -> ConnectionStatus:
        """Return a live snapshot of the current connection status.

        Checks the ``tunsnx`` network interface to determine whether a tunnel
        is actually active, independent of the internal state machine.

        Returns:
            Current :class:`~snxui.core.types.ConnectionStatus`.
        """
        # Perform I/O outside the lock so blocking subprocess calls do not
        # hold _lock and stall the monitor or connect threads.
        exists = self._tunsnx_exists()
        ip = self._get_tunsnx_ip() if exists else None

        with self._lock:
            # Update state and build the snapshot in a single critical section.
            # Previously three separate "with self._lock:" blocks created TOCTOU
            # windows where another thread (e.g. disconnect()) could modify
            # self._status between the state-update block and the snapshot block,
            # or where a tunsnx check outside the lock could race with a
            # concurrent disconnect() that already set state to DISCONNECTED —
            # causing get_status() to incorrectly flip state back to CONNECTED.
            if exists:
                if self._status.state not in (
                    ConnectionState.CONNECTED,
                    ConnectionState.CONNECTING,
                ):
                    # Tunnel exists but we didn't track it — update state.
                    self._status = ConnectionStatus(
                        state=ConnectionState.CONNECTED,
                        ip_address=ip,
                        interface="tunsnx",
                    )
                else:
                    self._status.ip_address = ip
            else:
                if self._status.state == ConnectionState.CONNECTED:
                    # Tunnel disappeared unexpectedly.
                    self._status = ConnectionStatus(state=ConnectionState.DISCONNECTED)

            # Return a shallow copy to prevent external mutation.
            return ConnectionStatus(
                state=self._status.state,
                profile=self._status.profile,
                ip_address=self._status.ip_address,
                interface=self._status.interface,
                connected_at=self._status.connected_at,
                error_message=self._status.error_message,
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _find_snx_binary(self) -> str:
        """Locate the SNX binary, raising :class:`FileNotFoundError` if absent.

        Searches :data:`_SNX_SEARCH_PATHS` as well as the system ``PATH``.

        Returns:
            Absolute path string to the SNX binary.

        Raises:
            FileNotFoundError: With a helpful installation message.
        """
        if self._snx_binary:
            return self._snx_binary

        # Check known locations first.
        for candidate in _SNX_SEARCH_PATHS:
            if candidate.exists() and candidate.is_file():
                self._snx_binary = str(candidate)
                logger.debug("Found SNX binary at %s", self._snx_binary)
                return self._snx_binary

        # Fallback: PATH lookup.
        found = shutil.which("snx")
        if found:
            self._snx_binary = found
            logger.debug("Found SNX binary in PATH: %s", self._snx_binary)
            return self._snx_binary

        raise FileNotFoundError(
            "SNX binary not found. Please install the Check Point SNX client.\n"
            "Download from your VPN portal and place it at /usr/bin/snx or "
            "/usr/local/bin/snx, then run: chmod +x /usr/bin/snx"
        )

    def _build_args(self, profile: Profile) -> list[str]:
        """Build the CLI argument list for the SNX connect command.

        Args:
            profile: Profile whose parameters to translate.

        Returns:
            List of argument strings (without the binary name).
        """
        args: list[str] = [
            "-s", profile.server,
            "-u", profile.username,
        ]
        if profile.ssl_port != 443:
            args += ["-p", str(profile.ssl_port)]
        if profile.ca_list:
            args += ["-l", profile.ca_list]
        if profile.certificate:
            args += ["-c", profile.certificate]
        if not profile.reauth:
            args.append("-n")
        if profile.cipher:
            args += ["-Z", profile.cipher]
        return args

    @staticmethod
    def _parse_office_ip(text: str) -> Optional[str]:
        """Extract the Office Mode IP address from SNX output.

        Args:
            text: Raw output captured from the SNX process.

        Returns:
            IP address string, or ``None`` if not found.
        """
        match = _RE_OFFICE_IP.search(text)
        if match:
            return match.group(1)
        return None

    # ------------------------------------------------------------------
    # tunsnx interface helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tunsnx_exists() -> bool:
        """Return ``True`` if the ``tunsnx`` network interface is present."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", "tunsnx"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    @staticmethod
    def _get_tunsnx_ip() -> Optional[str]:
        """Return the IP address assigned to ``tunsnx``, or ``None``."""
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show", "tunsnx"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
            return match.group(1) if match else None
        except (subprocess.SubprocessError, FileNotFoundError):
            return None

    # ------------------------------------------------------------------
    # Connection monitor
    # ------------------------------------------------------------------

    def _start_monitor(
        self,
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> None:
        """Start the background monitor thread."""
        self._stop_monitor()
        self._monitor_stop.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_connection,
            args=(profile, callback),
            name="snxui-monitor",
            daemon=True,
        )
        self._monitor_thread.start()
        logger.debug("Monitor thread started.")

    def _stop_monitor(self) -> None:
        """Signal and join the monitor thread if it is running."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_stop.set()
            self._monitor_thread.join(timeout=_MONITOR_INTERVAL + 2)
            logger.debug("Monitor thread stopped.")
        self._monitor_thread = None

    def _monitor_connection(
        self,
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> None:
        """Periodically check whether the ``tunsnx`` interface is still up.

        Runs until :attr:`_monitor_stop` is set or the tunnel disappears.
        When the tunnel goes away unexpectedly, the status transitions to
        DISCONNECTED and the callback is invoked.

        Args:
            profile: The profile that was used to connect (for the callback).
            callback: Optional status-change callback.
        """
        logger.debug("Monitor loop started (interval=%ds).", _MONITOR_INTERVAL)
        while not self._monitor_stop.wait(timeout=_MONITOR_INTERVAL):
            if not self._tunsnx_exists():
                logger.warning("tunsnx interface disappeared — connection lost.")
                with self._lock:
                    self._update_status(
                        ConnectionState.DISCONNECTED,
                        profile=profile,
                        error_message="VPN connection dropped unexpectedly.",
                        callback=callback,
                    )
                break
            # Refresh IP (may change on rekey).
            ip = self._get_tunsnx_ip()
            with self._lock:
                if self._status.ip_address != ip:
                    logger.debug("Tunnel IP changed to %s", ip)
                    self._status.ip_address = ip
                    if callback:
                        # Build snapshot inside the lock without calling
                        # get_status(), which would try to re-acquire self._lock
                        # (threading.Lock is not reentrant → deadlock).
                        snapshot = ConnectionStatus(
                            state=self._status.state,
                            profile=self._status.profile,
                            ip_address=self._status.ip_address,
                            interface=self._status.interface,
                            connected_at=self._status.connected_at,
                            error_message=self._status.error_message,
                        )
                        try:
                            callback(snapshot)
                        except Exception:  # noqa: BLE001
                            logger.exception("Exception in status callback.")
        logger.debug("Monitor loop exited.")

    # ------------------------------------------------------------------
    # Internal status helpers
    # ------------------------------------------------------------------

    def _update_status(
        self,
        state: ConnectionState,
        *,
        profile: Optional[Profile] = None,
        ip_address: Optional[str] = None,
        interface: Optional[str] = None,
        connected_at: Optional[float] = None,
        error_message: Optional[str] = None,
        callback: Optional[Callable[[ConnectionStatus], None]] = None,
    ) -> None:
        """Update internal status and optionally invoke the callback.

        Must be called with :attr:`_lock` held.
        """
        self._status = ConnectionStatus(
            state=state,
            profile=profile or self._status.profile,
            ip_address=ip_address,
            interface=interface,
            connected_at=connected_at,
            error_message=error_message,
        )
        if callback:
            snapshot = ConnectionStatus(
                state=self._status.state,
                profile=self._status.profile,
                ip_address=self._status.ip_address,
                interface=self._status.interface,
                connected_at=self._status.connected_at,
                error_message=self._status.error_message,
            )
            try:
                callback(snapshot)
            except Exception:  # noqa: BLE001
                logger.exception("Exception in status callback.")
