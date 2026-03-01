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

from .types import ConnectionState, ConnectionStatus, Profile, TwoFactorCallback

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

# --- 2FA prompts (all use re.IGNORECASE only, no MULTILINE) ---

_RE_2FA_RSA = re.compile(
    r"Enter\s+SecurID\s+PASSCODE\s*:|SecurID\s+passcode\s*:|PASSCODE\s*:",
    re.IGNORECASE,
)
_RE_2FA_RADIUS = re.compile(
    r"Enter\s+RADIUS\s+(?:token|passcode)\s*:|RADIUS\s+(?:token|passcode)\s*:"
    r"|\bToken\s*:",
    re.IGNORECASE,
)
_RE_2FA_CHALLENGE = re.compile(
    r"Challenge\s*:\s*\S+|Your\s+challenge\s+is\s*:\s*\S+|Enter\s+response\s*:",
    re.IGNORECASE,
)
_RE_2FA_GENERIC = re.compile(
    r"Enter\s+one.time\s+(?:password|code)\s*:|Verification\s+code\s*:|"
    r"\bOTP\s*:|Two.factor\s+code\s*:",
    re.IGNORECASE,
)

# Объединённый паттерн для expect() списка
_RE_2FA_ANY = re.compile(
    r"Enter\s+SecurID\s+PASSCODE\s*:|SecurID\s+passcode\s*:|PASSCODE\s*:|"
    r"Enter\s+RADIUS\s+(?:token|passcode)\s*:|RADIUS\s+(?:token|passcode)\s*:|"
    r"\bToken\s*:|"
    r"Challenge\s*:\s*\S+|Enter\s+response\s*:|"
    r"Enter\s+one.time\s+(?:password|code)\s*:|Verification\s+code\s*:|"
    r"\bOTP\s*:|Two.factor\s+code\s*:",
    re.IGNORECASE,
)

# Lines to skip when extracting meaningful SNX error output.
# Covers: banners, copyright, empty lines, usage: header,
# and CLI option lines like "-s gateway   specify gateway".
_RE_SNX_BANNER_SKIP = re.compile(
    r"^(Check\s+Point|SNX\s+-\s+(Network\s+Extension|Connected|Version)"
    r"|Logging\s+|Copyright|usage\s*:|-[a-z]\b|snx\s+-\w|snx\s{2,}|\s*$)",
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
        two_factor_callback: Optional[TwoFactorCallback] = None,
    ) -> bool:
        """Connect to the VPN using *profile* and *password*.

        Spawns SNX in a PTY, waits for the password prompt, sends the
        password, then waits for a success or failure indicator.

        Args:
            profile: The :class:`~snxui.core.types.Profile` to use.
            password: Plaintext password (handled in PTY, never logged).
            status_callback: Called from the monitor thread on each status
                change — must be thread-safe.
            two_factor_callback: Called when SNX requires a 2FA code;
                return the code string, or ``None`` to abort.

        Returns:
            ``True`` on successful connection, ``False`` otherwise.
        """
        if pexpect is None:
            raise RuntimeError(
                "pexpect is required for SNX automation. "
                "Install it with: pip install pexpect"
            )

        binary = self._find_snx_binary()
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.CONNECTING, profile=profile,
            )
        self._invoke_callback(status_callback, snapshot)

        args = self._build_args(profile)
        logger.info("Launching SNX: %s %s", binary, " ".join(args))

        child = None  # Initialise before try so except can safely close it.
        try:
            child = pexpect.spawn(
                binary, args, encoding="utf-8", timeout=_CONNECT_TIMEOUT, echo=False,
            )
            return self._run_connect_session(
                child, password, profile, status_callback, two_factor_callback,
            )
        except pexpect.exceptions.ExceptionPexpect as exc:
            return self._handle_pexpect_error(exc, child, profile, status_callback)

    def _handle_pexpect_error(
        self,
        exc: "pexpect.exceptions.ExceptionPexpect",
        child: Optional["pexpect.spawn"],
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> bool:
        """Clean up PTY and record error state after a pexpect exception."""
        logger.exception("pexpect error during connect: %s", exc)
        # Close the PTY child if it was successfully spawned before the
        # exception.  Without this, the snx process and its PTY file
        # descriptor would leak on every pexpect error.
        if child is not None:
            try:
                child.close()
            except Exception:
                logger.debug("PTY close failed during error cleanup.", exc_info=True)
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.ERROR,
                profile=profile,
                error_message=f"pexpect error: {exc}",
            )
        self._invoke_callback(callback, snapshot)
        return False

    def _run_connect_session(
        self,
        child: "pexpect.spawn",
        password: str,
        profile: Profile,
        status_callback: Optional[Callable[[ConnectionStatus], None]],
        two_factor_callback: Optional[TwoFactorCallback],
    ) -> bool:
        """Execute the PTY interaction sequence after spawning SNX.

        Must be called from within the ``try`` block in :meth:`connect`
        so that pexpect exceptions propagate to the outer handler.
        """
        early = self._await_password_prompt(child, profile, status_callback)
        if early is not None:
            return early
        logger.debug("Password prompt received, sending credentials.")
        child.sendline(password)
        return self._handle_post_password(child, profile, status_callback, two_factor_callback)

    def _await_password_prompt(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> Optional[bool]:
        """Wait for SNX to show the password prompt.

        Pass compiled regex objects directly so that pexpect uses them
        as-is (preserving re.IGNORECASE).  Passing .pattern strings
        causes pexpect to recompile with re.DOTALL only, silently
        dropping the IGNORECASE flag.

        Returns:
            ``None`` if the password prompt was received (caller should
            send the password and continue).  ``True`` if SNX reported
            already-connected (caller should return ``True``).  ``False``
            if connection failed before the prompt (caller should return
            ``False``).
        """
        idx = child.expect(
            [_RE_PASSWORD, _RE_ALREADY, _RE_CONN_FAILED, pexpect.EOF, pexpect.TIMEOUT],
            timeout=_PASSWORD_TIMEOUT,
        )

        if idx == 1:
            return self._handle_already_connected(child, profile, callback)
        if idx in (2, 3, 4):
            return self._handle_pre_prompt_failure(child, profile, callback, idx)
        # idx == 0: password prompt received.
        return None

    def _handle_already_connected(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> bool:
        """Handle SNX reporting already-connected state."""
        logger.info("SNX reports already connected.")
        status = self.get_status()
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.CONNECTED,
                profile=profile,
                ip_address=status.ip_address,
                interface=status.interface,
                connected_at=time.time(),
            )
        child.close()
        self._invoke_callback(callback, snapshot)
        return True

    def _handle_pre_prompt_failure(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
        idx: int = 2,
    ) -> bool:
        """Handle SNX failure before reaching the password prompt.

        Args:
            idx: pexpect match index — 2=conn-failed regex, 3=EOF, 4=TIMEOUT.
        """
        before = getattr(child, "before", "") or ""
        after = child.after if isinstance(child.after, str) else ""
        raw_output = (before + after).strip()
        logger.error("SNX pre-prompt failure (idx=%d). Output: %r", idx, raw_output)

        # Build a user-visible message: base cause + first meaningful SNX line.
        if idx == 4:
            base = "Connection timed out — server unreachable or port blocked."
        elif idx == 3:
            base = "SNX exited unexpectedly — check server address."
        else:
            base = "Connection failed — check server address and network."

        detail = self._extract_snx_error(raw_output)

        # Lines 0-1: shown in UI.  Lines 2+: included in clipboard only.
        msg_parts = [base]
        if detail:
            msg_parts.append(detail)
        try:
            binary = self._find_snx_binary()
            cmd_args = self._build_args(profile)
            msg_parts.append(f"Command: {binary} {' '.join(cmd_args)}")
        except Exception:
            pass
        if raw_output:
            msg_parts.append("---")
            msg_parts.append(raw_output[:800])
        error_message = "\n".join(msg_parts)

        with self._lock:
            snapshot = self._update_status(
                ConnectionState.ERROR,
                profile=profile,
                error_message=error_message,
            )
        child.close()
        self._invoke_callback(callback, snapshot)
        return False

    @staticmethod
    def _extract_snx_error(output: str) -> str:
        """Return the most relevant error line from raw SNX output.

        Returns empty string when the output is a help/usage page (SNX exited
        because of invalid arguments — the base error message is sufficient).
        Otherwise scans lines from the end, skipping banners and empty lines,
        and returns the first non-trivial line (up to 120 chars).
        """
        if re.search(r"usage\s*:\s*snx", output, re.IGNORECASE):
            return ""
        for line in reversed(output.splitlines()):
            line = line.strip()
            if line and not _RE_SNX_BANNER_SKIP.match(line):
                return line[:120]
        return ""

    def _finish_connected(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
        full_output: str,
    ) -> bool:
        """Finalize a successful connection: update status, start monitor, close PTY."""
        ip_address = self._parse_office_ip(full_output)
        logger.info("SNX connected. Office IP: %s", ip_address or "unknown")
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.CONNECTED,
                profile=profile,
                ip_address=ip_address,
                interface="tunsnx",
                connected_at=time.time(),
            )
        child.close()
        self._invoke_callback(callback, snapshot)
        self._start_monitor(profile, callback)
        return True

    def _handle_post_password(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
        two_factor_callback: Optional[TwoFactorCallback] = None,
    ) -> bool:
        """Wait for connect confirmation after the password was sent.

        Supports an interactive 2FA loop: if SNX presents a 2FA prompt,
        *two_factor_callback* is invoked to obtain the code.  The loop runs
        at most ``_2FA_LOOP_LIMIT`` times.

        Returns:
            ``True`` on successful connection, ``False`` otherwise.
        """
        _2FA_LOOP_LIMIT = 3

        for _round in range(_2FA_LOOP_LIMIT):
            idx = child.expect(
                [
                    _RE_CONNECTED,    # 0
                    _RE_AUTH_FAILED,  # 1
                    _RE_CONN_FAILED,  # 2
                    pexpect.EOF,      # 3
                    pexpect.TIMEOUT,  # 4
                    _RE_2FA_ANY,      # 5
                ],
                timeout=_CONNECT_TIMEOUT,
            )
            full_output = (child.before or "") + (
                child.after if isinstance(child.after, str) else ""
            )

            if idx == 0:
                return self._finish_connected(child, profile, callback, full_output)

            if idx in (1, 2, 3, 4):
                return self._handle_connect_failure(child, profile, callback, idx, full_output)

            # idx == 5: 2FA prompt
            sent = self._handle_2fa_prompt(child, profile, callback, two_factor_callback, full_output)
            if sent is False:
                return False
            # sent is True → code was sent, continue loop

        return self._handle_2fa_limit_exceeded(child, profile, callback)

    def _handle_connect_failure(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
        idx: int,
        full_output: str,
    ) -> bool:
        """Record ERROR state for a non-2FA connect failure."""
        error_map = {
            1: "Authentication failed — check username and password.",
            2: "Connection failed — check server address and network.",
            3: "Unexpected SNX process termination.",
            4: "SNX timed out waiting for connection confirmation.",
        }
        error_msg = error_map.get(idx, "Unknown SNX error.")
        logger.error("SNX connect failed (idx=%d): %s. Output: %r", idx, error_msg, full_output)
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.ERROR, profile=profile, error_message=error_msg,
            )
        child.close()
        self._invoke_callback(callback, snapshot)
        return False

    def _handle_2fa_prompt(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
        two_factor_callback: Optional[TwoFactorCallback],
        full_output: str,
    ) -> bool:
        """Handle a 2FA challenge prompt from SNX.

        Returns:
            ``True`` if the code was sent (loop should continue).
            ``False`` if an error was set and the loop should abort.
        """
        if two_factor_callback is None:
            logger.error("SNX requested 2FA but no two_factor_callback provided.")
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message="VPN requires two-factor authentication. "
                                  "Configure 2FA method in profile settings.",
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        code = two_factor_callback(full_output)  # Блокирует bg thread
        if code is None:
            logger.info("User cancelled 2FA input.")
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message="Two-factor authentication cancelled.",
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        child.sendline(code)
        return True

    def _handle_2fa_limit_exceeded(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> bool:
        """Record ERROR when the 2FA loop limit is exceeded."""
        logger.error("2FA loop limit exceeded.")
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.ERROR,
                profile=profile,
                error_message="Too many 2FA rounds — connection aborted.",
            )
        child.close()
        self._invoke_callback(callback, snapshot)
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

        try:
            idx = self._run_snx_disconnect(binary)
            return self._verify_disconnect_result(idx)
        except pexpect.exceptions.ExceptionPexpect as exc:
            logger.exception("pexpect error during disconnect: %s", exc)
            with self._lock:
                self._update_status(
                    ConnectionState.ERROR,
                    error_message=f"Disconnect error: {exc}",
                )
            return False

    def _run_snx_disconnect(self, binary: str) -> int:
        """Spawn ``snx -d``, wait for the result, and close the PTY.

        The PTY child is always closed in the ``finally`` block — even if
        ``child.expect`` raises a pexpect exception — so the caller never
        needs to manage the child's lifetime.

        Returns:
            The index returned by ``child.expect``:
            0 = disconnect confirmed, 1 = EOF, 2 = TIMEOUT.
        """
        child = pexpect.spawn(
            binary, ["-d"], encoding="utf-8", timeout=_DISCONNECT_TIMEOUT, echo=False,
        )
        try:
            return child.expect(
                [_RE_DISCONNECTED, pexpect.EOF, pexpect.TIMEOUT],
                timeout=_DISCONNECT_TIMEOUT,
            )
        finally:
            try:
                child.close()
            except Exception:
                logger.debug("PTY close failed during disconnect.", exc_info=True)

    def _verify_disconnect_result(self, idx: int) -> bool:
        """Interpret the pexpect index from ``_run_snx_disconnect``.

        Returns:
            ``True`` if the VPN is confirmed disconnected, ``False`` on error.
        """
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
            # Update state and return snapshot in a single critical section.
            # Previously three separate "with self._lock:" blocks created TOCTOU
            # windows where another thread (e.g. disconnect()) could modify
            # self._status between the state-update block and the snapshot block.
            self._reconcile_tunsnx_status(exists, ip)
            return ConnectionStatus(
                state=self._status.state,
                profile=self._status.profile,
                ip_address=self._status.ip_address,
                interface=self._status.interface,
                connected_at=self._status.connected_at,
                error_message=self._status.error_message,
            )

    def _reconcile_tunsnx_status(self, exists: bool, ip: Optional[str]) -> None:
        """Update internal state to match the current tunsnx interface status.

        Must be called with ``self._lock`` held.

        Args:
            exists: Whether the tunsnx interface currently exists.
            ip: IP address of the interface, or None if not present.
        """
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
                # Update the IP without changing other fields.
                # Consistent with _update_status(): always replace the
                # object instead of mutating it in-place.
                self._status = ConnectionStatus(
                    state=self._status.state,
                    profile=self._status.profile,
                    ip_address=ip,
                    interface=self._status.interface,
                    connected_at=self._status.connected_at,
                    error_message=self._status.error_message,
                )
        else:
            if self._status.state == ConnectionState.CONNECTED:
                # Tunnel disappeared unexpectedly.
                self._status = ConnectionStatus(state=ConnectionState.DISCONNECTED)

    def get_cached_status(self) -> ConnectionStatus:
        """Return the cached status snapshot without probing the ``tunsnx`` interface.

        Unlike :meth:`get_status`, this method performs no subprocess calls.
        It is safe to call from a background thread immediately after
        :meth:`disconnect` returns ``False``: at that point the tunnel is still
        up, so :meth:`get_status` would override the ERROR state with CONNECTED.
        Using the cached snapshot preserves the error message set by
        :meth:`disconnect` internally.

        Returns:
            A fresh :class:`~snxui.core.types.ConnectionStatus` copy of the
            current internal state.
        """
        with self._lock:
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
        login = f"{profile.domain}\\{profile.username}" if profile.domain else profile.username
        args: list[str] = [
            "-s", profile.server,
            "-u", login,
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
                    snapshot = self._update_status(
                        ConnectionState.DISCONNECTED,
                        profile=profile,
                        error_message="VPN connection dropped unexpectedly.",
                    )
                self._invoke_callback(callback, snapshot)
                break
            # Refresh IP (may change on rekey).
            ip = self._get_tunsnx_ip()
            ip_snapshot: Optional[ConnectionStatus] = None
            with self._lock:
                if self._status.ip_address != ip:
                    logger.debug("Tunnel IP changed to %s", ip)
                    ip_snapshot = self._update_status(
                        ConnectionState.CONNECTED,
                        profile=self._status.profile,
                        ip_address=ip,
                        interface=self._status.interface,
                        connected_at=self._status.connected_at,
                    )
            if ip_snapshot is not None:
                self._invoke_callback(callback, ip_snapshot)
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
    ) -> ConnectionStatus:
        """Update internal status and return a snapshot for callback dispatch.

        Must be called with :attr:`_lock` held.  The returned snapshot
        **must** be passed to the status callback *outside* the lock to
        avoid deadlocks caused by re-entrant lock acquisition inside the
        callback.
        """
        new = ConnectionStatus(
            state=state,
            profile=profile or self._status.profile,
            ip_address=ip_address,
            interface=interface,
            connected_at=connected_at,
            error_message=error_message,
        )
        self._status = new
        # Return a copy so callers cannot inadvertently mutate self._status.
        return ConnectionStatus(
            state=new.state,
            profile=new.profile,
            ip_address=new.ip_address,
            interface=new.interface,
            connected_at=new.connected_at,
            error_message=new.error_message,
        )

    @staticmethod
    def _invoke_callback(
        callback: Optional[Callable[[ConnectionStatus], None]],
        snapshot: ConnectionStatus,
    ) -> None:
        """Invoke *callback* with *snapshot* outside any lock."""
        if callback:
            try:
                callback(snapshot)
            except Exception:  # noqa: BLE001
                logger.exception("Exception in status callback.")
