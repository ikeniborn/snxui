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
from .vpn_backend import VPNBackend

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
    r"Login\s+failed|SNX:\s*Connection\s+aborted",
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

# Объединённый паттерн для expect() списка.
# Порядок альтернатив не влияет на приоритет — важен порядок в expect()-списке.
_RE_2FA_ANY = re.compile(
    r"Enter\s+SecurID\s+PASSCODE\s*:|SecurID\s+passcode\s*:|PASSCODE\s*:|"
    r"Enter\s+RADIUS\s+(?:token|passcode)\s*:|RADIUS\s*:.*(?:token|passcode|code)\s*:|"
    r"\bToken\s*:|"
    r"Challenge\s*:\s*\S+|Enter\s+response\s*:|"
    r"Enter\s+(?:your\s+)?one.time\s+(?:password|code)\s*:|"
    r"Please\s+enter\s+(?:your\s+)?one.time\s+password\s*:|"
    r"Enter\s+(?:your\s+)?(?:token|passcode)\s*:|"
    r"Verification\s+code\s*:|\bOTP\s*:|Two.factor\s+code\s*:",
    re.IGNORECASE,
)

# Gateway certificate confirmation: "Do you accept? [y]es/[N]o:"
_RE_GATEWAY_CONFIRM = re.compile(
    r"\[y\]es/\[N\]o\s*:|Do\s+you\s+accept\?|Please\s+confirm\s+the\s+connection",
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

_SNXRC_PATH = Path.home() / ".snxrc"


def _clear_snxrc() -> None:
    """Remove ``~/.snxrc`` to prevent SNX from using a stale or invalid auth_id.

    SNX binary always reads ``~/.snxrc`` at start-up and includes any stored
    ``auth_id`` in its HTTP authentication request — even when launched without
    ``-r``.  If ``auth_id`` contains a portal session token (CPCVPN_OBSCURE_KEY)
    rather than a CCC ``active_key``, the server rejects it immediately with
    "Connection aborted" before issuing any OTP challenge.  Deleting the file
    ensures SNX performs a clean credential exchange.
    """
    try:
        if _SNXRC_PATH.exists():
            _SNXRC_PATH.unlink()
            logger.info(
                "Cleared ~/.snxrc to prevent stale portal auth_id from "
                "interfering with fresh SNX authentication."
            )
    except OSError:
        logger.debug("Failed to delete ~/.snxrc", exc_info=True)


# ---------------------------------------------------------------------------
# PTY output logger
# ---------------------------------------------------------------------------


class _LogfileCapture:
    """Pipe all SNX PTY read-output to our debug logger, line by line.

    Assigned to ``child.logfile_read`` so every byte SNX writes to the
    terminal is echoed to the ``snxui.core.snx_backend`` logger at DEBUG
    level.  Carriage-returns are stripped; empty lines are skipped.
    """

    def __init__(self) -> None:
        self._buf = ""

    def write(self, data: str) -> int:
        self._buf += data
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            cleaned = line.rstrip("\r")
            if cleaned:
                logger.debug("SNX> %s", cleaned)
        return len(data)

    def flush(self) -> None:
        tail = self._buf.rstrip("\r")
        if tail:
            logger.debug("SNX> %s", tail)
        self._buf = ""


# ---------------------------------------------------------------------------
# SNXBackend
# ---------------------------------------------------------------------------


class SNXBinaryBackend(VPNBackend):
    """High-level interface for establishing and monitoring SNX VPN connections.

    Uses pexpect to drive the /usr/bin/snx binary via a pseudo-TTY.
    Only one connection is supported at a time per instance.  The backend is
    intentionally synchronous (no async/await); UI callbacks are dispatched
    from a background thread.

    Example::

        backend = SNXBinaryBackend()
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
        # Set to True by _run_portal_auth() when the server rejects credentials.
        # Read by home_page to decide whether to re-ask for password.
        self._portal_credentials_failed: bool = False
        # Set to True by _run_portal_auth() when portal auth succeeds.
        # Causes _build_args() to pass -r so SNX reads ~/.snxrc and skips
        # its own credential/OTP exchange (eliminates the double-OTP problem).
        self._portal_auth_ok: bool = False
        # Set to True by _run_portal_auth() when CCC auth succeeded and produced
        # an active_key written to ~/.snxrc.  Only when True is -r flag safe to
        # use — otherwise /SNX/ReLogin rejects the session token and reports
        # "Connection aborted".  When False, SNX falls back to regular PTY auth.
        self._ccc_auth_ok: bool = False

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

        self._portal_credentials_failed = False
        self._portal_auth_ok = False
        self._ccc_auth_ok = False
        binary = self._find_snx_binary()
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.CONNECTING, profile=profile,
            )
        self._invoke_callback(status_callback, snapshot)

        if profile.portal_auth:
            ok, cached_otp = self._run_portal_auth(profile, password, status_callback, two_factor_callback)
            if ok is not None:
                return ok
            # ok=None → portal auth succeeded; _run_portal_auth set self._portal_auth_ok=True.
            # When CCC auth also succeeded (_ccc_auth_ok=True), we use -r mode and SNX
            # skips OTP — the cached portal OTP is not needed in the PTY.
            # When CCC auth FAILED (_ccc_auth_ok=False), we fall back to full SNX PTY auth
            # (no -r).  In that case the cached portal OTP is STALE (RADIUS OTPs are
            # one-time-use), so we must NOT pass it — the server will send a fresh OTP
            # challenge to SNX and the user must enter a new code.
            if cached_otp is not None and self._ccc_auth_ok:
                # -r mode: wrap callback with one-shot cached OTP so reconnect session
                # doesn't prompt the user if the server somehow asks for OTP again.
                _orig_cb = two_factor_callback
                _otp_once: list[Optional[str]] = [cached_otp]

                def _one_shot_callback(prompt_text: str) -> Optional[str]:
                    if _otp_once:
                        code = _otp_once.pop(0)
                        logger.debug(
                            "SNX PTY 2FA: returning cached portal OTP (no dialog shown)."
                        )
                        return code
                    return _orig_cb(prompt_text) if _orig_cb is not None else None

                two_factor_callback = _one_shot_callback
            elif cached_otp is not None and not self._ccc_auth_ok:
                logger.info(
                    "Portal OTP was cached but CCC auth failed → SNX will use full PTY auth. "
                    "The cached OTP is STALE (RADIUS one-time-use); "
                    "SNX will prompt for a fresh OTP via the 2FA dialog."
                )

        args = self._build_args(profile)
        # use_reconnect=True only when -r is actually in args (portal_reconnect_mode=True).
        use_reconnect = "-r" in args
        logger.info("Launching SNX: %s %s", binary, " ".join(args))

        child = None  # Initialise before try so except can safely close it.
        try:
            child = pexpect.spawn(
                binary, args, encoding="utf-8", timeout=_CONNECT_TIMEOUT, echo=False,
            )
            child.logfile_read = _LogfileCapture()
            return self._run_connect_session(
                child, password, profile, status_callback, two_factor_callback,
                use_reconnect=use_reconnect,
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
        use_reconnect: bool = False,
    ) -> bool:
        """Execute the PTY interaction sequence after spawning SNX.

        Must be called from within the ``try`` block in :meth:`connect`
        so that pexpect exceptions propagate to the outer handler.

        When *use_reconnect* is True (``portal_reconnect_mode=True`` and portal
        auth succeeded, SNX launched with ``-u user -r``), the password is sent
        and the server uses ``CPCVPN_OBSCURE_KEY`` from ``~/.snxrc`` to skip OTP.
        """
        if use_reconnect:
            return self._run_reconnect_session(child, password, profile, status_callback)
        early = self._await_password_prompt(child, profile, status_callback)
        if early is not None:
            return early
        logger.debug("Password prompt received, sending credentials.")
        if profile.combined_auth:
            return self._send_combined_auth(
                child, password, profile, status_callback, two_factor_callback
            )
        child.sendline(password)
        return self._handle_post_password(child, profile, status_callback, two_factor_callback)

    def _run_reconnect_session(
        self,
        child: "pexpect.spawn",
        password: str,
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> bool:
        """PTY interaction for ``snx -r`` (reconnect) mode after portal auth.

        SNX still prompts for the password even with ``-r``, but the server
        uses ``CPCVPN_OBSCURE_KEY`` from ``~/.snxrc`` to skip the OTP/2FA
        step — only the password exchange happens in the PTY.

        Flow:
          Phase 1 — await password prompt (or direct connect if server skips it):
            * Password prompt → send password → Phase 2.
            * Connected directly → success.
            * Gateway cert confirm → auto-accept "y" → loop.
          Phase 2 — await connected after password:
            * Connected → success.
            * 2FA / OTP prompt → portal session expired; report error.
            * Auth/conn failure / EOF / TIMEOUT → report error.
        """
        logger.info(
            "SNX reconnect mode: sending password, OTP should be skipped by portal session."
        )

        # ── Phase 1: await password prompt ──────────────────────────────
        _CONFIRM_LIMIT = 3
        for _round in range(_CONFIRM_LIMIT):
            idx = child.expect(
                [
                    _RE_PASSWORD,         # 0 — password prompt
                    _RE_CONNECTED,        # 1 — connected without password (rare)
                    _RE_GATEWAY_CONFIRM,  # 2 — certificate confirmation
                    _RE_ALREADY,          # 3
                    _RE_AUTH_FAILED,      # 4
                    _RE_CONN_FAILED,      # 5
                    pexpect.EOF,          # 6
                    pexpect.TIMEOUT,      # 7
                ],
                timeout=_PASSWORD_TIMEOUT,
            )
            full_output = (child.before or "") + (
                child.after if isinstance(child.after, str) else ""
            )

            if idx == 0:
                logger.debug("Reconnect: password prompt — sending password.")
                child.sendline(password)
                break  # proceed to phase 2
            if idx == 1:
                return self._finish_connected(child, profile, callback, full_output)
            if idx == 2:
                logger.info(
                    "Reconnect: gateway certificate confirmation (round %d), auto-accepting.",
                    _round + 1,
                )
                child.sendline("y")
                continue
            if idx == 3:
                return self._handle_already_connected(child, profile, callback)
            # idx 4,5,6,7 → pre-password failure; map to indices 1,2,3,4
            return self._handle_connect_failure(child, profile, callback, idx - 3, full_output)
        else:
            logger.error("Reconnect: gateway confirmation loop exceeded %d rounds.", _CONFIRM_LIMIT)
            return self._handle_connect_failure(child, profile, callback, 4, "")

        # ── Phase 2: await connected (OTP skipped by portal session) ────
        idx2 = child.expect(
            [
                _RE_CONNECTED,    # 0
                _RE_2FA_ANY,      # 1 — OTP prompt: CPCVPN_OBSCURE_KEY not accepted
                _RE_PASSWORD,     # 2 — second password: unexpected
                _RE_AUTH_FAILED,  # 3
                _RE_CONN_FAILED,  # 4
                pexpect.EOF,      # 5
                pexpect.TIMEOUT,  # 6
            ],
            timeout=_CONNECT_TIMEOUT,
        )
        full_output2 = (child.before or "") + (
            child.after if isinstance(child.after, str) else ""
        )

        if idx2 == 0:
            return self._finish_connected(child, profile, callback, full_output2)

        if idx2 in (1, 2):
            # Server requested OTP even with portal session — CPCVPN_OBSCURE_KEY
            # was rejected or has expired.  Report an actionable error instead of
            # showing the OTP dialog (the session must be refreshed).
            logger.warning(
                "Reconnect: server requested %s after portal auth — "
                "CPCVPN_OBSCURE_KEY may be expired or invalid. Output: %r",
                "OTP" if idx2 == 1 else "second password",
                full_output2[:200],
            )
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message=(
                        "Portal session expired — server still requested OTP. "
                        "Disconnect and reconnect to start a new session."
                    ),
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        if idx2 == 3:
            # _RE_AUTH_FAILED matched (includes "SNX: Connection aborted.").
            # In reconnect mode this means the server rejected our session token
            # from ~/.snxrc.  Root cause: portal auth creates a *browser* session
            # (CPCVPN_SESSION_ID); /SNX/ReLogin requires a *CCC session* token that
            # the SNX binary generates when it does its own CCC-based auth.
            # This server requires RADIUS MultiChallenge OTP which the SNX binary
            # cannot handle natively, so a CCC session cannot be established.
            logger.error(
                "Reconnect: server rejected session token from ~/.snxrc "
                "(Connection aborted). "
                "This server likely requires CCC-based auth (not portal browser auth). "
                "Output: %r",
                full_output2[:200],
            )
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message=(
                        "Server rejected portal session token (Connection aborted).\n"
                        "Likely cause: the server requires 'User-Agent: SNXClient' "
                        "to create a CCC-compatible session.  This was fixed in the "
                        "current version — please disconnect and reconnect."
                    ),
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        # idx 4,5,6 → failure; map to _handle_connect_failure indices 2,3,4
        return self._handle_connect_failure(child, profile, callback, idx2 - 2, full_output2)

    def _send_combined_auth(
        self,
        child: "pexpect.spawn",
        password: str,
        profile: Profile,
        status_callback: Optional[Callable[[ConnectionStatus], None]],
        two_factor_callback: Optional[TwoFactorCallback],
    ) -> bool:
        """Send password+OTP as a single combined credential.

        Used when the server does not present an interactive OTP prompt but
        expects the one-time code appended directly to the password field in
        the authentication POST request.

        If *two_factor_callback* is ``None``, sends the plain password as a
        fallback (the user may have pre-appended the OTP themselves).

        Returns:
            ``True`` on successful connection, ``False`` otherwise.
        """
        if two_factor_callback is None:
            logger.warning(
                "combined_auth=True but no two_factor_callback provided — "
                "sending plain password. Pre-append OTP manually if required."
            )
            child.sendline(password)
            return self._handle_post_password(child, profile, status_callback, None)

        prompt_text = (
            child.after if isinstance(child.after, str) else ""
        ) or "Enter your OTP code:"
        otp = two_factor_callback(prompt_text)
        if otp is None:
            logger.info("Combined auth: user cancelled OTP input.")
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR,
                    profile=profile,
                    error_message="Two-factor authentication cancelled.",
                )
            child.close()
            self._invoke_callback(status_callback, snapshot)
            return False

        logger.debug("Combined auth: appending OTP to password.")
        child.sendline(password + otp)
        return self._handle_post_password(child, profile, status_callback, None)

    def _await_password_prompt(
        self,
        child: "pexpect.spawn",
        profile: Profile,
        callback: Optional[Callable[[ConnectionStatus], None]],
    ) -> Optional[bool]:
        """Wait for SNX to show the password prompt.

        Before asking for the password, SNX may present a gateway certificate
        confirmation ("Do you accept? [y]es/[N]o:").  This method handles
        that step automatically by sending "y" and continuing to wait for
        the actual password prompt.

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
        # SNX may ask to confirm the gateway certificate before prompting for
        # the password.  Allow up to _CONFIRM_LIMIT confirmation rounds (normally 1).
        _CONFIRM_LIMIT = 3
        for _confirm_round in range(_CONFIRM_LIMIT):
            idx = child.expect(
                [
                    _RE_PASSWORD,           # 0
                    _RE_ALREADY,            # 1
                    _RE_GATEWAY_CONFIRM,    # 2 — "Do you accept? [y]es/[N]o:"
                    _RE_CONN_FAILED,        # 3
                    pexpect.EOF,            # 4
                    pexpect.TIMEOUT,        # 5
                ],
                timeout=_PASSWORD_TIMEOUT,
            )

            if idx == 0:
                # Password prompt received — caller sends the password.
                return None
            if idx == 1:
                return self._handle_already_connected(child, profile, callback)
            if idx == 2:
                # Gateway certificate confirmation: auto-accept.
                before = getattr(child, "before", "") or ""
                logger.info(
                    "Gateway certificate confirmation requested (round %d). "
                    "Auto-accepting. Context: %r",
                    _confirm_round + 1,
                    before[-300:],
                )
                child.sendline("y")
                continue
            # idx 3,4,5 → pre-prompt failure
            return self._handle_pre_prompt_failure(child, profile, callback, idx - 1)

        # Exceeded confirmation rounds — treat as a connection failure.
        logger.error("Gateway confirmation loop exceeded %d rounds.", _CONFIRM_LIMIT)
        return self._handle_pre_prompt_failure(child, profile, callback, 4)

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
                    _RE_2FA_ANY,      # 1 — high priority: catch before auth-failed
                    _RE_PASSWORD,     # 2 — second "password:" prompt = OTP request
                    _RE_AUTH_FAILED,  # 3
                    _RE_CONN_FAILED,  # 4
                    pexpect.EOF,      # 5
                    pexpect.TIMEOUT,  # 6
                ],
                timeout=_CONNECT_TIMEOUT,
            )
            full_output = (child.before or "") + (
                child.after if isinstance(child.after, str) else ""
            )

            if idx == 0:
                return self._finish_connected(child, profile, callback, full_output)

            if idx in (1, 2):
                # idx 1 = explicit 2FA prompt; idx 2 = repeated "password:" = OTP
                if idx == 2:
                    logger.debug("Second password prompt detected — treating as OTP request.")
                sent = self._handle_2fa_prompt(child, profile, callback, two_factor_callback, full_output)
                if sent is False:
                    return False
                # sent is True → code was sent, continue loop
                continue

            # idx 3,4,5,6 → map to legacy indices 1,2,3,4 for _handle_connect_failure
            return self._handle_connect_failure(child, profile, callback, idx - 2, full_output)

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
    # Portal auth helpers
    # ------------------------------------------------------------------

    def _run_portal_auth(
        self,
        profile: Profile,
        password: str,
        status_callback: Optional[Callable[[ConnectionStatus], None]],
        two_factor_callback: Optional[TwoFactorCallback],
    ) -> tuple[Optional[bool], Optional[str]]:
        """Authenticate against the Check Point portal via HTTPS.

        Called before spawning the SNX PTY when ``profile.portal_auth`` is
        True.  Performs the multi-step portal login (password → RADIUS OTP /
        MCForm) against ``/Login/Login`` and ``/Login/MultiChallenge``.

        After this method returns ``(None, ...)`` the SNX binary is launched in
        reconnect mode (``-u user -r``) so it reads the portal session token from
        ``~/.snxrc`` and skips its own credential/OTP exchange.  Gateways that
        require portal auth typically disable the plain CCC password path, making
        ``-r`` the only viable mode.

        ``write_snxrc`` stores the best available session token as ``auth_id``
        for the ``/SNX/ReLogin`` endpoint — preferring a CCC-compatible token
        from ``/SNX/SNX`` (if the portal exposes it) over the raw
        ``CPCVPN_SESSION_ID`` browser-session cookie.  The SNX binary still asks
        for the password in the PTY (Phase 1 of reconnect), but the server should
        accept the session without requesting a second OTP factor.

        Note: Servers that require RADIUS MultiChallenge OTP for CCC auth cannot
        be reached via this flow because the SNX binary does not support
        MultiChallenge in its PTY interaction.  In that case ``/SNX/ReLogin``
        always returns "Connection aborted" regardless of which token is used.
        Use snx-rs (https://github.com/ancwrd1/snx-rs) for such gateways.

        Returns:
            Tuple ``(status, cached_otp)`` where:

            * ``status=None, cached_otp=...`` — portal auth succeeded; caller
              proceeds to SNX PTY.  ``cached_otp`` is the OTP string if one was
              collected during portal step 2, or ``None`` if no OTP was needed.
              The caller should wrap ``two_factor_callback`` with a one-shot that
              returns ``cached_otp`` to suppress the second interactive prompt.
            * ``status=False, cached_otp=None`` — portal auth failed; abort.
            (``True`` is never returned; the full connect happens via SNX.)
        """
        from .portal_auth import PortalAuth
        from .ccc_auth import CCCAuth

        login = (
            f"{profile.domain}\\{profile.username}"
            if profile.domain
            else profile.username
        )
        pa = PortalAuth(server=profile.server, port=profile.ssl_port, verify_ssl=not profile.ignore_server_cert)
        result = pa.authenticate(login, password, otp_callback=two_factor_callback)

        if result.success:
            logger.info("Portal auth succeeded. Attempting CCC auth for active_key.")
            # ── CCC auth: obtain a CCC-compatible active_key for /SNX/ReLogin ──
            # The portal auth creates a *browser* session (CPCVPN_SESSION_ID) which
            # /SNX/ReLogin rejects.  CCC auth (/clients/ endpoint) creates a native
            # session token (active_key) that /SNX/ReLogin actually accepts.
            # We try CCC immediately after portal auth — using the same credentials
            # and the OTP that was just collected (cached_otp avoids a second prompt).
            ccc = CCCAuth(server=profile.server, port=profile.ssl_port, verify_ssl=not profile.ignore_server_cert)
            # Use the realm extracted during portal GET /Login/Login.
            # Required by CCC UserPass as :selectedRealm.
            realm = result.realm
            active_key = ccc.authenticate(
                username=login,
                password=password,
                realm=realm,
                otp_callback=two_factor_callback,
                cached_otp=result.otp_used,
                # Pass CPCVPN_OBSCURE_KEY as portal_session_id so the server
                # can link this CCC request to the authenticated portal session.
                portal_session_id=result.obscure_key or result.session_id,
                # Forward portal cookies so the server can associate this CCC
                # request with the authenticated portal session (CPCVPN_SESSION_ID,
                # CPCVPN_OBSCURE_KEY, etc.).
                portal_cookies=result.portal_cookies,
            )
            if active_key:
                logger.info("CCC auth succeeded — writing active_key to ~/.snxrc.")
                # Write active_key as auth_id, overriding the portal session cookie.
                from .portal_auth import PortalAuthResult
                ccc_result = PortalAuthResult(
                    success=True,
                    session_id=result.session_id,
                    cookie_timeout=result.cookie_timeout,
                    snx_launch_token=active_key,
                )
                pa.write_snxrc(ccc_result)
                self._ccc_auth_ok = True
            else:
                logger.warning(
                    "CCC auth did not return active_key — "
                    "SNX reconnect mode (-r) will NOT be used since the session token "
                    "from CPCVPN_OBSCURE_KEY is not accepted by /SNX/ReLogin on this server. "
                    "Falling back to full SNX PTY auth (snx -u user, no -r). "
                    "SNX will prompt for a fresh OTP."
                )
                # Do NOT write ~/.snxrc when CCC failed.  Writing CPCVPN_OBSCURE_KEY
                # as auth_id causes SNX binary to include it in its HTTP authentication
                # request even when launched without -r.  The server rejects this stale
                # portal token with "Connection aborted" before SNX issues any OTP
                # challenge.  Delete any existing ~/.snxrc so SNX performs fresh auth.
                _clear_snxrc()
                # _ccc_auth_ok remains False → _build_args() will omit -r

            self._portal_credentials_failed = False
            self._portal_auth_ok = True
            if result.otp_used:
                logger.debug(
                    "Portal auth: OTP collected in step 2 (cached). "
                    "Will be discarded if CCC auth failed (RADIUS OTPs are one-time-use). "
                    "SNX PTY will prompt for a fresh OTP in that case."
                )
            return None, result.otp_used  # Proceed to SNX PTY

        logger.error("Portal auth failed: %s | diagnostic: %s",
                     result.error_message, result.diagnostic[:500])
        self._portal_credentials_failed = result.credentials_failed
        with self._lock:
            snapshot = self._update_status(
                ConnectionState.ERROR,
                profile=profile,
                error_message=result.error_message or "Portal authentication failed.",
            )
        self._invoke_callback(status_callback, snapshot)
        return False, None

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
        args: list[str] = ["-s", profile.server]

        # Portal reconnect mode — only when CCC auth produced a valid active_key:
        # ``write_snxrc`` stores the CCC active_key as ``auth_id`` in ``~/.snxrc``.
        # We pass ``-u user -r`` so SNX reads that file and validates via /SNX/ReLogin.
        #
        # When CCC auth failed (_ccc_auth_ok=False), -r is NOT safe to use because
        # /SNX/ReLogin will reject CPCVPN_OBSCURE_KEY (only CCC active_key works).
        # In that case we fall through to regular PTY auth (snx -u user, no -r)
        # so SNX can authenticate itself — it will prompt for OTP in the PTY.
        if profile.portal_auth and self._portal_auth_ok and self._ccc_auth_ok:
            login = (
                f"{profile.domain}\\{profile.username}"
                if profile.domain
                else profile.username
            )
            logger.info(
                "_build_args: CCC auth succeeded → using SNX -u %s -r (reconnect).",
                login,
            )
            return args + ["-u", login, "-r"]
        if profile.portal_auth and self._portal_auth_ok and not self._ccc_auth_ok:
            # CCC auth failed — fall through to regular PTY auth below.
            # SNX will handle full authentication including OTP interactively.
            login = (
                f"{profile.domain}\\{profile.username}"
                if profile.domain
                else profile.username
            )
            logger.info(
                "_build_args: CCC auth failed → SNX -u %s without -r "
                "(full PTY auth, server will request fresh OTP).",
                login,
            )

        # SNX requires EITHER -u <user> OR -c <certfile>, not both.
        if profile.certificate:
            args += ["-c", profile.certificate]
            # Pass CA dir only in certificate mode.  Some SNX builds
            # (e.g. 800008409) scan -l directory for *client* certificates
            # and wrongly report "cannot use both user/pass and certificate
            # auth" when -l is combined with -u.
            if profile.ca_list:
                args += ["-l", profile.ca_list]
        else:
            login = f"{profile.domain}\\{profile.username}" if profile.domain else profile.username
            args += ["-u", login]
        if profile.ssl_port != 443:
            args += ["-p", str(profile.ssl_port)]
        if not profile.reauth:
            args.append("-n")
        if profile.cipher:
            args += ["-Z", profile.cipher]
        # Note: tunnel_type (SSL/IPSec) is stored in the profile for future use
        # or informational purposes; SNX 800008409 does not expose CLI flags for
        # tunnel mode selection — the data channel is negotiated with the server.
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


# Backward-compatibility alias — existing code that imports SNXBackend continues to work.
SNXBackend = SNXBinaryBackend
