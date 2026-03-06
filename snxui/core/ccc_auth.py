"""Check Point CCC (Client Communication Channel) protocol authentication.

CCC is the native S-expression protocol that the SNX binary uses to authenticate
against Check Point gateways.  It produces an ``active_key`` session token that
``/SNX/ReLogin`` accepts — unlike the ``CPCVPN_SESSION_ID`` *browser* cookie
produced by the portal ``/Login/Login`` flow.

Protocol flow
-------------
1. **ClientHello**  → ``POST /clients/``
   Client identifies itself (client_type=4, linux, etc.).
   Server responds with CCCserverResponse:
   * return_code=0, session_id=... → ServerHello OK, proceed to UserPass
   * return_code=502              → "authenticate now" (session_id may be empty)
   * return_code=600              → "session expired, re-authenticate"
   Either way, extract whatever session_id the server returned and continue.

2. **UserPass** → ``POST /clients/`` with same or empty session_id
   Client sends username + password (+ selectedRealm).
   Server responds:
   * return_code=0 → success; ``active_key`` is in ResponseData
   * return_code=5 → MultiChallenge / OTP required; ``challenge_text`` in ResponseData
   * return_code=14 → wrong credentials

3. **ChallengeResponse** (only if return_code=5) → ``POST /clients/``
   Client submits OTP value via ``:user_code``.
   Server responds:
   * return_code=0 → ``active_key`` in ResponseData
   * return_code=14 → wrong OTP

The ``active_key`` is written to ``~/.snxrc`` as ``auth_id=`` and is what
``/SNX/ReLogin`` expects for reconnect mode (``snx -r``).

References
----------
* strings /usr/bin/snx build 800008409 — confirms /clients/ POST endpoint
* snx-rs (https://github.com/ancwrd1/snx-rs) — open-source CCC implementation
* Lab logs: /clients/ returns HTTP 200 with return_code=502 on ClientHello
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
import ssl
import urllib.error
import urllib.request
import uuid
from http.cookiejar import CookieJar
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SNX credential obfuscation (XOR table from snx-rs/crates/snxcore/src/util.rs)
# ---------------------------------------------------------------------------

# XOR key table extracted from the SNX binary (via snx-rs reverse-engineering).
# The Check Point CCC protocol requires username, password, and OTP to be
# obfuscated with this table before transmission; the server deobfuscates them.
_XOR_TABLE = bytes([
    45, 79, 68, 73, 70, 73, 69, 68, 38, 87, 48, 82, 79, 80, 69, 82, 84, 89,
    51, 72, 69, 69, 84, 55, 73, 84, 72, 47, 43, 52, 72, 69, 51, 72, 69, 69,
    84, 41, 36, 51, 63, 44, 36, 33, 48, 63, 33, 53, 63, 48, 50, 47, 48, 37,
    50, 52, 41, 37, 51, 46, 53, 44, 44, 16, 38, 55, 63, 55, 48, 63, 47, 34,
    42, 37, 35, 52, 51,
])


def _snx_obfuscate(value: str) -> str:
    """Obfuscate a string with the SNX XOR table, return lower-case hex.

    The Check Point CCC protocol requires credentials (username, password, OTP)
    to be obfuscated before transmission.  The server deobfuscates them.

    Algorithm (matches ``snx_obfuscate()`` in snx-rs/crates/snxcore/src/util.rs):
    Iterate the input bytes in **reverse order**, for each byte at original
    index *i* compute ``(byte % 255) XOR table[i % len(table)]`` (mapping 0
    to 255 to avoid null bytes), collect the results in that reverse order,
    then hex-encode.
    """
    data = value.encode("utf-8")
    result = []
    for i in range(len(data) - 1, -1, -1):
        c = data[i]
        xored = (c % 255) ^ _XOR_TABLE[i % len(_XOR_TABLE)]
        result.append(255 if xored == 0 else xored)
    return bytes(result).hex()


def _snx_deobfuscate(hex_str: str) -> str:
    """Deobfuscate a hex-encoded string from the server (server obfuscates prompts).

    Algorithm matches ``snx_deobfuscate()`` in snx-rs/crates/snxcore/src/util.rs:
    hex-decode → reverse → translate (XOR with table using ORIGINAL indices) → reverse.

    If *hex_str* is not valid hex (plain text prompt from older servers), returns
    the input unchanged.  Empty input returns empty string.
    """
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        return hex_str  # plain text prompt, return as-is
    if not data:
        return ""
    reversed_data = data[::-1]
    n = len(reversed_data)
    result = []
    for i in range(n - 1, -1, -1):
        c = reversed_data[i]
        xored = (c % 255) ^ _XOR_TABLE[i % len(_XOR_TABLE)]
        result.append(255 if xored == 0 else xored)
    result.reverse()
    return bytes(result).decode("utf-8", errors="replace")


def _get_device_id() -> str:
    """Return a stable device ID for CCC ``client_logging_data``.

    Reads ``/etc/machine-id`` (Linux standard) and derives a UUID v5 from it,
    formatted in braced upper-case (``{XXXXXXXX-…}``).  Falls back to a fixed
    namespace UUID when the file is unavailable.
    """
    try:
        machine_id = pathlib.Path("/etc/machine-id").read_text().strip()
    except Exception:
        machine_id = "snxui-default"
    return "{" + str(uuid.uuid5(uuid.NAMESPACE_OID, machine_id)).upper() + "}"


# Matches the active_key value in CCC S-expression responses so it can be
# redacted from debug logs (active_key is a session credential).
_RE_ACTIVE_KEY_LOG = re.compile(r'(:active_key\s*\(\s*")[^"]*(")', re.IGNORECASE)


def _redact_ccc(text: str) -> str:
    """Replace active_key value with *** to prevent credential leakage in logs."""
    return _RE_ACTIVE_KEY_LOG.sub(r"\1***\2", text)


# Words that the CCC server uses as OTP field names but that look like a
# password prompt to end users.  We normalise them to a clearer label.
_CCC_GENERIC_PROMPTS = {"password", "passcode", "code", "enter code", "otp"}


def _ccc_otp_prompt(raw: str) -> str:
    """Return a user-friendly prompt string for the CCC OTP dialog.

    The CCC server names its OTP field "password:", which confuses users.
    Normalise known generic labels to "CCC Authentication code".
    Informative retry messages (e.g. server error text) are kept as-is,
    prefixed with "CCC:".
    """
    stripped = raw.strip().rstrip(":").strip()
    if stripped.lower() in _CCC_GENERIC_PROMPTS or not stripped:
        return "CCC Authentication code"
    return f"CCC: {stripped}"


# SNX native client User-Agent (required by /clients/ endpoint)
_SNX_UA = "SNXClient"

# CCC protocol return codes
_RC_OK = 0         # Success
_RC_OTP = 5        # MultiChallenge / OTP required
_RC_WRONG_PW = 14  # Wrong credentials
# NOTE: 600 is NOT always an error — the server can return rc=600 with
# authn_status=done and an active_key (this is a valid success response).
# Only treat 500/502 as unconditional "need auth" failures.
_RC_NEED_AUTH = (500, 502)  # Server rejects the request format / CCC disabled


# ---------------------------------------------------------------------------
# S-expression helpers
# ---------------------------------------------------------------------------

def _sexp_str(text: str, key: str) -> str:
    """Extract ``:key ("value")`` or ``:key (value)`` from CCC S-expression.

    Returns the value string (without quotes) or empty string if not found.
    """
    # Try quoted form first: :key ("value")
    m = re.search(rf':{re.escape(key)}\s*\(\s*"([^"]*)"\s*\)', text)
    if m:
        return m.group(1)
    # Try unquoted form: :key (value)  — value must not contain parens or quotes
    m = re.search(rf':{re.escape(key)}\s*\(\s*([^()\s"\']+)\s*\)', text)
    if m:
        return m.group(1).strip()
    return ""


def _sexp_int(text: str, key: str) -> int:
    """Extract ``:key (integer)`` from CCC S-expression.  Returns -1 if absent."""
    m = re.search(rf':{re.escape(key)}\s*\(\s*(-?\d+)\s*\)', text)
    return int(m.group(1)) if m else -1


def _extract_sexp_block(text: str, key: str) -> str:
    """Extract the parenthesised block after ``:key`` using bracket counting.

    Returns the content *between* the outermost parentheses (i.e. without
    the enclosing ``(`` and ``)``) so the caller can process the inner
    items independently.  Returns ``""`` if *key* is not found.
    """
    m = re.search(rf':{re.escape(key)}\s*\(', text)
    if not m:
        return ""
    start = m.end() - 1  # index of the opening '('
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    return ""


def _split_sexp_items(block: str) -> list[str]:
    """Split *block* into its top-level ``(…)`` items.

    Each returned string is the content between the outer parentheses of one
    item (parentheses excluded).  Nested parentheses are handled correctly
    by bracket counting.
    """
    items: list[str] = []
    depth = 0
    start = -1
    for i, ch in enumerate(block):
        if ch == "(":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start != -1:
                items.append(block[start:i])
                start = -1
    return items


def _parse_login_options(response: str) -> list[tuple[str, str]]:
    """Extract login options from a CCC S-expression ServerHello.

    Check Point gateways include a ``login_options_list`` block in the
    ServerHello when the client sends ``ClientHello``.  Each option has an
    ``:id`` (the realm identifier, e.g. ``vpn_ssl_vpn``) and an optional
    ``:display_name`` (human-readable label).

    Returns:
        List of ``(id, display_name)`` tuples.  Empty when the block is absent.
    """
    list_block = _extract_sexp_block(response, "login_options_list")
    if not list_block:
        return []
    options: list[tuple[str, str]] = []
    for item in _split_sexp_items(list_block):
        id_ = _sexp_str(item, "id")
        name = _sexp_str(item, "display_name") or id_
        if id_:
            options.append((id_, name))
    return options


# ---------------------------------------------------------------------------
# CCC request builders
# ---------------------------------------------------------------------------

def _sexp_escape(value: str) -> str:
    """Escape a string value for use inside CCC S-expression quoted fields.

    S-expression quoted strings delimit values with ``"``.  A literal ``"``
    or ``\\`` inside the value must be backslash-escaped to avoid malforming
    the S-expression (e.g. a password containing ``"`` would break the parser).
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _build_hello(session_id: str = "") -> str:
    """Build a CCC ClientHello S-expression (snx-rs wire format).

    ``session_id`` is normally empty on first contact.  For portal-auth servers
    the CPCVPN_OBSCURE_KEY cookie value can be passed here so the server can
    associate the CCC request with an existing portal session.

    Wire format matches snx-rs (crates/snxcore/src/ccc.rs):
    - RequestHeader includes ``id`` and ``type``; ``session_id`` only when non-empty.
    - RequestData contains a nested ``:client_info`` block — NOT flat fields.
    - ``endpoint_os`` and ``selected_realm_id`` are NOT sent in ClientHello
      (realm is sent only in UserPass via ``selectedLoginOption``).
    """
    header_sid = f"  :session_id (\"{_sexp_escape(session_id)}\")\n" if session_id else ""
    return (
        "(CCCclientRequest\n"
        " :RequestHeader (\n"
        "  :id (0)\n"
        "  :type (ClientHello)\n"
        f"{header_sid}"
        " )\n"
        " :RequestData (\n"
        "  :client_info (\n"
        "   :client_type (TRAC)\n"
        "   :client_version (1)\n"
        "   :client_support_saml (true)\n"
        "  )\n"
        " )\n"
        ")\n"
    )


def _build_userpass(session_id: str, realm: str, username: str, password: str) -> str:
    """Build a CCC UserPass (authentication) S-expression (snx-rs wire format).

    Wire format differences from older incorrect implementation:
    - Credentials are XOR-obfuscated with ``_snx_obfuscate()`` — the server
      deobfuscates them server-side; plaintext credentials fail authentication.
    - Realm field is ``:selectedLoginOption`` (camelCase, per snx-rs serde rename),
      not ``:selected_login_option``.
    - ``:client_logging_data`` block included (``os_name=Windows``, ``device_id``),
      matching what snx-rs sends in ``AuthRequest``.
    - ``:endpoint_os`` is NOT sent (``None`` in snx-rs ``AuthRequest``).
    """
    sid = f'"{_sexp_escape(session_id)}"' if session_id else '""'
    obs_user = _snx_obfuscate(username)
    obs_pass = _snx_obfuscate(password)
    device_id = _get_device_id()
    lines = [
        "(CCCclientRequest\n",
        " :RequestHeader (\n",
        "  :id (1)\n",
        "  :type (UserPass)\n",
        f"  :session_id ({sid})\n",
        " )\n",
        " :RequestData (\n",
        "  :client_type (TRAC)\n",
        f"  :username (\"{obs_user}\")\n",
        f"  :password (\"{obs_pass}\")\n",
        "  :client_logging_data (\n",
        f"   :device_id (\"{_sexp_escape(device_id)}\")\n",
        "   :os_name (Windows)\n",
        "  )\n",
    ]
    if realm:
        lines.append(f"  :selectedLoginOption (\"{_sexp_escape(realm)}\")\n")
    lines += [" )\n", ")\n"]
    return "".join(lines)


def _build_otp_response(session_id: str, otp: str, req_id: int = 2) -> str:
    """Build a CCC MultiChallange S-expression for OTP/password challenge response.

    Note: ``MultiChallange`` is misspelled in the Check Point protocol.
    OTP/password is XOR-obfuscated with ``_snx_obfuscate()`` (matches snx-rs
    ``MultiChallengeRequest.user_input: ObfuscatedString``).
    """
    sid = f'"{_sexp_escape(session_id)}"' if session_id else '""'
    obs_otp = _snx_obfuscate(otp)
    return (
        "(CCCclientRequest\n"
        " :RequestHeader (\n"
        f"  :id ({req_id})\n"
        "  :type (MultiChallange)\n"
        f"  :session_id ({sid})\n"
        " )\n"
        " :RequestData (\n"
        "  :client_type (TRAC)\n"
        f"  :auth_session_id ({sid})\n"
        f"  :user_input (\"{obs_otp}\")\n"
        " )\n"
        ")\n"
    )


# ---------------------------------------------------------------------------
# CCCAuth client
# ---------------------------------------------------------------------------

class CCCAuth:
    """CCC protocol authenticator for Check Point VPN gateways.

    Uses ``POST /clients/`` with S-expression payloads to authenticate and
    obtain an ``active_key`` suitable for ``auth_id`` in ``~/.snxrc``.

    Args:
        server: VPN gateway hostname or IP.
        port:   HTTPS port (default 443).
        verify_ssl: Skip certificate verification when False.
    """

    def __init__(self, server: str, port: int = 443, verify_ssl: bool = True) -> None:
        self._server = server
        self._port = port
        self._portal_cookies: dict[str, str] = {}
        # Set to True when UserPass returns rc=14 (wrong username/password).
        # Callers use this to distinguish password failures from OTP failures
        # so the keyring entry is only deleted when the actual password is wrong.
        self.credentials_rejected: bool = False
        # Populated after ClientHello from :connectivity_info (:tcpt_port …).
        # Used by PythonSSLBackend to connect the SLIM SSL tunnel on the correct port.
        # 0 means "not yet discovered" — callers should fall back to profile.ssl_port.
        self.tcpt_port: int = 0
        # Populated after successful authentication from the final CCC response
        # (:session_id in ResponseHeader).  Included in the SSL tunnel ClientHello
        # RequestHeader so the server can bind the tunnel to the authenticated session.
        self.session_id: str = ""

        ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the server exposes a reachable ``/clients/`` endpoint."""
        try:
            req = urllib.request.Request(
                self._url("/clients/"), method="POST",
                data=_build_hello().encode(),
            )
            req.add_header("User-Agent", _SNX_UA)
            req.add_header("Content-Type", "application/x-snx-request")
            req.add_header("Accept", "*/*")
            with self._opener.open(req, timeout=5) as resp:
                body = resp.read(256).decode("utf-8", errors="replace")
            rc = _sexp_int(body, "return_code")
            logger.debug("CCC availability probe: HTTP 200, return_code=%d", rc)
            return True  # Any 200 response means CCC is available
        except urllib.error.HTTPError as exc:
            logger.debug("CCC not available: HTTP %d", exc.code)
            return False
        except Exception as exc:
            logger.debug("CCC availability probe error: %s", exc)
            return False

    def authenticate(
        self,
        username: str,
        password: str,
        realm: str,
        otp_callback: Optional[Callable[[str], Optional[str]]] = None,
        cached_otp: Optional[str] = None,
        portal_session_id: Optional[str] = None,
        portal_cookies: Optional[dict[str, str]] = None,
    ) -> Optional[str]:
        """Full CCC authentication flow.

        Args:
            username:          Login name (with domain prefix, e.g. ``DOM\\user``).
            password:          Plaintext password.
            realm:             Realm name from portal GET (e.g. ``ssl_vpn_UF-Username_RADIUS``).
            otp_callback:      Called with OTP prompt text when RADIUS OTP is required.
                               Must return OTP string or None to cancel.
            cached_otp:        OTP collected by a previous portal auth step.  Tried first
                               to avoid a second interactive prompt.
            portal_session_id: CPCVPN_OBSCURE_KEY (or SESSION_ID) value from portal auth.
                               If provided, it is sent as ``session_id`` in ClientHello so
                               the server can link the CCC request to an existing portal
                               session — some servers require this to create a CCC session.
            portal_cookies:    Dict of cookies from the portal auth session (CPCVPN_SESSION_ID,
                               CPCVPN_OBSCURE_KEY, etc.).  When provided, they are forwarded
                               as ``Cookie:`` header in every CCC POST.  Some Check Point
                               gateways require the portal session cookie to be present in
                               CCC requests to associate them with the authenticated session.

        Returns:
            ``active_key`` hex string on success, ``None`` on failure or cancellation.
        """
        self._portal_cookies = portal_cookies or {}
        logger.info(
            "CCC auth: starting for user=%r realm=%r on %s:%d%s%s",
            username, realm, self._server, self._port,
            f" (portal_session_id=%.12s…)" % portal_session_id if portal_session_id else "",
            f" (portal_cookies={list(self._portal_cookies.keys())})" if self._portal_cookies else "",
        )

        # ── Step 1: ClientHello ─────────────────────────────────────────
        # If a portal session is available, include it as session_id so the
        # server can associate this CCC request with the authenticated portal session.
        hello_body = _build_hello(session_id=portal_session_id or "")
        logger.debug("CCC: sending ClientHello")
        hello_resp = self._post_ccc(hello_body)
        if hello_resp is None:
            logger.error("CCC: ClientHello POST failed (network error)")
            return None

        hello_rc = _sexp_int(hello_resp, "return_code")
        session_id = _sexp_str(hello_resp, "session_id")
        logger.info(
            "CCC hello: return_code=%d session_id=%r",
            hello_rc, (session_id[:16] + "…") if len(session_id) > 16 else session_id,
        )

        # Extract tcpt_port from connectivity_info — used by PythonSSLBackend to
        # connect the SLIM SSL tunnel on the correct port (may differ from ssl_port).
        _conn = _extract_sexp_block(hello_resp, "connectivity_info")
        if _conn:
            _tp = _sexp_int(_conn, "tcpt_port")
            if _tp > 0:
                self.tcpt_port = _tp
                logger.debug("CCC: connectivity_info tcpt_port=%d", _tp)
            logger.debug("CCC: connectivity_info: %r", _conn[:400])

        # return_code=0 means proper ServerHello with capabilities.
        # return_code in _RC_NEED_AUTH means "please authenticate" — proceed with UserPass.
        # Any other code (including 600) is unexpected but we still try UserPass.
        if hello_rc not in (0,) + _RC_NEED_AUTH:
            logger.warning("CCC hello: unexpected return_code=%d (continuing anyway)", hello_rc)

        # ── Step 2a: Portal session resume (empty-credential UserPass) ──────────
        # When portal_session_id was provided AND the server echoed it back as
        # session_id in the ClientHello response (non-empty), the server has
        # recognised the portal session.  Try a UserPass with empty credentials
        # first — the server MAY issue an active_key without re-authentication
        # since the portal already authenticated the user.
        if portal_session_id and session_id:
            logger.info(
                "CCC: portal session recognised (session_id=%.16s…). "
                "Trying empty-credential UserPass as portal session resume.",
                session_id,
            )
            resume_resp = self._post_ccc(_build_userpass(session_id, "", "", ""))
            if resume_resp is not None:
                resume_rc = _sexp_int(resume_resp, "return_code")
                resume_authn = _sexp_str(resume_resp, "authn_status")
                resume_sid = _sexp_str(resume_resp, "session_id") or session_id
                logger.info(
                    "CCC portal resume: return_code=%d authn_status=%r",
                    resume_rc, resume_authn,
                )
                if resume_rc == _RC_OK or resume_authn == "done":
                    return self._extract_active_key(resume_resp, "PortalResume")
                if resume_rc == _RC_OTP or self._is_otp_challenge(resume_resp):
                    return self._handle_otp(
                        auth_resp=resume_resp,
                        session_id=resume_sid,
                        otp_callback=otp_callback,
                        cached_otp=cached_otp,
                    )
                # Any other code: fall through to regular credential auth
                logger.info(
                    "CCC portal resume: rc=%d — falling through to credential UserPass",
                    resume_rc,
                )
            else:
                logger.warning("CCC portal resume POST failed — falling through to credential UserPass")

        # ── Step 2b: UserPass with credentials ──────────────────────────────────
        logger.info("CCC: sending UserPass (realm=%r user=%r)", realm, username)
        auth_body = _build_userpass(session_id, realm, username, password)
        auth_resp = self._post_ccc(auth_body)
        if auth_resp is None:
            logger.error("CCC: UserPass POST failed (network error)")
            return None

        auth_rc = _sexp_int(auth_resp, "return_code")
        auth_authn = _sexp_str(auth_resp, "authn_status")
        session_id = _sexp_str(auth_resp, "session_id") or session_id
        logger.info(
            "CCC userpass: return_code=%d authn_status=%r",
            auth_rc, auth_authn,
        )

        # Success: return_code=0 OR authn_status=done (server uses 600 + authn_status=done)
        if auth_rc == _RC_OK or auth_authn == "done":
            return self._extract_active_key(auth_resp, "UserPass")

        if auth_rc == _RC_WRONG_PW:
            logger.error("CCC: wrong credentials (return_code=14)")
            self.credentials_rejected = True
            return None

        if auth_rc == _RC_OTP or self._is_otp_challenge(auth_resp):
            # ── Step 3: ChallengeResponse ─────────────────────────────
            return self._handle_otp(
                auth_resp=auth_resp,
                session_id=session_id,
                otp_callback=otp_callback,
                cached_otp=cached_otp,
            )

        if auth_rc in _RC_NEED_AUTH:
            logger.error(
                "CCC: UserPass returned 'need auth' code=%d — "
                "server may require different auth method or plain CCC is disabled.",
                auth_rc,
            )
            return None

        logger.error("CCC: UserPass unexpected return_code=%d", auth_rc)
        logger.debug("CCC: full response: %r", _redact_ccc(auth_resp[:500]))
        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_otp_challenge(response: str) -> bool:
        """Return True if the response signals an OTP/MultiChallenge requirement.

        Detects both the ``return_code=5`` convention and the snx-rs convention
        where ``authn_status != "done"`` with a ``prompt`` field present.
        """
        authn_status = _sexp_str(response, "authn_status")
        if authn_status and authn_status != "done":
            prompt = (
                _sexp_str(response, "prompt")
                or _sexp_str(response, "challenge_text")
                or _sexp_str(response, "challenge")
            )
            if prompt:
                return True
        return False

    def _url(self, path: str) -> str:
        return f"https://{self._server}:{self._port}{path}"

    def _post_ccc(self, body: str) -> Optional[str]:
        """POST *body* (CCC S-expression) to ``/clients/``.

        Returns response body as string, or ``None`` on error.
        Portal session cookies (if set via ``authenticate(portal_cookies=...)``)
        are forwarded as a ``Cookie:`` header so the server can associate this
        CCC request with the authenticated portal session.
        """
        url = self._url("/clients/")
        req = urllib.request.Request(url, method="POST", data=body.encode("utf-8"))
        req.add_header("User-Agent", _SNX_UA)
        req.add_header("Content-Type", "application/x-snx-request")
        req.add_header("Accept", "*/*")
        if self._portal_cookies:
            cookie_header = "; ".join(f"{k}={v}" for k, v in self._portal_cookies.items())
            req.add_header("Cookie", cookie_header)
            logger.debug("CCC POST: forwarding portal cookies: %s", list(self._portal_cookies.keys()))
        try:
            with self._opener.open(req, timeout=15) as resp:
                raw = resp.read(8192).decode("utf-8", errors="replace")
            logger.debug("CCC response (%d bytes): %r", len(raw), _redact_ccc(raw[:600]))
            return raw
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read(256).decode("utf-8", errors="replace")
            except Exception:
                err_body = str(exc)
            logger.error("CCC POST HTTP %d: %r", exc.code, err_body[:120])
            return None
        except Exception as exc:
            logger.error("CCC POST error: %s", exc)
            return None

    def _extract_active_key(self, response: str, stage: str) -> Optional[str]:
        """Extract and deobfuscate ``active_key`` from a CCC success response.

        The server sends ``active_key`` as an XOR-obfuscated hex string (the
        same ``ObfuscatedString`` type used for credentials).  We must call
        ``_snx_deobfuscate()`` to get the plaintext key before writing it to
        ``~/.snxrc`` — the SNX binary sends the plaintext key to the server
        in ``/SNX/ReLogin``, not the obfuscated form.

        Also stores ``session_id`` from the ResponseData block for future use
        (e.g. keep-alive or reconnect flows that may require the CCC session id).
        """
        # Store session_id from ResponseData (32-char) for the SSL tunnel ClientHello.
        # snx-rs uses ccc_session_id from ResponseData, not ResponseHeader (64-char).
        # Fallback to the first session_id found anywhere in the response.
        resp_data_block = _extract_sexp_block(response, "ResponseData")
        sess = (
            (_sexp_str(resp_data_block, "session_id") if resp_data_block else "")
            or _sexp_str(response, "session_id")
        )
        if sess:
            self.session_id = sess
            logger.debug("CCC %s: session_id=%.16s… (len=%d)", stage, sess, len(sess))

        raw = _sexp_str(response, "active_key")
        if raw:
            active_key = _snx_deobfuscate(raw)
            logger.info(
                "CCC %s: active_key obtained (%.12s…, %d chars)",
                stage, active_key, len(active_key),
            )
            return active_key
        logger.warning(
            "CCC %s: return_code=0 but no active_key found in response. "
            "Full response: %r", stage, response[:400],
        )
        return None

    def _handle_otp(
        self,
        auth_resp: str,
        session_id: str,
        otp_callback: Optional[Callable[[str], Optional[str]]],
        cached_otp: Optional[str],
    ) -> Optional[str]:
        """Handle CCC MultiChallenge (OTP) step after UserPass.

        The server returns return_code=5 with a challenge prompt.
        We submit the OTP via ChallengeResponse and extract the active_key.
        """
        # Extract challenge prompt from server response.
        # Server obfuscates prompt values with XOR table (same as credentials) —
        # apply _snx_deobfuscate() to convert hex back to readable text.
        # Plain-text prompts (older servers) are returned unchanged by _snx_deobfuscate().
        challenge = (
            _snx_deobfuscate(_sexp_str(auth_resp, "challenge_text"))
            or _snx_deobfuscate(_sexp_str(auth_resp, "prompt"))
            or _snx_deobfuscate(_sexp_str(auth_resp, "challenge"))
            or "Additional authentication required. Enter OTP:"
        )
        logger.info("CCC OTP challenge: %r", challenge[:120])

        # Try cached OTP first (collected by portal auth step 2 already)
        otp: Optional[str] = None
        if cached_otp:
            logger.info("CCC: trying cached OTP from portal auth step 2.")
            otp = cached_otp
        elif otp_callback:
            logger.info("CCC: requesting OTP from user.")
            otp = otp_callback(_ccc_otp_prompt(challenge))
        else:
            logger.error("CCC: OTP required but no callback and no cached OTP.")
            return None

        if otp is None:
            logger.info("CCC: OTP cancelled by user.")
            return None

        logger.info("CCC: sending ChallengeResponse with OTP.")
        otp_resp = self._post_ccc(_build_otp_response(session_id, otp))
        if otp_resp is None:
            logger.error("CCC: ChallengeResponse POST failed (network error)")
            return None

        otp_rc = _sexp_int(otp_resp, "return_code")
        otp_authn = _sexp_str(otp_resp, "authn_status")
        logger.info(
            "CCC challenge_response: return_code=%d authn_status=%r",
            otp_rc, otp_authn,
        )

        # Success: return_code=0 OR authn_status=done.
        # Servers like ug.vpn.rt.ru return rc=600 + authn_status=done + active_key.
        if otp_rc == _RC_OK or otp_authn == "done":
            return self._extract_active_key(otp_resp, "ChallengeResponse")

        if otp_rc == _RC_WRONG_PW:
            # Cached OTP may have been consumed by portal auth already.
            # Try once more with a fresh OTP from the user if we had a cached one.
            if cached_otp and otp_callback:
                logger.warning(
                    "CCC: cached OTP rejected (may be already consumed by portal auth). "
                    "Requesting fresh OTP from user."
                )
                fresh_otp = otp_callback(_ccc_otp_prompt(challenge))
                if fresh_otp is None:
                    logger.info("CCC: fresh OTP cancelled.")
                    return None
                retry_resp = self._post_ccc(_build_otp_response(session_id, fresh_otp, req_id=3))
                if retry_resp is None:
                    return None
                retry_rc = _sexp_int(retry_resp, "return_code")
                retry_authn = _sexp_str(retry_resp, "authn_status")
                logger.info(
                    "CCC challenge_response retry: return_code=%d authn_status=%r",
                    retry_rc, retry_authn,
                )
                if retry_rc == _RC_OK or retry_authn == "done":
                    return self._extract_active_key(retry_resp, "ChallengeResponse(retry)")
                logger.error("CCC: fresh OTP also rejected (return_code=%d)", retry_rc)
            else:
                logger.error("CCC: OTP rejected (return_code=14).")
            return None

        # rc=600 + authn_status != "done" → server rejected OTP but allows retry
        # (ug.vpn.rt.ru sends rc=600 + authn_status=continue + auth_state=failed_attempt
        # when the one-time code is wrong; a new session_id is issued for the retry).
        if otp_rc == 600 and otp_authn and otp_authn != "done":
            # The server issues a NEW session_id inside ResponseData for the retry.
            # ResponseHeader also contains a session_id (the old one), so we must
            # extract specifically from ResponseData to avoid sending the stale id
            # (old session_id → server returns rc=601 "session expired/invalid").
            resp_data = _extract_sexp_block(otp_resp, "ResponseData")
            retry_session = (
                (_sexp_str(resp_data, "session_id") if resp_data else "")
                or session_id
            )
            raw_err = _sexp_str(otp_resp, "error_message")
            server_err = _snx_deobfuscate(raw_err) if raw_err else ""
            retry_prompt = server_err or challenge or "Wrong OTP — enter a new code:"
            logger.warning(
                "CCC: OTP rejected (rc=600, authn_status=%r, auth_state=%r). "
                "Server message: %r. Requesting retry from user.",
                otp_authn,
                _sexp_str(otp_resp, "auth_state"),
                server_err[:100] if server_err else raw_err[:50] if raw_err else "(none)",
            )
            if otp_callback is None:
                logger.error("CCC: OTP rejected and no callback available for retry.")
                return None
            fresh_otp = otp_callback(_ccc_otp_prompt(retry_prompt))
            if fresh_otp is None:
                logger.info("CCC: OTP retry cancelled by user.")
                return None
            retry_resp = self._post_ccc(_build_otp_response(retry_session, fresh_otp, req_id=3))
            if retry_resp is None:
                return None
            retry_rc = _sexp_int(retry_resp, "return_code")
            retry_authn = _sexp_str(retry_resp, "authn_status")
            logger.info(
                "CCC challenge_response retry: return_code=%d authn_status=%r",
                retry_rc, retry_authn,
            )
            if retry_rc == _RC_OK or retry_authn == "done":
                return self._extract_active_key(retry_resp, "ChallengeResponse(retry)")
            logger.error(
                "CCC: retry OTP also rejected (return_code=%d, authn_status=%r).",
                retry_rc, retry_authn,
            )
            return None

        logger.error("CCC: ChallengeResponse unexpected return_code=%d", otp_rc)
        logger.debug("CCC: full OTP response: %r", _redact_ccc(otp_resp[:400]))
        return None


# ---------------------------------------------------------------------------
# Server discovery
# ---------------------------------------------------------------------------


def discover_login_options(
    server: str,
    port: int = 443,
    verify_ssl: bool = True,
) -> list[tuple[str, str]]:
    """Query a Check Point gateway for available login option IDs.

    Identical information to ``snx-rs -m info -s <server>`` but implemented
    entirely in Python without requiring the ``snx-rs`` binary.

    Strategy
    --------
    1. **CCC ClientHello** — Send a ``ClientHello`` to ``POST /clients/``.
       The ServerHello normally includes a ``login_options_list`` block whose
       items have ``:id`` (the realm ID, e.g. ``vpn_ssl_vpn``) and
       ``:display_name`` (human-readable label).  This is the primary source.
    2. **Portal HTML fallback** — ``GET /Login/Login`` and parse the
       ``realmsArrJSON`` JavaScript variable that the Check Point portal
       embeds in the page.  Used when the CCC response lacks
       ``login_options_list`` (some older gateways).

    Args:
        server:     VPN gateway hostname or IP.
        port:       HTTPS port (default 443).
        verify_ssl: Verify TLS certificate (default True).

    Returns:
        List of ``(id, display_name)`` tuples.  The ``id`` value is what
        should be entered as ``Login Type`` in the profile.  Empty list when
        neither source provides options or the server is unreachable.
    """
    # -- Strategy 1: CCC ClientHello ----------------------------------------
    ccc = CCCAuth(server=server, port=port, verify_ssl=verify_ssl)
    resp = ccc._post_ccc(_build_hello())
    if resp:
        options = _parse_login_options(resp)
        if options:
            logger.info(
                "discover_login_options: %d option(s) via CCC on %s:%d",
                len(options), server, port,
            )
            return options
        logger.debug(
            "discover_login_options: CCC responded but no login_options_list — "
            "trying portal HTML fallback"
        )

    # -- Strategy 2: portal /Login/Login HTML --------------------------------
    # Use a CookieJar so the opener follows cookie-based redirect flows that
    # some Check Point gateways use to verify cookie support before returning
    # the actual login page (the one that contains realmsArrJSON).
    _disc_ctx = ssl.create_default_context()
    if not verify_ssl:
        _disc_ctx.check_hostname = False
        _disc_ctx.verify_mode = ssl.CERT_NONE
    _disc_cj = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_disc_ctx),
        urllib.request.HTTPCookieProcessor(_disc_cj),
    )
    try:
        url = f"https://{server}:{port}/Login/Login"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                    "Gecko/20100101 Firefox/120.0"
                ),
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            },
        )
        with opener.open(req, timeout=10) as http_resp:
            html = http_resp.read(131072).decode("utf-8", errors="replace")
        logger.debug(
            "discover_login_options: portal HTML body %d bytes, "
            "realmsArrJSON present=%s",
            len(html), "realmsArrJSON" in html,
        )
        m = re.search(r"realmsArrJSON\s*=\s*'([^']+)'", html)
        if m:
            raw_json = m.group(1).replace('\\"', '"')
            realms = json.loads(raw_json)
            options = [
                (
                    str(r["name"]),
                    str(r.get("displayName") or r.get("display_name") or r["name"]),
                )
                for r in realms
                if isinstance(r, dict) and r.get("name")
            ]
            if options:
                logger.info(
                    "discover_login_options: %d option(s) via portal HTML on %s:%d",
                    len(options), server, port,
                )
                return options
    except Exception as exc:
        logger.debug("discover_login_options portal HTML error: %s", exc)

    logger.warning(
        "discover_login_options: no login options found on %s:%d", server, port
    )
    return []
