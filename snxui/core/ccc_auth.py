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

import logging
import re
import ssl
import urllib.error
import urllib.request
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Matches the active_key value in CCC S-expression responses so it can be
# redacted from debug logs (active_key is a session credential).
_RE_ACTIVE_KEY_LOG = re.compile(r'(:active_key\s*\(\s*")[^"]*(")', re.IGNORECASE)


def _redact_ccc(text: str) -> str:
    """Replace active_key value with *** to prevent credential leakage in logs."""
    return _RE_ACTIVE_KEY_LOG.sub(r"\1***\2", text)

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


def _build_hello(realm: str = "", session_id: str = "") -> str:
    """Build a CCC ClientHello S-expression.

    ``realm`` is passed as ``selected_realm_id`` if known; the server ignores
    it in the Hello step but some implementations include it.

    ``session_id`` is normally empty on first contact.  For portal-auth servers
    the CPCVPN_OBSCURE_KEY cookie value can be passed here so the server can
    associate the CCC request with an existing portal session (hypothesis).

    Format matches the wire format observed in snx-rs and the SNX binary:
    - RequestHeader must include ``:type (ClientHello)``
    - ``client_type`` must be the string ``TRAC``, not a numeric value
    """
    realm_val = f'"{_sexp_escape(realm)}"' if realm else '""'
    sid = f'"{_sexp_escape(session_id)}"' if session_id else '""'
    return (
        "(CCCclientRequest\n"
        " :RequestHeader (\n"
        "  :id (0)\n"
        "  :type (ClientHello)\n"
        f"  :session_id ({sid})\n"
        " )\n"
        " :RequestData (\n"
        "  :client_type (TRAC)\n"
        "  :client_version (1)\n"
        "  :client_support_saml (true)\n"
        "  :endpoint_os (unix)\n"
        f"  :selected_realm_id ({realm_val})\n"
        " )\n"
        ")\n"
    )


def _build_userpass(session_id: str, realm: str, username: str, password: str) -> str:
    """Build a CCC UserPass (authentication) S-expression.

    Field names match the wire format from snx-rs and the blog post reversing
    the SNX protocol:
    - RequestHeader must include ``:type (UserPass)``
    - ``client_type`` must be ``TRAC`` (string, not numeric)
    - username field is ``username`` (not ``userName``)
    - realm field is ``selected_login_option`` (not ``selectedRealm``)
    """
    sid = f'"{_sexp_escape(session_id)}"' if session_id else '""'
    lines = [
        "(CCCclientRequest\n",
        " :RequestHeader (\n",
        "  :id (1)\n",
        "  :type (UserPass)\n",
        f"  :session_id ({sid})\n",
        " )\n",
        " :RequestData (\n",
        "  :client_type (TRAC)\n",
        "  :endpoint_os (unix)\n",
        f"  :username (\"{_sexp_escape(username)}\")\n",
        f"  :password (\"{_sexp_escape(password)}\")\n",
    ]
    if realm:
        lines.append(f"  :selected_login_option (\"{_sexp_escape(realm)}\")\n")
    lines += [" )\n", ")\n"]
    return "".join(lines)


def _build_otp_response(session_id: str, otp: str, req_id: int = 2) -> str:
    """Build a CCC MultiChallange S-expression for OTP submission.

    Note: ``MultiChallange`` is misspelled in the Check Point protocol
    (missing the 'e' in Challenge).  The field names match snx-rs:
    - RequestHeader must include ``:type (MultiChallange)``
    - ``user_input`` (not ``user_code``)
    - ``auth_session_id`` identifies the auth session awaiting the OTP
    - ``client_type (TRAC)`` must be included
    """
    sid = f'"{_sexp_escape(session_id)}"' if session_id else '""'
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
        f"  :user_input (\"{_sexp_escape(otp)}\")\n"
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
        hello_body = _build_hello(realm, session_id=portal_session_id or "")
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
        """Extract ``active_key`` from a CCC success response."""
        active_key = _sexp_str(response, "active_key")
        if active_key:
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
        # Extract challenge prompt from server response
        challenge = (
            _sexp_str(auth_resp, "challenge_text")
            or _sexp_str(auth_resp, "prompt")
            or _sexp_str(auth_resp, "challenge")
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
            otp = otp_callback(f"[CCC] {challenge}")
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
        logger.info("CCC challenge_response: return_code=%d", otp_rc)

        if otp_rc == _RC_OK:
            return self._extract_active_key(otp_resp, "ChallengeResponse")

        if otp_rc == _RC_WRONG_PW:
            # Cached OTP may have been consumed by portal auth already.
            # Try once more with a fresh OTP from the user if we had a cached one.
            if cached_otp and otp_callback:
                logger.warning(
                    "CCC: cached OTP rejected (may be already consumed by portal auth). "
                    "Requesting fresh OTP from user."
                )
                fresh_otp = otp_callback(f"[CCC] {challenge}")
                if fresh_otp is None:
                    logger.info("CCC: fresh OTP cancelled.")
                    return None
                retry_resp = self._post_ccc(_build_otp_response(session_id, fresh_otp, req_id=3))
                if retry_resp is None:
                    return None
                retry_rc = _sexp_int(retry_resp, "return_code")
                logger.info("CCC challenge_response retry: return_code=%d", retry_rc)
                if retry_rc == _RC_OK:
                    return self._extract_active_key(retry_resp, "ChallengeResponse(retry)")
                logger.error("CCC: fresh OTP also rejected (return_code=%d)", retry_rc)
            else:
                logger.error("CCC: OTP rejected (return_code=14).")
            return None

        logger.error("CCC: ChallengeResponse unexpected return_code=%d", otp_rc)
        logger.debug("CCC: full OTP response: %r", _redact_ccc(otp_resp[:400]))
        return None
