"""Check Point VPN portal HTTPS authentication.

Implements the web-based login flow that Check Point's JavaScript login page
performs in the browser, adapted for headless Python execution.

Discovered authentication flow (from GET /Login/Login HTML analysis)
--------------------------------------------------------------------
Portal: МРФ 'Юг' (Check Point R80+)
Realm:  ssl_vpn_UF-Username_RADIUS
Auth:   2-step — Step 1: Username/Password (authMethodType=2)
                 Step 2: RADIUS OTP         (authMethodType=5)

Step 1 POST fields (to /Login/Login):
  selectedRealm  = ssl_vpn_UF-Username_RADIUS
  userName       = domain\\user  (or domain/user)
  Password       = plaintext     (server may also accept this)
  password       = RSA-encrypted (if RSA key available; preferred)
  HeightData     = (empty)

Step 2 POST fields (to /Login/MultiChallenge via MCForm):
  username       = <login name>  (NOT userName; pre-filled by server)
  password       = RSA-encrypted RADIUS OTP
  cancelFlag     = (empty)
  HeightData     = (empty)
  params         = <base64 session state echoed from MCForm hidden field>

Success indicator: CPCVPN_SESSION_ID cookie appears after step 2.

RSA password encryption (Check Point JS_RSA.js pattern)
--------------------------------------------------------
The portal loads JS_RSA.js and encrypts the password client-side.
RSA modulus + exponent are embedded in the page as hex strings.
Python replicates this using stdlib pow() (large-int modular exponent).
If no RSA key is found, plain Password= field is used as fallback.

References (strings from /usr/bin/snx build 800008409)
-------------------------------------------------------
  POST /Login/Login HTTP/1.1
  POST /SNX/ReLogin HTTP/1.1
  loginType=Standard&userName=
  Code=
  &HeightData=&Login=Sign+In
  CPCVPN_SESSION_ID
  auth_id="
  cookie_timeout="
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Session cookie set by Check Point portal on successful login
_SESSION_COOKIE = "CPCVPN_SESSION_ID"

# SNX reconnect config file written after portal auth
_SNXRC_PATH = Path.home() / ".snxrc"

# Browser User-Agent (portal JS checks this)
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
)

# Patterns for OTP challenge in server response
_OTP_PATTERNS = re.compile(
    r"Additional\s+authentication|one.time.pass|SecurID|PASSCODE"
    r"|Verification\s+[Cc]ode|RADIUS|authMethodType.*[\"']5[\"']"
    r"|two.factor|2fa|Enter.*token|Enter.*code",
    re.IGNORECASE,
)

# Patterns for successful auth redirect in response body
_SUCCESS_PATTERNS = re.compile(
    r"SNX.*[Cc]onnect|/SNX/SNX|sslvpn.*success|VPN\s+Connected|[Ll]ogout",
    re.IGNORECASE,
)


@dataclass
class PortalAuthResult:
    """Result of a portal authentication attempt."""

    success: bool
    session_id: Optional[str] = None
    auth_id: Optional[str] = None
    cookie_timeout: Optional[str] = None
    obscure_key: Optional[str] = None       # CPCVPN_OBSCURE_KEY — VPN tunnel key for SNX -r reconnect
    otp_required: bool = False
    otp_prompt: Optional[str] = None        # Clean human-readable prompt for OTP dialog
    otp_form_url: Optional[str] = None      # OTP form submit URL (may differ from /Login/Login)
    otp_form_fields: Optional[dict] = None  # Hidden fields from MCForm (username, params, etc.)
    error_message: Optional[str] = None
    diagnostic: str = ""
    credentials_failed: bool = False  # True when server rejects username/password


# ---------------------------------------------------------------------------
# RSA encryption (Check Point JS_RSA.js compatible)
# ---------------------------------------------------------------------------

def _rsa_encrypt_password(password: str, modulus_hex: str, exponent_hex: str) -> str:
    """Encrypt *password* with Check Point's RSA scheme.

    Replicates JS_RSA.js: standard PKCS#1 v1.5 + Check Point's byte reversal.

    From Check Point's JS_RSA.js ``cpRSA.encrypt()``::

        text = unescape(encodeURIComponent(text));   // UTF-8 bytes
        var value = this.oRSAkey.encrypt(text);      // PKCS#1 v1.5
        // "this is needed to match CheckPoint's string_to_bytes()
        //  reverse pairs of hex digits: A1B9 --> B9A1"
        for (var j = value.length-2; j >= 0; j -= 2)
            newPass += value.substr(j, 2);

    The server's ``string_to_bytes()`` expects the bytes in reverse order,
    so the entire 256-byte ciphertext is mirrored (last byte first).
    """
    try:
        n = int(modulus_hex.strip(), 16)
        e = int(exponent_hex.strip(), 16)
        # JS: unescape(encodeURIComponent(text)) — converts to UTF-8 byte string
        msg = password.encode("utf-8")
        k = (n.bit_length() + 7) // 8  # key length in bytes

        # PKCS#1 v1.5 EM = 0x00 | 0x02 | PS | 0x00 | M
        ps_len = k - len(msg) - 3
        if ps_len < 8:
            logger.warning("RSA: key too small for password length, falling back to plain.")
            return ""
        ps = bytes(
            b for b in secrets.token_bytes(ps_len * 4) if b != 0
        )[:ps_len]
        em = b"\x00\x02" + ps + b"\x00" + msg
        m = int.from_bytes(em, "big")
        c = pow(m, e, n)
        hex_val = format(c, f"0{k * 2}x")

        # Check Point byte reversal: "reverse pairs of hex digits: A1B9 → B9A1"
        # Mirrors the entire ciphertext so last byte comes first.
        return "".join(hex_val[i : i + 2] for i in range(len(hex_val) - 2, -1, -2))
    except Exception as exc:
        logger.warning("RSA encryption failed (%s), will use plain password.", exc)
        return ""


# ---------------------------------------------------------------------------
# PortalAuth
# ---------------------------------------------------------------------------

class PortalAuth:
    """HTTPS client for Check Point VPN portal authentication.

    Args:
        server: VPN gateway hostname or IP.
        port: HTTPS port (default 443).
        verify_ssl: Skip certificate verification when False (gateway uses
            self-signed cert already accepted by SNX).
    """

    def __init__(
        self,
        server: str,
        port: int = 443,
        verify_ssl: bool = False,
    ) -> None:
        self._server = server
        self._port = port

        ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        self._cj: CookieJar = CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_ctx),
            urllib.request.HTTPCookieProcessor(self._cj),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def authenticate(
        self,
        username: str,
        password: str,
        otp_callback: Optional[Callable[[str], Optional[str]]] = None,
    ) -> PortalAuthResult:
        """Two-step portal authentication.

        Step 1: username + password (may be RSA-encrypted).
        Step 2: RADIUS OTP (if realm requires it).

        Args:
            username: Login name including domain prefix if needed
                (e.g. ``DOM\\user``).
            password: Plaintext password.
            otp_callback: Called with prompt text when RADIUS OTP is needed.
                Must return the OTP string or None to cancel.
        """
        logger.info(
            "Portal auth: login for %r on %s:%d",
            username, self._server, self._port,
        )

        # ── Step 0: GET login page ──────────────────────────────────────
        page_info = self._fetch_login_page()
        realm = page_info.get("realm", "")
        rsa_mod = page_info.get("rsa_modulus", "")
        rsa_exp = page_info.get("rsa_exponent", "10001")  # 65537 decimal
        # Clean OTP prompt from realm's authSchemesInfo (authMethodType=5 header).
        # Used as dialog text instead of raw HTML from result.diagnostic.
        otp_header = page_info.get(
            "otp_header",
            "Additional authentication required. Enter RADIUS OTP:",
        )

        if realm:
            logger.info("Portal auth: realm=%r", realm)
        else:
            logger.warning("Portal auth: realm not found in page; submitting without selectedRealm.")

        # ── Step 1: password ───────────────────────────────────────────
        result = self._post_credentials(
            username=username,
            password=password,
            realm=realm,
            rsa_mod=rsa_mod,
            rsa_exp=rsa_exp,
            step=1,
        )

        if result.success:
            return result

        # ── Step 2: RADIUS OTP ─────────────────────────────────────────
        if result.otp_required:
            if otp_callback is None:
                return PortalAuthResult(
                    success=False,
                    error_message=(
                        "VPN requires RADIUS OTP. "
                        "Configure 2FA method in profile or enable 'Ask Server for MFA'."
                    ),
                )
            # Use the clean display header from the realm definition as prompt.
            # Never use result.diagnostic as prompt — it may contain raw HTML.
            prompt = result.otp_prompt or otp_header
            logger.info("Portal auth: requesting RADIUS OTP from user (prompt=%r).", prompt[:80])
            otp = otp_callback(prompt)
            if otp is None:
                logger.info("Portal auth: user cancelled OTP.")
                return PortalAuthResult(
                    success=False,
                    error_message="Two-factor authentication cancelled.",
                )
            logger.info("Portal auth: submitting RADIUS OTP (step 2).")
            return self._post_credentials(
                username=username,
                password=otp,                          # RADIUS OTP — RSA-encrypted same as password
                realm=realm,
                rsa_mod=rsa_mod,                       # isPasswordHidingMode=1: OTP also RSA-encrypted
                rsa_exp=rsa_exp,
                step=2,
                form_url=result.otp_form_url,          # Use MCForm action URL if detected
                otp_form_fields=result.otp_form_fields, # Hidden fields from MCForm
            )

        return result

    def write_snxrc(self, result: PortalAuthResult) -> bool:
        """Write session info to ``~/.snxrc`` for SNX reconnect mode (``-r``).

        SNX binary uses ``auth_id`` to skip the OTP/2FA challenge (the server
        recognises the portal session and skips the second factor).  The
        correct value depends on the Check Point build:

        * ``CPCVPN_OBSCURE_KEY`` — VPN tunnel key set by some CP builds after
          a successful two-step portal auth.  SNX binary reads this and matches
          it against its internal session state.  This is the preferred value.
        * ``CPCVPN_SESSION_ID``  — web portal session cookie.  Some older CP
          builds accept this instead; used as fallback when OBSCURE_KEY is absent.
        """
        if not result.success or not result.session_id:
            logger.warning("write_snxrc: no valid session.")
            return False
        # Prefer CPCVPN_OBSCURE_KEY (VPN tunnel key); fall back to CPCVPN_SESSION_ID.
        effective_auth_id = result.obscure_key or result.auth_id or result.session_id
        logger.info(
            "write_snxrc: auth_id source=%s value=%.12s…",
            "CPCVPN_OBSCURE_KEY" if result.obscure_key else "CPCVPN_SESSION_ID",
            effective_auth_id,
        )
        lines = [
            f'gateway="{self._server}"',
            f'auth_id="{effective_auth_id}"',
        ]
        if result.cookie_timeout:
            lines.append(f'cookie_timeout="{result.cookie_timeout}"')
        content = "\n".join(lines) + "\n"
        try:
            _SNXRC_PATH.write_text(content, encoding="utf-8")
            _SNXRC_PATH.chmod(0o600)
            logger.info("Portal auth: wrote session to %s", _SNXRC_PATH)
            return True
        except OSError as exc:
            logger.error("Portal auth: cannot write %s: %s", _SNXRC_PATH, exc)
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fetch_login_page(self) -> dict:
        """GET /Login/Login, set session cookie, extract realm + RSA key.

        Returns dict with keys: realm, rsa_modulus, rsa_exponent, hidden_fields.
        """
        url = self._url("/Login/Login")
        req = urllib.request.Request(url, method="GET")
        self._set_browser_headers(req, referer=None)
        try:
            with self._opener.open(req, timeout=20) as resp:
                html = resp.read(32768).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Portal auth: GET failed (%s), continuing.", exc)
            return {}

        logger.debug(
            "Portal GET: cookies=%s, body_len=%d, body_preview=%.500s",
            [c.name for c in self._cj], len(html), html,
        )

        info = {}

        # Extract realm name from realmsArrJSON JavaScript variable.
        # Check Point embeds the JSON inside a JS string with escaped quotes:
        #   realmsArrJSON = '[{\"name\":\"ssl_vpn_...\"}]';
        # Python reads these as literal backslash+quote sequences, so we must
        # unescape \" → " before parsing.
        realm_match = re.search(r"realmsArrJSON\s*=\s*'([^']+)'", html)
        if realm_match:
            try:
                raw_json = realm_match.group(1).replace('\\"', '"')
                realms = json.loads(raw_json)
                if realms and isinstance(realms, list):
                    # Use the first non-hidden realm
                    selected_realm = None
                    for r in realms:
                        if not r.get("isHidden", True):
                            info["realm"] = r["name"]
                            logger.debug("Portal auth: realms=%s", [r.get("name") for r in realms])
                            selected_realm = r
                            break
                    if "realm" not in info and realms:
                        info["realm"] = realms[0]["name"]
                        selected_realm = realms[0]
                    # Extract OTP (step 2) display header from authSchemesInfo.
                    # authMethodType=5 = RADIUS OTP; the header is used as prompt text
                    # in the OTP dialog instead of raw HTML from the server response.
                    if selected_realm:
                        for scheme in selected_realm.get("authSchemesInfo", []):
                            if scheme.get("authMethodType") == 5:
                                header = scheme.get("customDisplayHeader", "").strip()
                                if header:
                                    info["otp_header"] = header
                                    logger.debug("Portal auth: OTP display header=%r", header)
                                break
            except (json.JSONDecodeError, KeyError, IndexError) as exc:
                logger.warning("Portal auth: could not parse realmsArrJSON: %s", exc)

        # Extract RSA public key from the main HTML page.
        self._search_rsa_key(html, info)

        if "rsa_modulus" not in info:
            # RSA key not in main HTML — try the external JS files where
            # Check Point R80 portals typically define RSA_Modulus / RSA_Exponent.
            self._fetch_rsa_from_js(info)

        if "rsa_modulus" in info:
            logger.info(
                "Portal auth: RSA key found (%d hex chars).",
                len(info.get("rsa_modulus", "")),
            )
        else:
            logger.warning(
                "Portal auth: RSA key not found — "
                "sending plaintext login-input only (may fail)."
            )

        # Extract hidden fields (including 'password' placeholder)
        info["hidden_fields"] = self._extract_hidden_fields(html)

        return info

    # RSA key search patterns shared by main-page and JS-file searches.
    # Minimum 64 hex chars (256-bit) to avoid matching color codes or short IDs.
    _RSA_MOD_PATTERNS = (
        r'RSA_Modulus\s*=\s*["\']([0-9a-fA-F]{64,})["\']',
        r'var\s+(?:rsa_?)?modulus\s*=\s*["\']([0-9a-fA-F]{64,})["\']',
        r'"(?:modulus|n)"\s*:\s*"([0-9a-fA-F]{64,})"',
        r"'(?:modulus|n)'\s*:\s*'([0-9a-fA-F]{64,})'",
        r'setPublic\s*\(\s*["\']([0-9a-fA-F]{64,})["\']',
        r'setPublicKey\s*\(\s*["\']([0-9a-fA-F]{64,})["\']',
        # Object-literal style: { n: "hex...", e: "..." }
        r'\bn\s*:\s*["\']([0-9a-fA-F]{64,})["\']',
        # Direct assignment without var/let/const
        r'[Mm]odulus\s*=\s*["\']([0-9a-fA-F]{64,})["\']',
    )
    _RSA_EXP_PATTERNS = (
        r'RSA_Exponent\s*=\s*["\']([0-9a-fA-F]+)["\']',
        r'var\s+(?:rsa_?)?exponent\s*=\s*["\']([0-9a-fA-F]+)["\']',
        r'"(?:exponent|e)"\s*:\s*"([0-9a-fA-F]+)"',
        r"'(?:exponent|e)'\s*:\s*'([0-9a-fA-F]+)'",
        r'setPublic\s*\([^,]+,\s*["\']([0-9a-fA-F]+)["\']',
        r'setPublicKey\s*\([^,]+,\s*["\']([0-9a-fA-F]+)["\']',
        r'\be\s*:\s*["\']([0-9a-fA-F]+)["\']',
        r'[Ee]xponent\s*=\s*["\']([0-9a-fA-F]+)["\']',
    )

    def _search_rsa_key(self, text: str, info: dict) -> None:
        """Search *text* for RSA modulus and exponent and update *info*."""
        if "rsa_modulus" not in info:
            for pat in self._RSA_MOD_PATTERNS:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    modulus = m.group(1)
                    info["rsa_modulus"] = modulus
                    # Log first/last chars so we can verify it's the right key
                    logger.debug(
                        "RSA modulus found by pattern %r: %s...%s (%d hex chars).",
                        pat, modulus[:24], modulus[-8:], len(modulus),
                    )
                    break
        if "rsa_exponent" not in info:
            for pat in self._RSA_EXP_PATTERNS:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    info["rsa_exponent"] = m.group(1)
                    logger.debug("RSA exponent found: %r", m.group(1))
                    break

    def _fetch_rsa_from_js(self, info: dict) -> None:
        """Try to fetch external JS files to locate the RSA public key.

        Check Point R80 portals define RSA_Modulus / RSA_Exponent in
        ``utilities.js`` or ``login-page.js`` rather than inline.
        Some portals embed the key in JS_RSA.js itself (combined library + key).
        """
        for js_path in (
            "/Login/utilities.js",
            "/Login/js/login-page.js",
            "/Login/JS_RSA.js",
        ):
            if "rsa_modulus" in info:
                break
            js_url = self._url(js_path)
            try:
                req = urllib.request.Request(js_url, method="GET")
                self._set_browser_headers(req, referer=self._url("/Login/Login"))
                with self._opener.open(req, timeout=10) as resp:
                    js_text = resp.read(131072).decode("utf-8", errors="replace")

                logger.debug("Portal auth: fetched %s (%d bytes).", js_path, len(js_text))

                had_mod = "rsa_modulus" in info
                self._search_rsa_key(js_text, info)
                # If a key was just found in this file, log context around the match
                if not had_mod and "rsa_modulus" in info:
                    self._log_rsa_key_context(js_text, info["rsa_modulus"], js_path)
            except Exception as exc:
                logger.debug(
                    "Portal auth: could not fetch %s: %s", js_path, exc
                )

    def _post_credentials(
        self,
        *,
        username: str,
        password: str,
        realm: str,
        rsa_mod: str,
        rsa_exp: str,
        step: int,
        form_url: Optional[str] = None,
        otp_form_fields: Optional[dict] = None,
    ) -> PortalAuthResult:
        """POST to /Login/Login with credentials for authentication step *step*.

        Both step 1 (password) and step 2 (RADIUS OTP) are RSA-encrypted.
        Check Point's ``utilities.js`` sets ``isPasswordHidingMode = 1``
        unconditionally, so ``encryptPasswordAndDisablePasswordDisplay()`` always
        runs — including on the OTP step.

        The browser flow (both steps):
          1. User types into the visible ``#passwordDisplayed`` (name="login-input")
          2. JS RSA-encrypts the value → stores ciphertext in hidden ``name="password"``
          3. JS *disables* ``#passwordDisplayed`` → disabled inputs are NOT submitted
          4. Form POSTs with only the hidden ``password`` field (RSA ciphertext)

        We replicate this: omit ``login-input`` when RSA succeeds; keep plaintext
        in ``login-input`` only as a last-resort fallback when RSA is unavailable.

        RSA key confirmed from JS_RSA.js context:
            var modulus = '824295d7…' ; var exponent = '010001';
            this.savePublicKey(modulus, exponent);
        """
        # form_url is set when the OTP challenge page uses a different endpoint
        # (e.g. Check Point RADIUS: #MCForm action="/Login/MCSubmit").
        # Fall back to /Login/Login when not provided.
        if form_url:
            url = self._url(form_url) if form_url.startswith("/") else form_url
            logger.info("Portal auth: submitting step %d to %s", step, url)
        else:
            url = self._url("/Login/Login")

        # RSA-encrypt the credential (mirrors browser formSubmit behaviour).
        # Check Point's utilities.js sets isPasswordHidingMode = 1 unconditionally,
        # so BOTH step 1 (password) and step 2 (RADIUS OTP) are RSA-encrypted.
        # The server validates the RSA-encrypted ``password`` field.
        encrypted_pw = ""
        if rsa_mod:
            encrypted_pw = _rsa_encrypt_password(password, rsa_mod, rsa_exp)
            if encrypted_pw:
                logger.debug(
                    "Portal auth: RSA-encrypted step %d credential (%d hex chars).",
                    step, len(encrypted_pw),
                )
            else:
                logger.warning(
                    "Portal auth: RSA encryption failed — "
                    "sending plaintext in login-input as fallback."
                )

        form: dict[str, str] = {}
        if form_url:
            # ── MCForm submission (/Login/MultiChallenge) ─────────────────
            # The RADIUS OTP challenge page uses a completely different form
            # from the initial login: different field names and extra hidden
            # fields (params, cancelFlag) that must be re-submitted as-is.
            #
            # MCForm fields (from server HTML):
            #   username   — NOT userName; value comes from hidden input
            #   password   — RSA-encrypted OTP (we fill this)
            #   cancelFlag — empty string (required, must be present)
            #   HeightData — empty string (required)
            #   params     — base64 session state (must echo back verbatim)
            #
            # Add all hidden fields extracted from the MCForm response
            # (username, cancelFlag, HeightData, params, …), then override password.
            for k, v in (otp_form_fields or {}).items():
                if k != "password":  # we set password ourselves below
                    form[k] = v
            # Ensure required fields are present even if extraction missed them
            if "username" not in form:
                form["username"] = username
            form.setdefault("cancelFlag", "")
            form.setdefault("HeightData", "")
            # pin: present in MCForm, not disabled for RADIUS OTP (authType=5).
            # Browser submits it empty because pinTextInputId is display:none
            # (updateInputFields() hides it) but the input itself is not disabled.
            form.setdefault("pin", "")
            form["password"] = encrypted_pw  # RSA-encrypted OTP
        else:
            # ── Standard /Login/Login form ────────────────────────────────
            if realm:
                form["selectedRealm"] = realm
            form["loginType"] = "Standard"        # radio button checked by default
            form["userName"] = username
            form["pin"] = ""                      # PIN field (blank for standard RADIUS)
            # login-input: the browser's encryptPasswordAndDisablePasswordDisplay()
            # *disables* the #passwordDisplayed input after RSA-encrypting its value.
            # Disabled HTML inputs are NOT included in the form POST.  We replicate
            # that behaviour by omitting login-input when RSA encryption succeeded.
            # When RSA is unavailable, include the plaintext as a last-resort fallback.
            if not encrypted_pw:
                form["login-input"] = password    # plaintext fallback (no RSA key)
            form["password"] = encrypted_pw       # RSA ciphertext
            form["HeightData"] = ""
            form["Login"] = "Sign In"             # matches SNX binary: Login=Sign+In

        # Log the form we're about to POST (password fields redacted)
        _SENSITIVE = {"login-input", "password"}
        log_form = {k: ("***" if k in _SENSITIVE and v else v) for k, v in form.items()}
        logger.debug("Portal auth POST step %d form: %s", step, log_form)

        body = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        self._set_browser_headers(req, referer=url)

        try:
            with self._opener.open(req, timeout=20) as resp:
                status = resp.status
                raw = resp.read(32768).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read(32768).decode("utf-8", errors="replace")
            except Exception:
                raw = str(exc)
        except Exception as exc:
            logger.error("Portal auth POST error: %s", exc)
            return PortalAuthResult(
                success=False,
                error_message=f"HTTPS error: {exc}",
                diagnostic=str(exc),
            )

        cookies_now = [c.name for c in self._cj]
        diag = (
            f"Step{step} HTTP {status} | cookies: {cookies_now} | "
            f"body_len: {len(raw)} | body[:200]: {raw[:200]!r}"
        )
        logger.info("Portal auth POST diagnostic:\n%s", diag)

        # ── Check for session cookie ────────────────────────────────────
        session_id = self._find_cookie(_SESSION_COOKIE)
        if session_id:
            auth_id = self._find_cookie("auth_id") or session_id
            timeout = self._find_cookie("cookie_timeout")
            obscure_key = self._find_cookie("CPCVPN_OBSCURE_KEY")
            logger.info(
                "Portal auth: %s cookie obtained — authenticated! "
                "CPCVPN_OBSCURE_KEY=%s",
                _SESSION_COOKIE,
                "present" if obscure_key else "absent",
            )
            return PortalAuthResult(
                success=True,
                session_id=session_id,
                auth_id=auth_id,
                cookie_timeout=timeout,
                obscure_key=obscure_key,
                diagnostic=diag,
            )

        # ── Try to parse JSON response ─────────────────────────────────
        json_result = self._try_parse_json(raw)
        if json_result is not None:
            logger.debug("Portal auth: JSON response: %s", json_result)
            if isinstance(json_result, dict):
                # errCode 0 or status "success" / "redirect"
                err_code = json_result.get("errCode", -1)
                status_str = str(json_result.get("status", ""))
                if err_code == 0 or "success" in status_str.lower():
                    logger.info("Portal auth: JSON success (errCode=0).")
                    # Session might come in a subsequent redirect; try finding cookie
                    s = self._find_cookie(_SESSION_COOKIE)
                    return PortalAuthResult(success=bool(s), session_id=s, diagnostic=diag)
                # OTP/challenge required
                if err_code in (105, 106, 107) or "additional" in status_str.lower():
                    return PortalAuthResult(success=False, otp_required=True, diagnostic=diag)
                # Other error
                err_msg = json_result.get("errMessage") or f"Portal error code {err_code}"
                return PortalAuthResult(
                    success=False,
                    error_message=err_msg,
                    diagnostic=diag,
                )

        # ── Detect: server returned the login page again ───────────────
        # The login page HTML always contains 'action="/Login/Login"' AND
        # 'realmsArrJSON'.  It also contains "RADIUS" in the realm name,
        # which would falsely trigger _OTP_PATTERNS below, so we MUST
        # check for the login page BEFORE the OTP scan.
        if 'action="/Login/Login"' in raw and "realmsArrJSON" in raw:
            error_hint = self._extract_login_page_error(raw)
            # If the server returns the login page WITHOUT an error message on
            # step 1, it accepted the password and is now requesting a second
            # factor (RADIUS OTP / challenge-response).  The re-displayed form
            # is the OTP entry page, not an error.
            if not error_hint and step == 1:
                logger.info(
                    "Portal auth: login page without error on step 1 — "
                    "treating as OTP challenge (step 2 required)."
                )
                return PortalAuthResult(
                    success=False,
                    otp_required=True,
                    diagnostic=diag,
                )
            logger.warning(
                "Portal auth: server returned login page (step %d) — %s",
                step, error_hint or "authentication rejected.",
            )
            return PortalAuthResult(
                success=False,
                error_message=error_hint or "Неверный пароль или имя пользователя.",
                diagnostic=diag,
                credentials_failed=True,
            )

        # ── Check body for success / OTP indicators ────────────────────
        if _SUCCESS_PATTERNS.search(raw):
            logger.info("Portal auth: success pattern in body.")
            return PortalAuthResult(success=True, diagnostic=diag)

        if _OTP_PATTERNS.search(raw) and step == 1:
            # Check Point RADIUS OTP challenge page uses #MCForm with its own action URL.
            otp_url = self._extract_otp_form_url(raw)
            otp_fields = self._extract_mcform_hidden_fields(raw)
            if otp_url:
                logger.info(
                    "Portal auth: MCForm OTP submit URL detected: %s  hidden_fields=%s",
                    otp_url, list(otp_fields.keys()),
                )
            else:
                logger.info("Portal auth: OTP challenge detected — no MCForm, will POST to /Login/Login.")
            return PortalAuthResult(
                success=False,
                otp_required=True,
                otp_form_url=otp_url,
                otp_form_fields=otp_fields,  # re-submitted verbatim in step 2
                diagnostic=diag,             # for logs only, NOT shown to user as prompt
            )

        # Empty response (2 bytes) may mean the POST was processed with
        # missing required field; add debug info for diagnosis
        if len(raw.strip()) <= 4:
            logger.warning(
                "Portal auth: POST returned nearly empty body (%d chars). "
                "Possible causes: wrong realm name, missing hidden field, "
                "or server requires JavaScript-only flow.",
                len(raw),
            )

        error_hint = self._extract_error(raw)
        return PortalAuthResult(
            success=False,
            error_message=error_hint or "Portal authentication failed.",
            diagnostic=diag,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"https://{self._server}:{self._port}{path}"

    def _set_browser_headers(
        self,
        req: urllib.request.Request,
        referer: Optional[str],
    ) -> None:
        req.add_header("User-Agent", _USER_AGENT)
        req.add_header("Accept", "text/html,application/xhtml+xml,application/json,*/*")
        req.add_header("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
        if referer:
            req.add_header("Referer", referer)
            req.add_header("Origin", f"https://{self._server}:{self._port}")

    @staticmethod
    def _extract_otp_form_url(html: str) -> Optional[str]:
        """Extract the action URL of the RADIUS OTP challenge form (#MCForm).

        Check Point's RADIUS challenge page renders a ``<form id="MCForm">``
        that submits the OTP to a different endpoint (e.g. ``/Login/MCSubmit``).
        We extract that action URL so step 2 submits to the right place.
        """
        # Match <form ... id="MCForm" ... action="/path"> in either attribute order
        m = re.search(
            r'<form\b[^>]*\bid=["\']MCForm["\'][^>]*\baction=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        if not m:
            m = re.search(
                r'<form\b[^>]*\baction=["\']([^"\']+)["\'][^>]*\bid=["\']MCForm["\']',
                html,
                re.IGNORECASE,
            )
        return m.group(1) if m else None

    @staticmethod
    def _extract_mcform_hidden_fields(html: str) -> dict[str, str]:
        """Extract hidden inputs from the ``<form id="MCForm">`` block.

        The RADIUS OTP challenge page renders a ``<form id="MCForm">`` that
        contains hidden fields which must be re-submitted verbatim:

        * ``username``   — pre-filled by server with the current login name
        * ``cancelFlag`` — empty string; must be present for server to process
        * ``HeightData`` — empty string; required
        * ``params``     — base64 session state (e.g. ``bLaunchSWS=0||snx_relogin=0``)

        The ``password`` field is excluded because we fill it ourselves
        with the RSA-encrypted OTP.

        The ``VerificationProblemDiv`` section is stripped before extraction
        because it contains ``phoneNumbersSelection`` (used for "resend code"
        flow). The browser's ``inputDisable()`` on page-load disables all inputs
        inside that div so they are NOT sent in the normal OTP submission.
        Sending ``phoneNumbersSelection`` would confuse the server into the
        "resend" code path instead of validating the submitted OTP.
        """
        form_m = re.search(
            r'<form\b[^>]*\bid=["\']MCForm["\'][^>]*>([\s\S]*?)</form>',
            html, re.IGNORECASE,
        )
        if not form_m:
            return {}
        form_html = form_m.group(1)

        # Strip the VerificationProblemDiv section and everything after it.
        # That section is display:none and contains phoneNumbersSelection which
        # the browser disables on page-load (not sent in normal OTP submission).
        vp_m = re.search(
            r'<div\b[^>]*\bid=["\']VerificationProblemDiv["\']',
            form_html, re.IGNORECASE,
        )
        if vp_m:
            form_html = form_html[:vp_m.start()]

        fields: dict[str, str] = {}
        for m in re.finditer(
            r'<input\b[^>]+\btype=["\']?hidden["\']?[^>]*>',
            form_html, re.IGNORECASE,
        ):
            tag = m.group(0)
            name_m = re.search(r'\bname=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_m = re.search(r'\bvalue=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                name = name_m.group(1)
                if name != "password":  # password is set from RSA-encrypted OTP
                    fields[name] = value_m.group(1) if value_m else ""
        return fields

    def _find_cookie(self, name: str) -> Optional[str]:
        for cookie in self._cj:
            if cookie.name == name:
                return cookie.value
        return None

    @staticmethod
    def _log_rsa_key_context(text: str, modulus: str, source: str) -> None:
        """Log ~200 chars around the RSA modulus match for diagnosis.

        This helps verify that the found hex string is actually the server's
        RSA public key and not a library test vector or some other constant.
        """
        pos = text.find(modulus[:32])  # search by first 32 chars
        if pos < 0:
            return
        start = max(0, pos - 120)
        end = min(len(text), pos + len(modulus) + 80)
        context = text[start:end]
        logger.debug(
            "RSA key context in %s (pos %d):\n...%s...",
            source, pos, context,
        )

    @staticmethod
    def _extract_hidden_fields(html: str) -> dict[str, str]:
        """Extract ``<input type="hidden">`` names/values from HTML form."""
        fields: dict[str, str] = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']?hidden["\']?[^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                fields[name_m.group(1)] = value_m.group(1) if value_m else ""
        return fields

    @staticmethod
    def _try_parse_json(text: str) -> object:
        """Return parsed JSON from *text* if it looks like JSON, else None."""
        stripped = text.strip().lstrip("\ufeff")
        if stripped and stripped[0] in ("{", "["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        return None

    @staticmethod
    def _extract_login_page_error(html: str) -> str:
        """Extract the error message from the Check Point login page.

        The portal puts auth errors in:
            <div id="errorMsgDIV" ...><span class="errorMessage">TEXT</span></div>
        """
        m = re.search(
            r'id=["\']?errorMsgDIV["\']?[^>]*>.*?<[^>]+class=["\']?errorMessage["\']?[^>]*>\s*([^<]{3,300})\s*<',
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if m:
            return re.sub(r'\s+', ' ', m.group(1)).strip()
        return ""

    @staticmethod
    def _extract_error(html: str) -> str:
        """Return a short error hint from portal HTML response."""
        for pattern in (
            r'<[^>]*id=["\']?(?:error|err|msg|message)["\']?[^>]*>\s*([^<]{5,200})\s*<',
            r'class=["\']?(?:error|alert|warning)["\']?[^>]*>\s*([^<]{5,200})\s*<',
            r'<title>\s*([^<]{5,120})\s*</title>',
        ):
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                text = re.sub(r'\s+', ' ', m.group(1)).strip()
                if text:
                    return text[:120]
        return ""
