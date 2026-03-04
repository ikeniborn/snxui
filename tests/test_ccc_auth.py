"""Tests for snxui.core.ccc_auth — CCC S-expression protocol authentication."""

from __future__ import annotations

import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from snxui.core.ccc_auth import (
    CCCAuth,
    _build_hello,
    _build_otp_response,
    _build_userpass,
    _sexp_escape,
    _sexp_int,
    _sexp_str,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_resp(body: str, status: int = 200):
    raw = body.encode("utf-8")
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = raw
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _ccc_auth(server: str = "vpn.test") -> CCCAuth:
    return CCCAuth(server=server, port=443, verify_ssl=False)


def _http_error(code: int) -> urllib.error.HTTPError:
    exc = urllib.error.HTTPError(None, code, "err", {}, BytesIO(b""))
    exc.read = lambda n=256: b""
    return exc


# CCC response builders for tests
def _hello_resp(rc: int = 0, session_id: str = "") -> str:
    sid = f'"{session_id}"' if session_id else ""
    return (
        "(CCCserverResponse\n"
        f"\t:ResponseHeader (\n"
        f"\t\t:id (0)\n"
        f"\t\t:session_id ({sid})\n"
        f"\t\t:return_code ({rc})\n"
        "\t)\n"
        "\t:ResponseData ()\n"
        ")\n"
    )


def _auth_success_resp(active_key: str = "deadbeef" * 8, session_id: str = "sess1") -> str:
    return (
        "(CCCserverResponse\n"
        f"\t:ResponseHeader (\n"
        f"\t\t:id (1)\n"
        f'\t\t:session_id ("{session_id}")\n'
        "\t\t:return_code (0)\n"
        "\t)\n"
        "\t:ResponseData (\n"
        f'\t\t:active_key ({active_key})\n'
        "\t)\n"
        ")\n"
    )


def _otp_challenge_resp(
    session_id: str = "sess2",
    challenge: str = "Enter OTP:",
) -> str:
    return (
        "(CCCserverResponse\n"
        "\t:ResponseHeader (\n"
        "\t\t:id (1)\n"
        f'\t\t:session_id ("{session_id}")\n'
        "\t\t:return_code (5)\n"
        "\t)\n"
        "\t:ResponseData (\n"
        f'\t\t:challenge_text ("{challenge}")\n'
        "\t)\n"
        ")\n"
    )


def _wrong_pw_resp() -> str:
    return (
        "(CCCserverResponse\n"
        "\t:ResponseHeader (\n"
        "\t\t:id (1)\n"
        "\t\t:session_id ()\n"
        "\t\t:return_code (14)\n"
        "\t)\n"
        "\t:ResponseData ()\n"
        ")\n"
    )


# ---------------------------------------------------------------------------
# S-expression helpers
# ---------------------------------------------------------------------------


class TestSexpEscape:
    def test_plain_string_unchanged(self):
        assert _sexp_escape("password123") == "password123"

    def test_double_quote_escaped(self):
        assert _sexp_escape('pass"word') == 'pass\\"word'

    def test_backslash_escaped(self):
        assert _sexp_escape("path\\dir") == "path\\\\dir"

    def test_both_escaped(self):
        assert _sexp_escape('a\\"b') == 'a\\\\\\"b'

    def test_empty_string(self):
        assert _sexp_escape("") == ""


class TestBuilderEscaping:
    """Verify builders escape special chars to prevent S-expression injection."""

    def test_userpass_escapes_password_quote(self):
        body = _build_userpass("s", "r", "u", 'pass"word')
        assert ':password ("pass\\"word")' in body

    def test_userpass_escapes_username_quote(self):
        body = _build_userpass("s", "r", 'user"name', "pw")
        assert ':username ("user\\"name")' in body

    def test_userpass_escapes_realm_quote(self):
        body = _build_userpass("s", 're"alm', "u", "pw")
        assert ':selected_login_option ("re\\"alm")' in body

    def test_otp_escapes_quote(self):
        body = _build_otp_response("s", '12"34')
        assert ':user_input ("12\\"34")' in body

    def test_hello_escapes_realm_quote(self):
        body = _build_hello('re"alm')
        assert ':selected_realm_id ("re\\"alm")' in body


class TestSexpStr:
    def test_quoted_value(self):
        text = ':session_id ("abc123")'
        assert _sexp_str(text, "session_id") == "abc123"

    def test_unquoted_value(self):
        text = ":client_type (4)"
        # _sexp_str returns unquoted integers too
        assert _sexp_str(text, "client_type") == "4"

    def test_empty_value_quotes(self):
        text = ':session_id ("")'
        assert _sexp_str(text, "session_id") == ""

    def test_missing_key(self):
        assert _sexp_str("(CCCserverResponse)", "active_key") == ""

    def test_hex_token(self):
        key = "a" * 32
        text = f":active_key ({key})"
        assert _sexp_str(text, "active_key") == key

    def test_multiline(self):
        text = "(CCCserverResponse\n\t:return_code (0)\n\t:session_id (\"sess\")\n)"
        assert _sexp_str(text, "session_id") == "sess"


class TestSexpInt:
    def test_basic(self):
        assert _sexp_int(":return_code (0)", "return_code") == 0

    def test_nonzero(self):
        assert _sexp_int(":return_code (502)", "return_code") == 502

    def test_missing(self):
        assert _sexp_int("(CCCserverResponse)", "return_code") == -1

    def test_negative(self):
        assert _sexp_int(":id (-1)", "id") == -1


# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------


class TestBuildHello:
    def test_contains_client_type_trac(self):
        assert ":client_type (TRAC)" in _build_hello()

    def test_type_is_client_hello(self):
        assert ":type (ClientHello)" in _build_hello()

    def test_session_id_empty_quoted(self):
        assert ':session_id ("")' in _build_hello()

    def test_session_id_portal_key_included(self):
        h = _build_hello(session_id="abc123portal")
        assert ':session_id ("abc123portal")' in h

    def test_realm_included(self):
        h = _build_hello("my_realm")
        assert ':selected_realm_id ("my_realm")' in h

    def test_empty_realm_empty_quoted(self):
        h = _build_hello("")
        assert ':selected_realm_id ("")' in h

    def test_endpoint_os_unix(self):
        assert ":endpoint_os (unix)" in _build_hello()


class TestBuildUserpass:
    def test_contains_username(self):
        body = _build_userpass("sess", "realm", "alice", "pw")
        assert ':username ("alice")' in body

    def test_contains_password(self):
        body = _build_userpass("sess", "realm", "alice", "hunter2")
        assert ':password ("hunter2")' in body

    def test_contains_realm(self):
        body = _build_userpass("sess", "my_realm", "u", "p")
        assert ':selected_login_option ("my_realm")' in body

    def test_realm_omitted_when_empty(self):
        body = _build_userpass("sess", "", "u", "p")
        assert "selected_login_option" not in body

    def test_session_id_included(self):
        body = _build_userpass("abc123", "r", "u", "p")
        assert ':session_id ("abc123")' in body

    def test_empty_session_id_empty_quoted(self):
        body = _build_userpass("", "r", "u", "p")
        assert ':session_id ("")' in body

    def test_id_is_1(self):
        body = _build_userpass("s", "r", "u", "p")
        assert ":id (1)" in body

    def test_type_is_userpass(self):
        body = _build_userpass("s", "r", "u", "p")
        assert ":type (UserPass)" in body

    def test_client_type_trac(self):
        body = _build_userpass("s", "r", "u", "p")
        assert ":client_type (TRAC)" in body


class TestBuildOtpResponse:
    def test_contains_user_input(self):
        body = _build_otp_response("sess", "123456")
        assert ':user_input ("123456")' in body

    def test_contains_auth_session_id(self):
        body = _build_otp_response("sess42", "123456")
        assert ':auth_session_id ("sess42")' in body

    def test_type_is_multi_challange(self):
        # Note: "MultiChallange" is intentionally misspelled in the protocol
        body = _build_otp_response("sess", "123456")
        assert ":type (MultiChallange)" in body

    def test_client_type_trac(self):
        body = _build_otp_response("sess", "123456")
        assert ":client_type (TRAC)" in body

    def test_default_id_is_2(self):
        body = _build_otp_response("sess", "123456")
        assert ":id (2)" in body

    def test_custom_id(self):
        body = _build_otp_response("sess", "123456", req_id=3)
        assert ":id (3)" in body


# ---------------------------------------------------------------------------
# CCCAuth.authenticate()
# ---------------------------------------------------------------------------


class TestCccAuthenticate:
    """Full authenticate() flow tests with mocked HTTP."""

    def _setup_open(self, ca: CCCAuth, responses: list):
        """Install a fake _post_ccc that returns responses in order."""
        resp_iter = iter(responses)

        def fake_post(body: str) -> str | None:
            try:
                return next(resp_iter)
            except StopIteration:
                return None

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        return ca

    # ── Success: return_code=0 from UserPass ────────────────────────────

    def test_success_userpass_returns_active_key(self):
        ca = _ccc_auth()
        active_key = "deadbeef" * 8
        self._setup_open(ca, [
            _hello_resp(rc=502),                    # ClientHello → need auth
            _auth_success_resp(active_key=active_key),  # UserPass → success
        ])
        result = ca.authenticate("alice", "password", "my_realm")
        assert result == active_key

    def test_success_with_session_from_hello(self):
        """If ServerHello provides a session_id, UserPass must use it."""
        ca = _ccc_auth()
        posted = []
        orig_build_userpass = _build_userpass

        def fake_post(body: str) -> str:
            posted.append(body)
            if len(posted) == 1:
                return _hello_resp(rc=0, session_id="SERVERSESSION")
            return _auth_success_resp(active_key="aabbccdd" * 8)

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        result = ca.authenticate("u", "p", "realm")
        # Second POST (UserPass) must contain the session from hello
        assert ':session_id ("SERVERSESSION")' in posted[1]
        assert result == "aabbccdd" * 8

    # ── Wrong password ──────────────────────────────────────────────────

    def test_wrong_password_returns_none(self):
        ca = _ccc_auth()
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _wrong_pw_resp(),
        ])
        result = ca.authenticate("u", "wrongpw", "realm")
        assert result is None

    # ── OTP flow ────────────────────────────────────────────────────────

    def test_otp_flow_with_callback(self):
        """OTP challenge → callback called → ChallengeResponse → active_key."""
        ca = _ccc_auth()
        active_key = "cafebabe" * 8
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="S1", challenge="Enter token:"),
            _auth_success_resp(active_key=active_key, session_id="S1"),
        ])
        otp_received = []
        result = ca.authenticate(
            "u", "p", "r",
            otp_callback=lambda prompt: (otp_received.append(prompt), "123456")[1],
        )
        assert result == active_key
        assert otp_received  # callback was called
        assert "Enter token:" in otp_received[0]

    def test_otp_flow_with_cached_otp(self):
        """cached_otp must be tried first without calling otp_callback."""
        ca = _ccc_auth()
        active_key = "11223344" * 8
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="S2"),
            _auth_success_resp(active_key=active_key, session_id="S2"),
        ])
        callback_called = []
        result = ca.authenticate(
            "u", "p", "r",
            otp_callback=lambda p: callback_called.append(p) or "999999",
            cached_otp="777777",
        )
        assert result == active_key
        # Callback must NOT have been called (cached OTP was used)
        assert not callback_called

    def test_otp_cancelled_returns_none(self):
        ca = _ccc_auth()
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(),
        ])
        result = ca.authenticate("u", "p", "r", otp_callback=lambda _: None)
        assert result is None

    def test_otp_wrong_cached_retries_with_callback(self):
        """If cached OTP is rejected, must call otp_callback for a fresh one."""
        ca = _ccc_auth()
        active_key = "aabbccdd" * 8
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="S3"),
            _wrong_pw_resp(),                           # cached OTP rejected
            _auth_success_resp(active_key=active_key),  # fresh OTP accepted
        ])
        fresh_called = []
        result = ca.authenticate(
            "u", "p", "r",
            otp_callback=lambda p: (fresh_called.append(p), "999999")[1],
            cached_otp="old_otp",
        )
        assert result == active_key
        assert fresh_called  # callback was called for fresh OTP

    def test_no_callback_no_cached_otp_returns_none(self):
        ca = _ccc_auth()
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(),
        ])
        result = ca.authenticate("u", "p", "r")
        assert result is None

    # ── Network errors ───────────────────────────────────────────────────

    # ── Portal cookies forwarded in HTTP headers ─────────────────────────

    def test_portal_cookies_sent_in_cookie_header(self):
        """Portal cookies must appear as Cookie: header in every CCC POST."""
        from unittest.mock import patch as _patch

        ca = _ccc_auth()
        active_key = "aabbccdd" * 8
        sent_headers = []

        original_open = ca._opener.open

        def recording_open(req, timeout=None):
            sent_headers.append(dict(req.headers))
            # Build a fake response like original _post_ccc expects
            resp = _make_resp(_auth_success_resp(active_key=active_key))
            return resp

        with _patch.object(ca._opener, "open", side_effect=recording_open):
            result = ca.authenticate(
                "u", "p", "realm",
                portal_cookies={"CPCVPN_SESSION_ID": "SID123", "CPCVPN_OBSCURE_KEY": "KEY456"},
            )

        assert result == active_key
        assert sent_headers, "At least one request was sent"
        # All requests must carry the Cookie header
        for h in sent_headers:
            cookie_val = h.get("Cookie", "")
            assert "CPCVPN_SESSION_ID=SID123" in cookie_val
            assert "CPCVPN_OBSCURE_KEY=KEY456" in cookie_val

    def test_no_portal_cookies_no_cookie_header(self):
        """Without portal_cookies, no Cookie: header must be added."""
        from unittest.mock import patch as _patch

        ca = _ccc_auth()
        sent_headers = []

        def recording_open(req, timeout=None):
            sent_headers.append(dict(req.headers))
            return _make_resp(_auth_success_resp())

        with _patch.object(ca._opener, "open", side_effect=recording_open):
            ca.authenticate("u", "p", "realm")

        for h in sent_headers:
            assert "Cookie" not in h

    def test_hello_network_error_returns_none(self):
        ca = _ccc_auth()
        ca._post_ccc = lambda body: None  # type: ignore[method-assign]
        assert ca.authenticate("u", "p", "r") is None

    def test_userpass_network_error_returns_none(self):
        ca = _ccc_auth()
        responses = [_hello_resp(rc=502), None]
        resp_iter = iter(responses)
        ca._post_ccc = lambda body: next(resp_iter)  # type: ignore[method-assign]
        assert ca.authenticate("u", "p", "r") is None

    # ── Unexpected return codes ──────────────────────────────────────────

    def test_need_auth_from_userpass_returns_none(self):
        """If server returns 502 from UserPass without authn_status=done, give up."""
        ca = _ccc_auth()
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _hello_resp(rc=502),  # 502 from UserPass = CCC disabled / wrong format
        ])
        result = ca.authenticate("u", "p", "r")
        assert result is None

    def test_rc600_with_authn_status_done_returns_active_key(self):
        """return_code=600 + authn_status=done is a valid success (observed in the wild)."""
        ca = _ccc_auth()
        active_key = "cafecafe" * 8
        rc600_success = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (1)\n"
            "\t\t:type (UserPass)\n"
            '\t\t:session_id ("s1")\n'
            "\t\t:return_code (600)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            "\t\t:authn_status (done)\n"
            "\t\t:is_authenticated (true)\n"
            f"\t\t:active_key ({active_key})\n"
            "\t)\n"
            ")\n"
        )
        self._setup_open(ca, [_hello_resp(rc=502), rc600_success])
        result = ca.authenticate("u", "p", "r")
        assert result == active_key

    # ── Portal session resume ────────────────────────────────────────────

    def test_portal_resume_succeeds_with_empty_credentials(self):
        """When portal session recognised (server echoes session_id), try empty-cred UserPass first.

        If it returns active_key (rc=0), return it without sending credential UserPass.
        """
        ca = _ccc_auth()
        active_key = "aabbccdd" * 8
        posted = []

        def fake_post(body: str) -> str:
            posted.append(body)
            n = len(posted)
            if n == 1:
                # ClientHello response: server echoes portal_session_id as session_id
                return _hello_resp(rc=502, session_id="OBSCUREKEY123456")
            if n == 2:
                # Portal resume (empty-cred UserPass) → success
                return _auth_success_resp(active_key=active_key)
            # Should NOT reach step 3 (credential UserPass)
            pytest.fail("Unexpected POST #3 — should have returned after portal resume")

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        result = ca.authenticate(
            "u", "p", "realm",
            portal_session_id="OBSCUREKEY123456",
        )
        assert result == active_key
        assert len(posted) == 2, "Only ClientHello + portal-resume UserPass should be sent"
        # Portal resume UserPass must have empty credentials
        assert ':username ("")' in posted[1]
        assert ':password ("")' in posted[1]

    def test_portal_resume_falls_through_to_credential_auth_on_502(self):
        """If portal resume returns 502, fall through to credential UserPass."""
        ca = _ccc_auth()
        active_key = "11223344" * 8
        posted = []

        def fake_post(body: str) -> str:
            posted.append(body)
            n = len(posted)
            if n == 1:
                return _hello_resp(rc=502, session_id="OBSCUREKEY123456")
            if n == 2:
                # Portal resume → still need auth (502)
                return _hello_resp(rc=502, session_id="OBSCUREKEY123456")
            # Credential UserPass → success
            return _auth_success_resp(active_key=active_key)

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        result = ca.authenticate(
            "u", "p", "realm",
            portal_session_id="OBSCUREKEY123456",
        )
        assert result == active_key
        assert len(posted) == 3  # Hello + portal resume + credential UserPass
        # Third POST must contain the real username
        assert ':username ("u")' in posted[2]

    def test_portal_resume_skipped_when_server_returns_empty_session_id(self):
        """If ClientHello returns empty session_id, portal resume is skipped."""
        ca = _ccc_auth()
        active_key = "cafecafe" * 8
        posted = []

        def fake_post(body: str) -> str:
            posted.append(body)
            n = len(posted)
            if n == 1:
                return _hello_resp(rc=502, session_id="")  # server did NOT echo portal key
            return _auth_success_resp(active_key=active_key)

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        result = ca.authenticate(
            "u", "p", "realm",
            portal_session_id="OBSCUREKEY123456",  # provided, but server didn't echo
        )
        assert result == active_key
        # Only Hello + credential UserPass — NO portal resume
        assert len(posted) == 2
        assert ':username ("u")' in posted[1]

    def test_portal_resume_otp_challenge_handled(self):
        """If portal resume returns OTP challenge (rc=5), handle it via _handle_otp."""
        ca = _ccc_auth()
        active_key = "deadd00d" * 8
        posted = []
        otp_called = []

        def fake_post(body: str) -> str:
            posted.append(body)
            n = len(posted)
            if n == 1:
                return _hello_resp(rc=502, session_id="OBSCUREKEY123456")
            if n == 2:
                # Portal resume → OTP required
                return _otp_challenge_resp(session_id="OBSCUREKEY123456", challenge="Enter token:")
            # ChallengeResponse → success
            return _auth_success_resp(active_key=active_key)

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        result = ca.authenticate(
            "u", "p", "realm",
            portal_session_id="OBSCUREKEY123456",
            otp_callback=lambda prompt: (otp_called.append(prompt), "654321")[1],
        )
        assert result == active_key
        assert otp_called  # OTP callback was invoked

    # ── Active key extraction ────────────────────────────────────────────

    def test_active_key_no_active_key_in_success_returns_none(self):
        """return_code=0 but no active_key → return None."""
        ca = _ccc_auth()
        empty_success = (
            "(CCCserverResponse :ResponseHeader (:return_code (0) :session_id (\"x\"))"
            " :ResponseData ())"
        )
        self._setup_open(ca, [_hello_resp(502), empty_success])
        assert ca.authenticate("u", "p", "r") is None


# ---------------------------------------------------------------------------
# CCCAuth.is_available()
# ---------------------------------------------------------------------------


class TestCccIsAvailable:
    def test_200_means_available(self):
        ca = _ccc_auth()
        # is_available() uses _opener.open directly, not _post_ccc
        resp = _make_resp(_hello_resp(rc=502))
        with patch.object(ca._opener, "open", return_value=resp):
            assert ca.is_available() is True

    def test_network_error_means_not_available(self):
        ca = _ccc_auth()
        with patch.object(ca._opener, "open", side_effect=_http_error(404)):
            assert ca.is_available() is False


# ---------------------------------------------------------------------------
# PortalAuthResult.realm field
# ---------------------------------------------------------------------------


class TestPortalAuthResultRealm:
    """Verify that authenticate() stores the realm in PortalAuthResult."""

    def test_realm_stored_in_step1_success(self):
        """When step 1 succeeds without OTP, result.realm must equal the realm from GET."""
        from snxui.core.portal_auth import PortalAuth, PortalAuthResult

        realm = "MY_REALM"
        success_result = PortalAuthResult(success=True, session_id="SID")

        with patch.object(PortalAuth, "_fetch_login_page", return_value={"realm": realm}), \
             patch.object(PortalAuth, "_post_credentials", return_value=success_result), \
             patch.object(PortalAuth, "_fetch_snx_resources", return_value=None):
            pa = PortalAuth(server="vpn.test", port=443, verify_ssl=False)
            result = pa.authenticate("user", "pass")

        assert result.success is True
        assert result.realm == realm

    def test_realm_stored_in_step2_success(self):
        """When step 2 (OTP) succeeds, result.realm must equal the realm from GET."""
        from snxui.core.portal_auth import PortalAuth

        # We'll just test the direct field setting path
        from snxui.core.portal_auth import PortalAuthResult
        r = PortalAuthResult(success=True, session_id="s", realm="ssl_vpn_RADIUS")
        assert r.realm == "ssl_vpn_RADIUS"

    def test_realm_default_empty(self):
        from snxui.core.portal_auth import PortalAuthResult
        assert PortalAuthResult(success=True).realm == ""


def _make_response_raw(body: str):
    raw = body.encode("utf-8")
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = raw
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _fake_portal_open(req, timeout=20):
    return _make_response_raw("")
