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
    _extract_sexp_block,
    _parse_login_options,
    _redact_ccc,
    _sexp_escape,
    _sexp_int,
    _sexp_str,
    _snx_deobfuscate,
    _snx_obfuscate,
    _split_sexp_items,
    discover_login_options,
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
    # active_key in the CCC wire format is XOR-obfuscated (ObfuscatedString).
    # _extract_active_key() calls _snx_deobfuscate(), so the response must contain
    # the obfuscated form; the caller's expected value is the plaintext.
    obs_key = _snx_obfuscate(active_key)
    return (
        "(CCCserverResponse\n"
        f"\t:ResponseHeader (\n"
        f"\t\t:id (1)\n"
        f'\t\t:session_id ("{session_id}")\n'
        "\t\t:return_code (0)\n"
        "\t)\n"
        "\t:ResponseData (\n"
        f'\t\t:active_key ({obs_key})\n'
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
# SNX obfuscation
# ---------------------------------------------------------------------------


class TestSnxObfuscate:
    """_snx_obfuscate must match the Rust implementation in snx-rs/crates/snxcore/src/util.rs."""

    def test_known_value_testuser(self):
        # Verified against snx-rs test: obfuscate("testuser") == "36203a333d372a59"
        assert _snx_obfuscate("testuser") == "36203a333d372a59"

    def test_empty_string_is_empty_hex(self):
        assert _snx_obfuscate("") == ""

    def test_round_trip_not_plaintext(self):
        # Obfuscated value must differ from the input
        result = _snx_obfuscate("password123")
        assert result != "password123"
        assert all(c in "0123456789abcdef" for c in result)

    def test_length_doubles(self):
        # Hex-encoding doubles byte length
        assert len(_snx_obfuscate("abc")) == 6


# ---------------------------------------------------------------------------
# SNX deobfuscation
# ---------------------------------------------------------------------------


class TestSnxDeobfuscate:
    """_snx_deobfuscate must be the exact inverse of _snx_obfuscate."""

    def test_round_trip_testuser(self):
        assert _snx_deobfuscate(_snx_obfuscate("testuser")) == "testuser"

    def test_round_trip_password(self):
        assert _snx_deobfuscate(_snx_obfuscate("s3cr3t!")) == "s3cr3t!"

    def test_known_server_prompt(self):
        # Observed in real server response from ug.vpn.rt.ru:
        # :prompt (771c203726313a372e5d) → "password: "
        assert _snx_deobfuscate("771c203726313a372e5d") == "password: "

    def test_empty_hex_returns_empty_string(self):
        assert _snx_deobfuscate("") == ""

    def test_plain_text_returned_unchanged(self):
        # Non-hex strings (plain-text prompts from older servers) pass through
        assert _snx_deobfuscate("Enter OTP:") == "Enter OTP:"

    def test_invalid_hex_returned_unchanged(self):
        assert _snx_deobfuscate("gg") == "gg"


# ---------------------------------------------------------------------------
# S-expression helpers
# ---------------------------------------------------------------------------


class TestRedactCcc:
    """_redact_ccc must mask active_key values to prevent log-based credential theft."""

    def test_redacts_active_key(self):
        response = '(CCCserverResponse :ResponseData (:active_key ("abcdef1234567890")))'
        redacted = _redact_ccc(response)
        assert "abcdef1234567890" not in redacted
        assert ":active_key" in redacted
        assert "***" in redacted

    def test_leaves_other_fields_intact(self):
        response = '(CCCserverResponse :ResponseData (:return_code (0) :session_id ("abc")))'
        assert _redact_ccc(response) == response

    def test_no_active_key_unchanged(self):
        text = "no sensitive data here"
        assert _redact_ccc(text) == text


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
    """Verify builders obfuscate credentials and escape special chars in realm/session_id."""

    def test_userpass_username_is_obfuscated(self):
        body = _build_userpass("s", "r", "alice", "pw")
        # username must appear as obfuscated hex, NOT plaintext
        assert f':username ("{_snx_obfuscate("alice")}")' in body
        assert ':username ("alice")' not in body

    def test_userpass_password_is_obfuscated(self):
        body = _build_userpass("s", "r", "u", 'pass"word')
        obs = _snx_obfuscate('pass"word')
        # password is hex-obfuscated — no raw quote injection possible
        assert f':password ("{obs}")' in body
        assert '"pass"word"' not in body

    def test_userpass_escapes_realm_quote(self):
        body = _build_userpass("s", 're"alm', "u", "pw")
        assert ':selectedLoginOption ("re\\"alm")' in body

    def test_otp_is_obfuscated(self):
        body = _build_otp_response("s", "123456")
        assert f':user_input ("{_snx_obfuscate("123456")}")' in body
        assert ':user_input ("123456")' not in body

    def test_hello_contains_client_info_block(self):
        body = _build_hello()
        assert ":client_info (" in body
        assert ":client_type (TRAC)" in body


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

    def test_session_id_absent_when_empty(self):
        # When session_id is empty, field must NOT appear (snx-rs sends session_id: None)
        assert "session_id" not in _build_hello()

    def test_session_id_portal_key_included(self):
        h = _build_hello(session_id="abc123portal")
        assert ':session_id ("abc123portal")' in h

    def test_client_info_nesting(self):
        # RequestData must contain nested :client_info block (not flat fields)
        h = _build_hello()
        assert ":client_info (" in h

    def test_no_endpoint_os_in_hello(self):
        # endpoint_os is NOT sent in ClientHello (snx-rs wire format)
        assert "endpoint_os" not in _build_hello()

    def test_no_realm_in_hello(self):
        # selected_realm_id is NOT sent in ClientHello; realm goes in UserPass only
        assert "selected_realm_id" not in _build_hello()

    def test_client_support_saml_true(self):
        assert ":client_support_saml (true)" in _build_hello()


class TestBuildUserpass:
    def test_contains_username_obfuscated(self):
        body = _build_userpass("sess", "realm", "alice", "pw")
        assert f':username ("{_snx_obfuscate("alice")}")' in body

    def test_contains_password_obfuscated(self):
        body = _build_userpass("sess", "realm", "alice", "hunter2")
        assert f':password ("{_snx_obfuscate("hunter2")}")' in body

    def test_empty_credentials_produce_empty_hex(self):
        # Empty string obfuscates to "" — portal resume sends empty-credential UserPass
        body = _build_userpass("sess", "", "", "")
        assert ':username ("")' in body
        assert ':password ("")' in body

    def test_contains_realm(self):
        body = _build_userpass("sess", "my_realm", "u", "p")
        assert ':selectedLoginOption ("my_realm")' in body

    def test_realm_omitted_when_empty(self):
        body = _build_userpass("sess", "", "u", "p")
        assert "selectedLoginOption" not in body

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

    def test_contains_client_logging_data(self):
        body = _build_userpass("s", "r", "u", "p")
        assert ":client_logging_data (" in body
        assert ":os_name (Windows)" in body
        assert ":device_id (" in body

    def test_no_endpoint_os_in_userpass(self):
        # endpoint_os is None in snx-rs AuthRequest — must not appear
        body = _build_userpass("s", "r", "u", "p")
        assert "endpoint_os" not in body


class TestBuildOtpResponse:
    def test_contains_user_input_obfuscated(self):
        body = _build_otp_response("sess", "123456")
        assert f':user_input ("{_snx_obfuscate("123456")}")' in body
        assert ':user_input ("123456")' not in body

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
        assert "Enter token" in otp_received[0]

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
            f"\t\t:active_key ({_snx_obfuscate(active_key)})\n"
            "\t)\n"
            ")\n"
        )
        self._setup_open(ca, [_hello_resp(rc=502), rc600_success])
        result = ca.authenticate("u", "p", "r")
        assert result == active_key

    def test_challenge_response_rc600_authn_done_returns_active_key(self):
        """ChallengeResponse: rc=600 + authn_status=done is a success (observed in the wild).

        ug.vpn.rt.ru returns rc=600 + authn_status=done + active_key in ChallengeResponse.
        The old code only checked rc==0 and discarded the active_key with an error message.
        """
        ca = _ccc_auth()
        active_key = "714f1c01" * 8
        rc600_otp_success = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (2)\n"
            "\t\t:type (ChallengeResponse)\n"
            '\t\t:session_id ("s42")\n'
            "\t\t:return_code (600)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            "\t\t:authn_status (done)\n"
            "\t\t:is_authenticated (true)\n"
            f"\t\t:active_key ({_snx_obfuscate(active_key)})\n"
            "\t)\n"
            ")\n"
        )
        self._setup_open(ca, [
            _hello_resp(rc=600),
            _otp_challenge_resp(session_id="s42", challenge="password: "),
            rc600_otp_success,
        ])
        result = ca.authenticate(
            "u", "p", "r",
            otp_callback=lambda _: "123456",
        )
        assert result == active_key

    def test_otp_challenge_prompt_deobfuscated(self):
        """Obfuscated hex prompt from server is decoded to readable text before callback."""
        ca = _ccc_auth()
        # '771c203726313a372e5d' obfuscates to 'password: '
        otp_resp_with_hex_prompt = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (1)\n"
            '\t\t:session_id ("s1")\n'
            "\t\t:return_code (5)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            '\t\t:prompt ("771c203726313a372e5d")\n'
            "\t)\n"
            ")\n"
        )
        self._setup_open(ca, [
            _hello_resp(rc=502),
            otp_resp_with_hex_prompt,
            _auth_success_resp(),
        ])
        prompts_received = []
        ca.authenticate(
            "u", "p", "r",
            otp_callback=lambda p: (prompts_received.append(p), "000000")[1],
        )
        assert prompts_received, "callback was called"
        # "password:" prompt from server must be normalised to friendly label
        assert prompts_received[0] == "CCC Authentication code"
        assert "771c203726313a372e5d" not in prompts_received[0]

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
        # Third POST must contain the real username (obfuscated)
        assert f':username ("{_snx_obfuscate("u")}")' in posted[2]

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
        assert f':username ("{_snx_obfuscate("u")}")' in posted[1]

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

    # ── OTP retry on rc=600 + authn_status=continue ─────────────────────

    def test_otp_retry_rc600_continue_prompts_user_and_succeeds(self):
        """rc=600 + authn_status=continue after OTP → server issues a new session_id
        and we re-ask the user for a fresh OTP code (ug.vpn.rt.ru pattern).

        Real server behaviour (confirmed from live logs):
        - ResponseHeader contains the OLD session_id
        - ResponseData contains the NEW session_id to use for the retry request
        The code must extract from ResponseData, not ResponseHeader.
        """
        ca = _ccc_auth()
        active_key = "aabbccdd" * 8
        obs_key = _snx_obfuscate(active_key)

        # Mirrors ug.vpn.rt.ru: old session in Header, NEW session in ResponseData.
        rc600_continue = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (2)\n"
            '\t\t:session_id ("old_session")\n'   # old — must NOT be used for retry
            "\t\t:return_code (600)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            "\t\t:authn_status (continue)\n"
            "\t\t:auth_state (failed_attempt)\n"
            '\t\t:session_id ("new_retry_session")\n'  # new — MUST be used for retry
            "\t)\n"
            ")\n"
        )
        rc0_success = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (3)\n"
            '\t\t:session_id ("new_retry_session")\n'
            "\t\t:return_code (0)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            f"\t\t:active_key ({obs_key})\n"
            "\t\t:authn_status (done)\n"
            "\t)\n"
            ")\n"
        )

        prompts: list[str] = []
        otp_values = ["111111", "222222"]  # first=wrong, second=correct

        def otp_callback(prompt: str) -> str:
            prompts.append(prompt)
            return otp_values.pop(0)

        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="s1"),  # UserPass → OTP challenge
            rc600_continue,                          # ChallengeResponse 1 → wrong OTP
            rc0_success,                             # ChallengeResponse 2 → success
        ])
        result = ca.authenticate("u", "p", "r", otp_callback=otp_callback)
        assert result == active_key
        # Callback must have been called twice: initial OTP + retry
        assert len(prompts) == 2

    def test_otp_retry_rc600_continue_user_cancels_retry_returns_none(self):
        """If user cancels the retry OTP dialog, authenticate() returns None."""
        ca = _ccc_auth()

        rc600_continue = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (2)\n"
            '\t\t:session_id ("old_sess")\n'
            "\t\t:return_code (600)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            "\t\t:authn_status (continue)\n"
            "\t\t:auth_state (failed_attempt)\n"
            '\t\t:session_id ("new_retry_sess")\n'
            "\t)\n"
            ")\n"
        )
        call_count = 0

        def otp_callback(prompt: str) -> str | None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "111111"  # first OTP — will be rejected
            return None  # user cancels retry

        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="s1"),
            rc600_continue,
        ])
        result = ca.authenticate("u", "p", "r", otp_callback=otp_callback)
        assert result is None
        assert call_count == 2, "callback should have been called twice"

    def test_otp_retry_rc600_continue_no_callback_returns_none(self):
        """If rc=600+continue but no callback available, return None (no retry possible)."""
        ca = _ccc_auth()

        rc600_continue = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (2)\n"
            '\t\t:session_id ("s")\n'
            "\t\t:return_code (600)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            "\t\t:authn_status (continue)\n"
            "\t)\n"
            ")\n"
        )
        # cached_otp used as first OTP (no callback)
        self._setup_open(ca, [
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="s"),
            rc600_continue,
        ])
        result = ca.authenticate("u", "p", "r", cached_otp="111111")
        assert result is None

    def test_otp_retry_uses_new_session_id_from_responsedata(self):
        """Retry must use session_id from ResponseData, NOT from ResponseHeader.

        Real server (ug.vpn.rt.ru) structure on rc=600+continue:
          ResponseHeader.session_id = OLD (the original UserPass session)
          ResponseData.session_id   = NEW (must be used for the retry request)
        Using the old session_id from ResponseHeader causes rc=601 (session expired).
        """
        ca = _ccc_auth()
        active_key = "cafebabe" * 8
        obs_key = _snx_obfuscate(active_key)

        posted_bodies: list[str] = []
        old_session_id = "OLD_SESSION_IN_HEADER"
        new_session_id = "NEW_SESSION_IN_RESPONSEDATA"

        # Header has OLD, ResponseData has NEW — retry must use NEW.
        rc600_continue = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (2)\n"
            f'\t\t:session_id ("{old_session_id}")\n'   # old — must NOT be used
            "\t\t:return_code (600)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            "\t\t:authn_status (continue)\n"
            "\t\t:auth_state (failed_attempt)\n"
            f'\t\t:session_id ("{new_session_id}")\n'   # new — MUST be used
            "\t)\n"
            ")\n"
        )
        rc0_success = (
            "(CCCserverResponse\n"
            "\t:ResponseHeader (\n"
            "\t\t:id (3)\n"
            "\t\t:return_code (0)\n"
            "\t)\n"
            "\t:ResponseData (\n"
            f"\t\t:active_key ({obs_key})\n"
            "\t\t:authn_status (done)\n"
            "\t)\n"
            ")\n"
        )

        responses = iter([
            _hello_resp(rc=502),
            _otp_challenge_resp(session_id="initial_session"),
            rc600_continue,
            rc0_success,
        ])

        def fake_post(body: str) -> str | None:
            posted_bodies.append(body)
            return next(responses, None)

        ca._post_ccc = fake_post  # type: ignore[method-assign]
        result = ca.authenticate("u", "p", "r", otp_callback=lambda _: "222222")
        assert result == active_key
        assert len(posted_bodies) == 4
        # The 4th POST must use the NEW session_id from ResponseData.
        assert new_session_id in posted_bodies[3], (
            "retry ChallengeResponse must use session_id from ResponseData, not ResponseHeader"
        )
        # Sanity-check: must NOT use the old session_id from ResponseHeader.
        assert old_session_id not in posted_bodies[3], (
            "retry must NOT use the old session_id from ResponseHeader"
        )

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


# ---------------------------------------------------------------------------
# S-expression block extraction helpers
# ---------------------------------------------------------------------------


_HELLO_RESP_WITH_OPTIONS = """\
(CCCserverResponse
  :ResponseHeader (
    :id (0)
    :session_id ("")
    :return_code (500)
  )
  :ResponseData (
    :supported_data_tunnel_protocols (ssl ipsec)
    :login_options_data (
      :login_options_list (
        (
          :id ("vpn_ssl_vpn")
          :display_name ("SSL VPN")
          :show_realm (1)
          :factors (
            (:factor_type ("up"))
          )
        )
        (
          :id ("vpn_USERNAME_RADIUS")
          :display_name ("Username + RADIUS")
          :show_realm (1)
          :factors (
            (:factor_type ("up"))
            (:factor_type ("radius"))
          )
        )
      )
    )
  )
)
"""

_HELLO_RESP_NO_OPTIONS = """\
(CCCserverResponse
  :ResponseHeader (
    :id (0)
    :session_id ("")
    :return_code (502)
  )
  :ResponseData ()
)
"""

_PORTAL_HTML_WITH_REALMS = """\
<html>
<script>
var realmsArrJSON = '[{\\"name\\":\\"realm_A\\",\\"displayName\\":\\"Realm Alpha\\"},{\\"name\\":\\"realm_B\\",\\"displayName\\":\\"Realm Beta\\"}]';
</script>
</html>
"""


class TestExtractSexpBlock:
    def test_simple_key(self) -> None:
        text = ':foo (bar baz)'
        assert _extract_sexp_block(text, "foo") == "bar baz"

    def test_nested_parens(self) -> None:
        text = ':outer (:inner (deep) end)'
        block = _extract_sexp_block(text, "outer")
        assert ":inner" in block
        assert "deep" in block

    def test_missing_key(self) -> None:
        assert _extract_sexp_block("no key here", "missing") == ""

    def test_unclosed_paren(self) -> None:
        assert _extract_sexp_block(":key (unclosed", "key") == ""


class TestSplitSexpItems:
    def test_two_items(self) -> None:
        block = "(a b) (c d)"
        items = _split_sexp_items(block)
        assert len(items) == 2
        assert items[0].strip() == "a b"
        assert items[1].strip() == "c d"

    def test_nested_inner_parens(self) -> None:
        block = "(:id (x) :name (y z)) (:id (p) :name (q))"
        items = _split_sexp_items(block)
        assert len(items) == 2

    def test_empty_block(self) -> None:
        assert _split_sexp_items("") == []


class TestParseLoginOptions:
    def test_two_options_returned(self) -> None:
        options = _parse_login_options(_HELLO_RESP_WITH_OPTIONS)
        assert len(options) == 2

    def test_ids_correct(self) -> None:
        options = _parse_login_options(_HELLO_RESP_WITH_OPTIONS)
        ids = [o[0] for o in options]
        assert "vpn_ssl_vpn" in ids
        assert "vpn_USERNAME_RADIUS" in ids

    def test_display_names_correct(self) -> None:
        options = _parse_login_options(_HELLO_RESP_WITH_OPTIONS)
        by_id = {o[0]: o[1] for o in options}
        assert by_id["vpn_ssl_vpn"] == "SSL VPN"
        assert by_id["vpn_USERNAME_RADIUS"] == "Username + RADIUS"

    def test_no_options_block(self) -> None:
        assert _parse_login_options(_HELLO_RESP_NO_OPTIONS) == []

    def test_empty_string(self) -> None:
        assert _parse_login_options("") == []


class TestDiscoverLoginOptions:
    """Tests for discover_login_options() — mocked network calls."""

    def _make_ccc_resp(self, body: str, status: int = 200):
        raw = body.encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = raw
        mock_resp.status = status
        return mock_resp

    def test_ccc_returns_options(self) -> None:
        """When CCC ClientHello response has login_options_list, return them."""
        mock_resp = self._make_ccc_resp(_HELLO_RESP_WITH_OPTIONS)

        with patch("snxui.core.ccc_auth.urllib.request.OpenerDirector.open",
                   return_value=mock_resp):
            options = discover_login_options("vpn.example.com", 443, False)

        assert len(options) == 2
        assert options[0][0] == "vpn_ssl_vpn"

    def test_ccc_no_options_fallback_to_portal(self) -> None:
        """When CCC returns no login_options_list, fall back to portal HTML."""
        ccc_resp = self._make_ccc_resp(_HELLO_RESP_NO_OPTIONS)
        portal_resp = self._make_ccc_resp(_PORTAL_HTML_WITH_REALMS)

        call_count = [0]

        def _fake_open(req, timeout=10):
            call_count[0] += 1
            if call_count[0] == 1:
                return ccc_resp  # first call = CCC
            return portal_resp  # second call = portal HTML

        with patch("snxui.core.ccc_auth.urllib.request.OpenerDirector.open", side_effect=_fake_open):
            options = discover_login_options("vpn.example.com", 443, False)

        assert len(options) == 2
        ids = [o[0] for o in options]
        assert "realm_A" in ids
        assert "realm_B" in ids

    def test_network_error_returns_empty(self) -> None:
        """Network errors produce an empty list, not an exception."""
        with patch("snxui.core.ccc_auth.urllib.request.OpenerDirector.open",
                   side_effect=OSError("unreachable")):
            options = discover_login_options("bad.host", 443, True)

        assert options == []

    def test_ccc_error_portal_also_fails_returns_empty(self) -> None:
        """Both CCC and portal fail → empty list."""
        with patch("snxui.core.ccc_auth.urllib.request.OpenerDirector.open",
                   side_effect=OSError("connection refused")):
            options = discover_login_options("vpn.example.com", 443, False)

        assert options == []
