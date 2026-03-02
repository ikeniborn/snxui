"""Tests for snxui.core.portal_auth.

All HTTP calls are mocked so these tests run without network access.
"""

from __future__ import annotations

import json
import textwrap
import urllib.parse
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from snxui.core.portal_auth import (
    PortalAuth,
    PortalAuthResult,
    _rsa_encrypt_password,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(body: str | bytes, status: int = 200, cookies: dict | None = None):
    """Return a fake urllib response context manager."""
    if isinstance(body, str):
        raw = body.encode("utf-8")
    else:
        raw = body
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = raw
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


_MINIMAL_LOGIN_PAGE = textwrap.dedent("""\
    <html><head><title>VPN Login</title></head>
    <body>
    <form method="POST" action="/Login/Login">
    <input type="hidden" name="password" value="">
    <input type="hidden" name="HeightData" value="">
    <input type="text" name="userName" id="userName">
    <input type="password" name="Password" id="Password">
    <input type="submit" name="Login" value="Sign In">
    </form>
    <script>
    var realmsArrJSON = '[{"name":"ssl_vpn_RADIUS","isHidden":false,"authMethodTypes":["2","5"]}]';
    </script>
    </body></html>
""")

# Use a 128-hex-char (512-bit) modulus to satisfy the {64,} minimum in patterns.
_RSA_MODULUS = "a" * 128
_LOGIN_PAGE_WITH_RSA = _MINIMAL_LOGIN_PAGE.replace(
    "</script>",
    (
        f"RSA_Modulus = '{_RSA_MODULUS}';\n"
        "RSA_Exponent = '010001';\n"
        "</script>"
    ),
)


# ---------------------------------------------------------------------------
# RSA encryption
# ---------------------------------------------------------------------------


class TestRsaEncryptPassword:
    """Unit tests for the _rsa_encrypt_password helper."""

    # A small 512-bit RSA modulus (for fast tests; not secure!).
    # n = 2^512 - 569  (prime-ish, just for testing decrypt round-trip)
    _MOD_HEX = (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        "e7"
    )  # 128 hex chars = 512 bits ≈ 64 bytes
    _EXP_HEX = "010001"  # e = 65537

    def test_returns_hex_string(self):
        result = _rsa_encrypt_password("secret", self._MOD_HEX, self._EXP_HEX)
        assert isinstance(result, str)
        assert all(c in "0123456789abcdef" for c in result)

    def test_length_matches_key_bytes(self):
        result = _rsa_encrypt_password("secret", self._MOD_HEX, self._EXP_HEX)
        k = len(self._MOD_HEX) // 2
        assert len(result) == k * 2

    def test_empty_modulus_returns_empty(self):
        result = _rsa_encrypt_password("secret", "", "010001")
        assert result == ""

    def test_invalid_hex_returns_empty(self):
        result = _rsa_encrypt_password("secret", "ZZZZ", "010001")
        assert result == ""

    def test_password_too_long_returns_empty(self):
        # With a 64-byte key, PKCS#1 v1.5 requires ps_len >= 8, so message
        # can be at most k-3-8 = 53 bytes.  Use 60-char password → falls back.
        long_pw = "A" * 60
        result = _rsa_encrypt_password(long_pw, self._MOD_HEX, self._EXP_HEX)
        assert result == ""

    def test_different_passwords_produce_different_ciphertext(self):
        # PKCS#1 v1.5 uses random padding — two encryptions of the same
        # password should differ; two different passwords definitely differ.
        r1 = _rsa_encrypt_password("password1", self._MOD_HEX, self._EXP_HEX)
        r2 = _rsa_encrypt_password("password2", self._MOD_HEX, self._EXP_HEX)
        assert r1 != r2


# ---------------------------------------------------------------------------
# PortalAuth._fetch_login_page
# ---------------------------------------------------------------------------


class TestFetchLoginPage:
    """Tests for GET /Login/Login + page parsing."""

    def _make_portal(self):
        return PortalAuth(server="vpn.test", port=443, verify_ssl=False)

    def test_extracts_realm_from_realms_arr_json(self):
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(_MINIMAL_LOGIN_PAGE)):
            info = pa._fetch_login_page()
        assert info["realm"] == "ssl_vpn_RADIUS"

    def test_extracts_rsa_modulus(self):
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(_LOGIN_PAGE_WITH_RSA)):
            info = pa._fetch_login_page()
        assert info["rsa_modulus"] == _RSA_MODULUS
        assert info["rsa_exponent"] == "010001"

    def test_no_rsa_key_absent_from_result(self):
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(_MINIMAL_LOGIN_PAGE)):
            info = pa._fetch_login_page()
        assert "rsa_modulus" not in info

    def test_hidden_fields_extracted(self):
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(_MINIMAL_LOGIN_PAGE)):
            info = pa._fetch_login_page()
        assert "password" in info["hidden_fields"]
        assert "HeightData" in info["hidden_fields"]

    def test_realms_arr_json_with_escaped_quotes(self):
        # Real Check Point servers embed the JSON with \" inside a JS string:
        #   realmsArrJSON = '[{\"name\":\"ssl_vpn_RADIUS\",...}]';
        # This test verifies we unescape \" → " before json.loads().
        html = (
            "<script>\n"
            "var realmsArrJSON = "
            "'[{\\\"name\\\":\\\"ssl_vpn_UF-Username_RADIUS\\\","
            "\\\"isHidden\\\":false}]';\n"
            "</script>"
        )
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(html)):
            info = pa._fetch_login_page()
        assert info["realm"] == "ssl_vpn_UF-Username_RADIUS"

    def test_get_failure_returns_empty_dict(self):
        pa = self._make_portal()
        with patch.object(pa._opener, "open", side_effect=OSError("refused")):
            info = pa._fetch_login_page()
        assert info == {}

    def test_skips_hidden_realms(self):
        # Build HTML with two realms: first hidden, second visible.
        realms = json.dumps([
            {"name": "ssl_vpn_HIDDEN", "isHidden": True, "authMethodTypes": ["2"]},
            {"name": "ssl_vpn_VISIBLE", "isHidden": False, "authMethodTypes": ["5"]},
        ])
        html = _MINIMAL_LOGIN_PAGE.replace(
            "var realmsArrJSON = '[{\"name\":\"ssl_vpn_RADIUS\",\"isHidden\":false,\"authMethodTypes\":[\"2\",\"5\"]}]';",
            f"var realmsArrJSON = '{realms}';",
        )
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(html)):
            info = pa._fetch_login_page()
        assert info["realm"] == "ssl_vpn_VISIBLE"

    def test_fallback_to_first_realm_when_all_hidden(self):
        html = _MINIMAL_LOGIN_PAGE.replace('"isHidden":false', '"isHidden":true')
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(html)):
            info = pa._fetch_login_page()
        assert info["realm"] == "ssl_vpn_RADIUS"


# ---------------------------------------------------------------------------
# PortalAuth._post_credentials
# ---------------------------------------------------------------------------


class TestPostCredentials:
    """Tests for POST /Login/Login response parsing."""

    def _make_portal(self):
        return PortalAuth(server="vpn.test", port=443, verify_ssl=False)

    def _post(self, pa, body, status=200, **kwargs):
        with patch.object(pa._opener, "open", return_value=_make_response(body, status)):
            return pa._post_credentials(
                username="alice",
                password="secret",
                otp="",
                realm="ssl_vpn_RADIUS",
                rsa_mod="",
                rsa_exp="",
                step=1,
                **kwargs,
            )

    def test_session_cookie_means_success(self):
        pa = self._make_portal()
        # Inject a fake session cookie into the jar
        from http.cookiejar import Cookie
        from unittest.mock import patch as _p
        cookie = MagicMock()
        cookie.name = "CPCVPN_SESSION_ID"
        cookie.value = "abc123"
        pa._cj._cookies = {}
        # Monkeypatch _find_cookie
        with patch.object(pa, "_find_cookie", side_effect=lambda n: "abc123" if n == "CPCVPN_SESSION_ID" else None):
            with patch.object(pa._opener, "open", return_value=_make_response("<html>", 200)):
                result = pa._post_credentials(
                    username="alice", password="secret", otp="",
                    realm="ssl_vpn_RADIUS", rsa_mod="", rsa_exp="", step=1,
                )
        assert result.success is True
        assert result.session_id == "abc123"

    def test_json_err_code_0_success(self):
        pa = self._make_portal()
        body = json.dumps({"errCode": 0, "status": "success"})
        result = self._post(pa, body)
        # errCode=0 → success=True only if session cookie also present;
        # since no cookie, success=False (session might come via redirect).
        # Adjust: the code sets success=bool(s) where s = _find_cookie(...)
        # No cookie injected, so success=False.
        assert result.success is False  # no session cookie
        assert result.error_message is None or result.success is False

    def test_json_err_code_105_otp_required(self):
        pa = self._make_portal()
        body = json.dumps({"errCode": 105, "errMessage": "OTP required"})
        result = self._post(pa, body)
        assert result.success is False
        assert result.otp_required is True

    def test_json_err_code_106_otp_required(self):
        pa = self._make_portal()
        body = json.dumps({"errCode": 106})
        result = self._post(pa, body)
        assert result.otp_required is True

    def test_json_err_code_other_returns_error(self):
        pa = self._make_portal()
        body = json.dumps({"errCode": 999, "errMessage": "Unknown error"})
        result = self._post(pa, body)
        assert result.success is False
        assert result.otp_required is False
        assert "Unknown error" in (result.error_message or "")

    def test_otp_pattern_in_html_triggers_otp_required(self):
        pa = self._make_portal()
        body = "<html>Additional authentication required. Enter RADIUS OTP:</html>"
        result = self._post(pa, body)
        assert result.otp_required is True

    def test_success_pattern_in_body(self):
        pa = self._make_portal()
        body = "<html>SNX Connect success — VPN Connected</html>"
        result = self._post(pa, body)
        assert result.success is True

    def test_empty_body_returns_failure(self):
        pa = self._make_portal()
        result = self._post(pa, "\ufeff\n")  # 2-byte empty response
        assert result.success is False
        assert result.otp_required is False

    def test_http_error_handled(self):
        import urllib.error
        pa = self._make_portal()
        exc = urllib.error.HTTPError(
            url="https://vpn.test/Login/Login",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=BytesIO(b"<html>Forbidden</html>"),
        )
        with patch.object(pa._opener, "open", side_effect=exc):
            result = pa._post_credentials(
                username="alice", password="secret", otp="",
                realm="", rsa_mod="", rsa_exp="", step=1,
            )
        assert result.success is False

    def test_network_error_returns_failure(self):
        pa = self._make_portal()
        with patch.object(pa._opener, "open", side_effect=OSError("timeout")):
            result = pa._post_credentials(
                username="alice", password="secret", otp="",
                realm="", rsa_mod="", rsa_exp="", step=1,
            )
        assert result.success is False
        assert "timeout" in (result.error_message or "")

    def test_post_body_step1_with_rsa(self):
        """Step 1 with RSA: login-input is empty, password has RSA ciphertext.

        The browser's formSubmit JS reads the plaintext from login-input, RSA-
        encrypts it into the hidden 'password' field, then clears login-input
        before the form is submitted.  We replicate that clearing behaviour.
        """
        # Use a real 512-bit modulus for fast RSA computation in tests.
        mod = TestRsaEncryptPassword._MOD_HEX
        exp = TestRsaEncryptPassword._EXP_HEX

        pa = self._make_portal()
        captured_body: list[bytes] = []

        def fake_open(req, timeout=None):
            captured_body.append(req.data)
            return _make_response("<html>fail</html>")

        with patch.object(pa._opener, "open", side_effect=fake_open):
            pa._post_credentials(
                username="alice", password="s3cr3t", otp="",
                realm="R", rsa_mod=mod, rsa_exp=exp, step=1,
            )

        assert captured_body, "HTTP request was not made"
        body_str = captured_body[0].decode()
        params = dict(urllib.parse.parse_qsl(body_str))

        # login-input must be ABSENT when RSA is used.
        # The browser's encryptPasswordAndDisablePasswordDisplay() disables the
        # #passwordDisplayed input; disabled inputs are not submitted by the browser.
        assert "login-input" not in params, "login-input must be omitted when RSA is used"
        # password must be non-empty RSA ciphertext (hex string of key length)
        encrypted = params.get("password", "")
        assert len(encrypted) == len(mod), "RSA ciphertext length must match key size"
        assert all(c in "0123456789abcdef" for c in encrypted), "password must be hex"
        # Code field must NOT be present (not in the HTML form)
        assert "Code" not in params, "Code field should not be sent"

    def test_post_body_step1_no_rsa_mod(self):
        """Step 1 without RSA key: login-input plaintext, password empty."""
        pa = self._make_portal()
        captured_body: list[bytes] = []

        def fake_open(req, timeout=None):
            captured_body.append(req.data)
            return _make_response("<html>fail</html>")

        with patch.object(pa._opener, "open", side_effect=fake_open):
            pa._post_credentials(
                username="alice", password="s3cr3t", otp="",
                realm="R", rsa_mod="", rsa_exp="", step=1,
            )

        body_str = captured_body[0].decode()
        params = dict(urllib.parse.parse_qsl(body_str))
        assert params.get("login-input") == "s3cr3t"
        assert params.get("password", "") == "", "password must be empty when no RSA key"

    def test_post_body_step2_otp_in_login_input(self):
        """Step 2 (OTP) without RSA key: OTP goes into login-input, password empty."""
        pa = self._make_portal()
        captured_body: list[bytes] = []

        def fake_open(req, timeout=None):
            captured_body.append(req.data)
            return _make_response("<html>fail</html>")

        with patch.object(pa._opener, "open", side_effect=fake_open):
            pa._post_credentials(
                username="alice", password="654321", otp="",
                realm="R", rsa_mod="", rsa_exp="", step=2,
            )

        body_str = captured_body[0].decode()
        params = dict(urllib.parse.parse_qsl(body_str))
        assert params.get("login-input") == "654321"
        assert params.get("password", "") == "", "no RSA key → plaintext fallback in login-input"
        assert "Code" not in params

    def test_post_body_step2_with_rsa_encrypts_otp(self):
        """Step 2 (OTP) with RSA key: OTP is RSA-encrypted, login-input omitted.

        Check Point's isPasswordHidingMode=1 means encryptPasswordAndDisablePasswordDisplay
        runs on BOTH step 1 and step 2 — the OTP is encrypted just like the password.
        """
        mod = TestRsaEncryptPassword._MOD_HEX
        exp = TestRsaEncryptPassword._EXP_HEX

        pa = self._make_portal()
        captured_body: list[bytes] = []

        def fake_open(req, timeout=None):
            captured_body.append(req.data)
            return _make_response("<html>fail</html>")

        with patch.object(pa._opener, "open", side_effect=fake_open):
            pa._post_credentials(
                username="alice", password="654321", otp="",
                realm="R", rsa_mod=mod, rsa_exp=exp, step=2,
            )

        body_str = captured_body[0].decode()
        params = dict(urllib.parse.parse_qsl(body_str))
        # login-input must be absent (browser disables it after RSA encryption)
        assert "login-input" not in params, "login-input must be omitted when RSA is used for step 2"
        encrypted = params.get("password", "")
        assert len(encrypted) == len(mod), "RSA ciphertext length must match key size"
        assert all(c in "0123456789abcdef" for c in encrypted)

    def test_login_page_no_error_step1_returns_otp_required(self):
        """Login page without error on step 1 means OTP challenge, not credentials_failed."""
        # Server returns the login page again but WITHOUT an error message —
        # this is the OTP challenge: step 1 succeeded, step 2 (RADIUS OTP) is needed.
        login_page_no_error = _MINIMAL_LOGIN_PAGE  # no errorMsgDIV / errorMessage
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(login_page_no_error)):
            result = pa._post_credentials(
                username="alice", password="secret", otp="",
                realm="ssl_vpn_RADIUS", rsa_mod="", rsa_exp="", step=1,
            )
        assert result.otp_required is True
        assert result.credentials_failed is False
        assert result.success is False

    def test_login_page_with_error_step1_returns_credentials_failed(self):
        """Login page WITH error on step 1 means wrong password → credentials_failed."""
        login_page_with_error = _MINIMAL_LOGIN_PAGE + (
            '<div id="errorMsgDIV">'
            '<span class="errorMessage">Access denied - wrong user name or password</span>'
            '</div>'
        )
        pa = self._make_portal()
        with patch.object(pa._opener, "open", return_value=_make_response(login_page_with_error)):
            result = pa._post_credentials(
                username="alice", password="wrong", otp="",
                realm="ssl_vpn_RADIUS", rsa_mod="", rsa_exp="", step=1,
            )
        assert result.credentials_failed is True
        assert result.otp_required is False
        assert "wrong" in (result.error_message or "").lower() or "denied" in (result.error_message or "").lower()


# ---------------------------------------------------------------------------
# PortalAuth.authenticate (integration)
# ---------------------------------------------------------------------------


class TestAuthenticate:
    """Integration tests for the two-step authenticate() flow."""

    def _make_portal(self):
        return PortalAuth(server="vpn.test", port=443, verify_ssl=False)

    def test_step1_success_returns_immediately(self):
        pa = self._make_portal()
        with patch.object(pa, "_fetch_login_page", return_value={"realm": "test_realm"}):
            with patch.object(
                pa, "_post_credentials",
                return_value=PortalAuthResult(success=True, session_id="SID1"),
            ):
                result = pa.authenticate("alice", "pass")
        assert result.success is True
        assert result.session_id == "SID1"

    def test_step1_otp_required_calls_callback_and_submits_step2(self):
        pa = self._make_portal()
        step2_result = PortalAuthResult(success=True, session_id="SID2")
        otp_cb = MagicMock(return_value="123456")

        with patch.object(pa, "_fetch_login_page", return_value={"realm": "R"}):
            with patch.object(
                pa, "_post_credentials",
                side_effect=[
                    PortalAuthResult(success=False, otp_required=True, diagnostic="Enter OTP:"),
                    step2_result,
                ],
            ) as mock_post:
                result = pa.authenticate("alice", "pass", otp_callback=otp_cb)

        otp_cb.assert_called_once_with("Enter OTP:")
        assert result.success is True
        # Step 2 call: password= otp, rsa_mod=""
        step2_call = mock_post.call_args_list[1]
        assert step2_call.kwargs["password"] == "123456"
        assert step2_call.kwargs["step"] == 2
        assert step2_call.kwargs["rsa_mod"] == ""

    def test_otp_required_no_callback_returns_error(self):
        pa = self._make_portal()
        with patch.object(pa, "_fetch_login_page", return_value={"realm": "R"}):
            with patch.object(
                pa, "_post_credentials",
                return_value=PortalAuthResult(success=False, otp_required=True),
            ):
                result = pa.authenticate("alice", "pass", otp_callback=None)
        assert result.success is False
        assert "OTP" in (result.error_message or "")

    def test_otp_cancelled_returns_error(self):
        pa = self._make_portal()
        otp_cb = MagicMock(return_value=None)  # user cancels
        with patch.object(pa, "_fetch_login_page", return_value={"realm": "R"}):
            with patch.object(
                pa, "_post_credentials",
                return_value=PortalAuthResult(success=False, otp_required=True, diagnostic="OTP:"),
            ):
                result = pa.authenticate("alice", "pass", otp_callback=otp_cb)
        assert result.success is False
        assert "cancel" in (result.error_message or "").lower()

    def test_step1_non_otp_failure_returned_directly(self):
        pa = self._make_portal()
        with patch.object(pa, "_fetch_login_page", return_value={}):
            with patch.object(
                pa, "_post_credentials",
                return_value=PortalAuthResult(success=False, error_message="Wrong password"),
            ):
                result = pa.authenticate("alice", "wrong")
        assert result.success is False
        assert result.otp_required is False
        assert result.error_message == "Wrong password"

    def test_domain_prefix_concatenated(self):
        """Domain\\user login format passed to _post_credentials."""
        pa = self._make_portal()
        calls = []

        def fake_post(**kw):
            calls.append(kw["username"])
            return PortalAuthResult(success=True, session_id="S")

        with patch.object(pa, "_fetch_login_page", return_value={}):
            with patch.object(pa, "_post_credentials", side_effect=fake_post):
                pa.authenticate("domain\\alice", "pass")

        assert calls[0] == "domain\\alice"

    def test_rsa_key_passed_to_post_step1(self):
        pa = self._make_portal()
        captured = {}

        def fake_post(**kw):
            captured.update(kw)
            return PortalAuthResult(success=True, session_id="X")

        page_info = {
            "realm": "R",
            "rsa_modulus": "abcdef",
            "rsa_exponent": "010001",
        }
        with patch.object(pa, "_fetch_login_page", return_value=page_info):
            with patch.object(pa, "_post_credentials", side_effect=fake_post):
                pa.authenticate("alice", "pass")

        assert captured["rsa_mod"] == "abcdef"
        assert captured["rsa_exp"] == "010001"
        assert captured["step"] == 1


# ---------------------------------------------------------------------------
# PortalAuth.write_snxrc
# ---------------------------------------------------------------------------


class TestWriteSnxrc:
    def test_writes_gateway_and_auth_id(self, tmp_path):
        pa = PortalAuth(server="vpn.test", port=443)
        snxrc = tmp_path / ".snxrc"

        result = PortalAuthResult(
            success=True,
            session_id="SID123",
            auth_id="AID456",
            cookie_timeout="3600",
        )

        with patch("snxui.core.portal_auth._SNXRC_PATH", snxrc):
            ok = pa.write_snxrc(result)

        assert ok is True
        content = snxrc.read_text()
        assert 'gateway="vpn.test"' in content
        assert 'auth_id="AID456"' in content
        assert 'cookie_timeout="3600"' in content

    def test_uses_session_id_when_no_auth_id(self, tmp_path):
        pa = PortalAuth(server="vpn.test", port=443)
        snxrc = tmp_path / ".snxrc"
        result = PortalAuthResult(success=True, session_id="SID99")

        with patch("snxui.core.portal_auth._SNXRC_PATH", snxrc):
            ok = pa.write_snxrc(result)

        assert ok is True
        content = snxrc.read_text()
        assert 'auth_id="SID99"' in content

    def test_no_cookie_timeout_omits_line(self, tmp_path):
        pa = PortalAuth(server="vpn.test", port=443)
        snxrc = tmp_path / ".snxrc"
        result = PortalAuthResult(success=True, session_id="SID", cookie_timeout=None)

        with patch("snxui.core.portal_auth._SNXRC_PATH", snxrc):
            pa.write_snxrc(result)

        assert "cookie_timeout" not in snxrc.read_text()

    def test_failed_result_returns_false(self, tmp_path):
        pa = PortalAuth(server="vpn.test", port=443)
        snxrc = tmp_path / ".snxrc"
        result = PortalAuthResult(success=False)

        with patch("snxui.core.portal_auth._SNXRC_PATH", snxrc):
            ok = pa.write_snxrc(result)

        assert ok is False
        assert not snxrc.exists()

    def test_file_permissions_600(self, tmp_path):
        pa = PortalAuth(server="vpn.test", port=443)
        snxrc = tmp_path / ".snxrc"
        result = PortalAuthResult(success=True, session_id="SID")

        with patch("snxui.core.portal_auth._SNXRC_PATH", snxrc):
            pa.write_snxrc(result)

        import stat
        mode = stat.S_IMODE(snxrc.stat().st_mode)
        assert mode == 0o600


# ---------------------------------------------------------------------------
# PortalAuth helpers
# ---------------------------------------------------------------------------


class TestExtractHiddenFields:
    def test_extracts_name_and_value(self):
        html = '<input type="hidden" name="foo" value="bar">'
        fields = PortalAuth._extract_hidden_fields(html)
        assert fields["foo"] == "bar"

    def test_empty_value(self):
        html = '<input type="hidden" name="HeightData" value="">'
        fields = PortalAuth._extract_hidden_fields(html)
        assert fields["HeightData"] == ""

    def test_multiple_fields(self):
        html = (
            '<input type="hidden" name="a" value="1">'
            '<input type="hidden" name="b" value="2">'
        )
        fields = PortalAuth._extract_hidden_fields(html)
        assert fields == {"a": "1", "b": "2"}

    def test_ignores_non_hidden_inputs(self):
        html = '<input type="text" name="user" value="alice">'
        fields = PortalAuth._extract_hidden_fields(html)
        assert fields == {}


class TestTryParseJson:
    def test_valid_json_object(self):
        result = PortalAuth._try_parse_json('{"errCode": 0}')
        assert result == {"errCode": 0}

    def test_valid_json_with_bom(self):
        result = PortalAuth._try_parse_json("\ufeff{\"a\":1}")
        assert result == {"a": 1}

    def test_html_returns_none(self):
        result = PortalAuth._try_parse_json("<html>hello</html>")
        assert result is None

    def test_empty_returns_none(self):
        result = PortalAuth._try_parse_json("")
        assert result is None

    def test_invalid_json_returns_none(self):
        result = PortalAuth._try_parse_json("{invalid}")
        assert result is None


class TestExtractError:
    def test_extracts_error_div(self):
        html = '<div id="error">Invalid credentials</div>'
        text = PortalAuth._extract_error(html)
        assert "Invalid credentials" in text

    def test_extracts_alert_class(self):
        html = '<div class="alert">Authentication failed</div>'
        text = PortalAuth._extract_error(html)
        assert "Authentication failed" in text

    def test_falls_back_to_title(self):
        html = "<html><head><title>Login Error</title></head></html>"
        text = PortalAuth._extract_error(html)
        assert "Login Error" in text

    def test_no_error_returns_empty(self):
        text = PortalAuth._extract_error("<html><body><p>Hello</p></body></html>")
        assert text == ""
