"""Tests for snxui.core.totp — RFC 6238 / RFC 4226 implementation."""
from __future__ import annotations

import base64

import pytest

from snxui.core.totp import _hotp, generate_totp, seconds_remaining


class TestHOTP:
    """RFC 4226 Appendix D test vectors (secret = b"12345678901234567890")."""

    @pytest.fixture()
    def rfc_secret(self) -> str:
        return base64.b32encode(b"12345678901234567890").decode()

    def test_hotp_rfc_counter_0(self, rfc_secret: str) -> None:
        assert _hotp(rfc_secret, 0) == "755224"

    def test_hotp_rfc_counter_1(self, rfc_secret: str) -> None:
        assert _hotp(rfc_secret, 1) == "287082"

    def test_hotp_rfc_counter_9(self, rfc_secret: str) -> None:
        assert _hotp(rfc_secret, 9) == "520489"

    def test_hotp_rfc_vectors_all(self, rfc_secret: str) -> None:
        """Verify multiple RFC 4226 test vectors in a single parametrized sweep."""
        expected = {
            0: "755224",
            1: "287082",
            2: "359152",
            3: "969429",
            4: "338314",
            5: "254676",
            6: "287922",
            7: "162583",
            8: "399871",
            9: "520489",
        }
        for counter, code in expected.items():
            assert _hotp(rfc_secret, counter) == code, f"Counter={counter} failed"

    def test_hotp_output_is_6_digits(self, rfc_secret: str) -> None:
        code = _hotp(rfc_secret, 0)
        assert len(code) == 6
        assert code.isdigit()

    def test_hotp_zero_padded(self) -> None:
        """Codes shorter than 6 digits must be zero-padded."""
        # Use secret that may yield small numeric values at some counter
        secret = base64.b32encode(b"12345678901234567890").decode()
        for counter in range(10):
            code = _hotp(secret, counter)
            assert len(code) == 6

    def test_invalid_secret_raises(self) -> None:
        with pytest.raises(Exception):
            _hotp("NOT_VALID_BASE32!!!", 0)

    def test_lowercase_secret_accepted(self) -> None:
        secret = base64.b32encode(b"12345678901234567890").decode().lower()
        # Should not raise and should match uppercase result
        upper_result = _hotp(secret.upper(), 0)
        lower_result = _hotp(secret, 0)
        assert lower_result == upper_result

    def test_secret_with_spaces_stripped(self) -> None:
        secret = base64.b32encode(b"12345678901234567890").decode()
        result_clean = _hotp(secret, 0)
        result_spaces = _hotp(f"  {secret}  ", 0)
        assert result_clean == result_spaces


class TestTOTP:
    def test_totp_deterministic_with_fixed_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("snxui.core.totp.time.time", lambda: 59.0)
        secret = base64.b32encode(b"12345678901234567890").decode()
        # counter = int(59.0) // 30 = 1
        assert generate_totp(secret) == _hotp(secret, 1)

    def test_totp_uses_correct_counter_at_t30(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("snxui.core.totp.time.time", lambda: 30.0)
        secret = base64.b32encode(b"12345678901234567890").decode()
        # counter = int(30.0) // 30 = 1
        assert generate_totp(secret) == _hotp(secret, 1)

    def test_totp_uses_correct_counter_at_t60(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("snxui.core.totp.time.time", lambda: 60.0)
        secret = base64.b32encode(b"12345678901234567890").decode()
        # counter = int(60.0) // 30 = 2
        assert generate_totp(secret) == _hotp(secret, 2)

    def test_generate_totp_length_and_digits(self) -> None:
        secret = base64.b32encode(b"test_secret_value!").decode()
        code = generate_totp(secret)
        assert len(code) == 6
        assert code.isdigit()

    def test_generate_totp_custom_digits(self) -> None:
        secret = base64.b32encode(b"12345678901234567890").decode()
        code = generate_totp(secret, digits=8)
        assert len(code) == 8
        assert code.isdigit()

    def test_generate_totp_invalid_secret_raises(self) -> None:
        with pytest.raises(Exception):
            generate_totp("NOT_VALID_BASE32!!!")


class TestSecondsRemaining:
    def test_in_range(self) -> None:
        remaining = seconds_remaining()
        assert 0 <= remaining <= 30

    def test_with_fixed_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("snxui.core.totp.time.time", lambda: 35.0)
        # 35 % 30 = 5, so 30 - 5 = 25 seconds remaining
        assert seconds_remaining() == 25

    def test_at_step_boundary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("snxui.core.totp.time.time", lambda: 60.0)
        # 60 % 30 = 0, so 30 - 0 = 30 seconds remaining
        assert seconds_remaining() == 30

    def test_custom_step(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("snxui.core.totp.time.time", lambda: 50.0)
        # 50 % 60 = 50, so 60 - 50 = 10 seconds remaining
        assert seconds_remaining(step=60) == 10
