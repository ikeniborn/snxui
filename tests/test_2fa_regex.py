"""Tests for 2FA regex patterns in snxui.core.snx_backend."""
from __future__ import annotations

import pytest

from snxui.core.snx_backend import (
    _RE_2FA_RSA,
    _RE_2FA_RADIUS,
    _RE_2FA_CHALLENGE,
    _RE_2FA_GENERIC,
    _RE_2FA_ANY,
)


class TestRSAPattern:
    @pytest.mark.parametrize("text", [
        "Enter SecurID PASSCODE:",
        "enter securid passcode:",  # case-insensitive
        "SecurID passcode:",
        "PASSCODE:",
    ])
    def test_matches(self, text: str) -> None:
        assert _RE_2FA_RSA.search(text), f"Expected match for: {text!r}"

    @pytest.mark.parametrize("text", [
        "Password:",
        "Enter password:",
        "Token:",
        "OTP:",
    ])
    def test_no_match(self, text: str) -> None:
        assert not _RE_2FA_RSA.search(text), f"Unexpected match for: {text!r}"


class TestRADIUSPattern:
    @pytest.mark.parametrize("text", [
        "Enter RADIUS token:",
        "Enter RADIUS passcode:",
        "RADIUS token:",
        "RADIUS passcode:",
        "Token:",
    ])
    def test_matches(self, text: str) -> None:
        assert _RE_2FA_RADIUS.search(text), f"Expected match for: {text!r}"

    @pytest.mark.parametrize("text", [
        "Password:",
        "Enter password:",
        "OTP:",
        "Verification code:",
    ])
    def test_no_match(self, text: str) -> None:
        assert not _RE_2FA_RADIUS.search(text), f"Unexpected match for: {text!r}"


class TestChallengePattern:
    @pytest.mark.parametrize("text", [
        "Challenge: DEADBEEF",
        "challenge: ABC123",  # case-insensitive
        "Your challenge is: FFEEDDCC",
        "Enter response:",
    ])
    def test_matches(self, text: str) -> None:
        assert _RE_2FA_CHALLENGE.search(text), f"Expected match for: {text!r}"

    @pytest.mark.parametrize("text", [
        "Password:",
        "Enter password:",
        "Token:",
        "Challenge:",  # no value after colon
    ])
    def test_no_match(self, text: str) -> None:
        assert not _RE_2FA_CHALLENGE.search(text), f"Unexpected match for: {text!r}"


class TestGenericPattern:
    @pytest.mark.parametrize("text", [
        "Enter one-time password:",
        "Enter one-time code:",
        "Verification code:",
        "OTP:",
        "Two-factor code:",
        "Two factor code:",  # dot matches space
    ])
    def test_matches(self, text: str) -> None:
        assert _RE_2FA_GENERIC.search(text), f"Expected match for: {text!r}"

    @pytest.mark.parametrize("text", [
        "Password:",
        "Enter password:",
        "PASSCODE:",
        "Token:",
    ])
    def test_no_match(self, text: str) -> None:
        assert not _RE_2FA_GENERIC.search(text), f"Unexpected match for: {text!r}"


class TestAnyPattern:
    """_RE_2FA_ANY should match anything matched by the individual patterns."""

    @pytest.mark.parametrize("text", [
        # RSA SecurID
        "Enter SecurID PASSCODE:",
        "PASSCODE:",
        # RADIUS
        "Enter RADIUS token:",
        "Token:",
        # Challenge-Response
        "Challenge: DEADBEEF",
        "Enter response:",
        # Generic OTP
        "Verification code:",
        "OTP:",
        "Two-factor code:",
        "Enter one-time password:",
    ])
    def test_matches_all_2fa_types(self, text: str) -> None:
        assert _RE_2FA_ANY.search(text), f"Expected _RE_2FA_ANY to match: {text!r}"

    def test_password_prompt_not_matched(self) -> None:
        assert not _RE_2FA_ANY.search("Password:")

    def test_enter_password_not_matched(self) -> None:
        assert not _RE_2FA_ANY.search("Enter password:")

    def test_snx_connected_not_matched(self) -> None:
        assert not _RE_2FA_ANY.search("SNX - Connected.")

    def test_auth_failed_not_matched(self) -> None:
        assert not _RE_2FA_ANY.search("Authentication failed")

    def test_case_insensitive(self) -> None:
        assert _RE_2FA_ANY.search("verification CODE:")
        assert _RE_2FA_ANY.search("ENTER RESPONSE:")
        assert _RE_2FA_ANY.search("otp:")
