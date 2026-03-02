"""Tests for snxui.core.profile_manager.

All tests use a temporary directory so they never touch the real
~/.config/snxui/profiles.json file.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from snxui.core.profile_manager import ProfileManager, _profile_to_dict, _profile_from_dict
from snxui.core.types import Profile


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_pm(tmp_path: Path) -> ProfileManager:
    """Return a ProfileManager backed by a temporary directory."""
    return ProfileManager(profiles_path=tmp_path / "profiles.json")


@pytest.fixture()
def sample_profile() -> Profile:
    """Return a minimal valid Profile."""
    return Profile(name="Test VPN", server="vpn.example.com", username="alice")


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_profile_to_dict_all_fields(self, sample_profile: Profile) -> None:
        d = _profile_to_dict(sample_profile)
        assert d["server"] == "vpn.example.com"
        assert d["username"] == "alice"
        assert d["ssl_port"] == 443
        assert d["certificate"] is None
        assert d["cipher"] is None

    def test_profile_from_dict_round_trip(self, sample_profile: Profile) -> None:
        d = _profile_to_dict(sample_profile)
        restored = _profile_from_dict(d)
        assert restored.id == sample_profile.id
        assert restored.server == sample_profile.server
        assert restored.username == sample_profile.username

    def test_profile_from_dict_ignores_unknown_keys(self) -> None:
        """Forward-compatible: unknown keys from newer versions must not crash."""
        d = {
            "id": "abc",
            "name": "x",
            "server": "s",
            "username": "u",
            "ssl_port": 443,
            "ca_list": "/etc/ssl/certs",
            "certificate": None,
            "reauth": True,
            "save_password": False,
            "cipher": None,
            "future_field_v2": "some_value",  # unknown
        }
        p = _profile_from_dict(d)
        assert p.server == "s"

    def test_json_file_is_readable_json(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        raw = json.loads(tmp_pm._path.read_text())
        assert "profiles" in raw
        assert "version" in raw
        assert sample_profile.id in raw["profiles"]

    def test_load_raw_recovers_from_null_profiles(self, tmp_pm: ProfileManager) -> None:
        """'profiles': null in JSON must not crash list_all() — resets to empty dict."""
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text(
            json.dumps({"version": 1, "default_id": None, "profiles": None}),
            encoding="utf-8",
        )
        assert tmp_pm.list_all() == []

    def test_load_raw_recovers_from_list_profiles(self, tmp_pm: ProfileManager) -> None:
        """'profiles': [] (list instead of dict) must not crash — resets to empty dict."""
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text(
            json.dumps({"version": 1, "default_id": None, "profiles": []}),
            encoding="utf-8",
        )
        assert tmp_pm.list_all() == []

    def test_load_raw_recovers_from_non_dict_root(self, tmp_pm: ProfileManager) -> None:
        """A JSON array at root level must not crash — resets entire store."""
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text("[1, 2, 3]", encoding="utf-8")
        assert tmp_pm.list_all() == []

    def test_tmp_file_cleaned_up_on_replace_failure(
        self, tmp_pm: ProfileManager, sample_profile: Profile
    ) -> None:
        """_save_raw must delete the staging .tmp file when replace() raises OSError.

        Without the finally-block fix, a failed atomic rename leaves
        profiles.tmp on disk.  A subsequent successful write would then
        produce a valid profiles.json AND a stale profiles.tmp, which
        could confuse future reads or manual inspection.
        """
        tmp_pm.create(sample_profile)  # creates profiles.json normally
        sample_profile.name = "Updated"
        with patch("pathlib.Path.replace", side_effect=OSError("disk full")):
            with pytest.raises(OSError):
                tmp_pm.update(sample_profile)
        # After the failed rename the staging file must be gone.
        assert not tmp_pm._path.with_suffix(".tmp").exists()

    def test_profile_from_dict_null_id_gets_uuid(self, tmp_pm: ProfileManager) -> None:
        """Profile with 'id': null must get a fresh UUID — not id=None.

        A None id cannot be used as a JSON object key (json.dump raises
        TypeError), making the profile permanently uneditable/undeletable.
        """
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text(
            json.dumps({
                "version": 1,
                "default_id": None,
                "profiles": {
                    "some-key": {
                        "id": None,
                        "name": "Broken",
                        "server": "s.example.com",
                        "username": "u",
                    }
                },
            }),
            encoding="utf-8",
        )
        profiles = tmp_pm.list_all()
        assert len(profiles) == 1
        assert isinstance(profiles[0].id, str)
        assert profiles[0].id  # non-empty

    def test_profile_from_dict_nonnumeric_ssl_port_falls_back_to_443(self) -> None:
        """ValueError from int("not_a_number") must silently reset ssl_port to 443.

        Exercises the ``except (TypeError, ValueError)`` branch in
        ``_profile_from_dict`` (profile_manager.py lines 76-79).  Without the
        except clause a corrupted profiles.json would crash on load instead of
        recovering gracefully.
        """
        d = {
            "id": "abc",
            "name": "x",
            "server": "s",
            "username": "u",
            "ssl_port": "not_a_number",  # str → int("not_a_number") raises ValueError
        }
        p = _profile_from_dict(d)
        assert p.ssl_port == 443

    def test_profile_from_dict_null_ssl_port_falls_back_to_443(self) -> None:
        """TypeError from int(None) must silently reset ssl_port to 443.

        Exercises the same ``except (TypeError, ValueError)`` branch as
        ``test_profile_from_dict_nonnumeric_ssl_port_falls_back_to_443`` but
        via a JSON null value (``"ssl_port": null``) which passes None to int().
        """
        d = {
            "id": "abc",
            "name": "x",
            "server": "s",
            "username": "u",
            "ssl_port": None,  # None → int(None) raises TypeError
        }
        p = _profile_from_dict(d)
        assert p.ssl_port == 443

    def test_profile_from_dict_empty_id_gets_uuid(self, tmp_pm: ProfileManager) -> None:
        """Profile with 'id': '' must get a fresh UUID — empty string id
        cannot be matched against any UUID key in the profiles dict."""
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text(
            json.dumps({
                "version": 1,
                "default_id": None,
                "profiles": {
                    "some-key": {
                        "id": "",
                        "name": "Broken",
                        "server": "s.example.com",
                        "username": "u",
                    }
                },
            }),
            encoding="utf-8",
        )
        profiles = tmp_pm.list_all()
        assert len(profiles) == 1
        assert isinstance(profiles[0].id, str)
        assert profiles[0].id  # non-empty UUID


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------


class TestFreshInstall:
    def test_list_all_works_when_config_dir_absent(self, tmp_path: Path) -> None:
        """ProfileManager must not raise when the config directory does not exist yet.

        On a fresh install ~/.config/snxui/ is absent.  Before the fix,
        _with_file_lock() tried to create the FileLock file before the
        directory existed, raising FileNotFoundError (not caught — only
        Timeout was caught).  This caused list_all() and create() to fail
        silently on first launch.
        """
        # Point to a *subdirectory* that does NOT exist yet.
        pm = ProfileManager(profiles_path=tmp_path / "nonexistent_subdir" / "profiles.json")
        # Must not raise — returns empty list on first run.
        profiles = pm.list_all()
        assert profiles == []

    def test_create_works_when_config_dir_absent(self, tmp_path: Path) -> None:
        """create() must persist a profile even when the config directory is missing."""
        pm = ProfileManager(profiles_path=tmp_path / "nonexistent_subdir" / "profiles.json")
        p = Profile(name="Work", server="vpn.example.com", username="alice")
        pm.create(p)
        assert pm.list_all()[0].server == "vpn.example.com"


class TestCreate:
    def test_create_returns_profile(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        result = tmp_pm.create(sample_profile)
        assert result is sample_profile

    def test_create_persists_to_file(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        assert tmp_pm._path.exists()

    def test_create_duplicate_id_raises(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        with pytest.raises(ValueError, match="already exists"):
            tmp_pm.create(sample_profile)

    def test_create_missing_server_raises(self, tmp_pm: ProfileManager) -> None:
        bad = Profile(name="x", server="", username="u")
        with pytest.raises(ValueError, match="server"):
            tmp_pm.create(bad)

    def test_create_missing_username_raises(self, tmp_pm: ProfileManager) -> None:
        bad = Profile(name="x", server="vpn.example.com", username="")
        with pytest.raises(ValueError, match="username"):
            tmp_pm.create(bad)

    def test_first_profile_becomes_default(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        assert tmp_pm.get_default() is not None
        assert tmp_pm.get_default().id == sample_profile.id  # type: ignore[union-attr]


class TestRead:
    def test_get_existing(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        fetched = tmp_pm.get(sample_profile.id)
        assert fetched is not None
        assert fetched.server == "vpn.example.com"

    def test_get_nonexistent_returns_none(self, tmp_pm: ProfileManager) -> None:
        assert tmp_pm.get("no-such-id") is None

    def test_list_all_empty(self, tmp_pm: ProfileManager) -> None:
        assert tmp_pm.list_all() == []

    def test_list_all_multiple(self, tmp_pm: ProfileManager) -> None:
        p1 = Profile(name="A", server="s1.example.com", username="u1")
        p2 = Profile(name="B", server="s2.example.com", username="u2")
        tmp_pm.create(p1)
        tmp_pm.create(p2)
        profiles = tmp_pm.list_all()
        assert len(profiles) == 2
        ids = {p.id for p in profiles}
        assert p1.id in ids
        assert p2.id in ids


class TestUpdate:
    def test_update_changes_field(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        sample_profile.name = "Updated Name"
        tmp_pm.update(sample_profile)
        fetched = tmp_pm.get(sample_profile.id)
        assert fetched is not None
        assert fetched.name == "Updated Name"

    def test_update_nonexistent_raises(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        with pytest.raises(KeyError):
            tmp_pm.update(sample_profile)

    def test_update_validates(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        sample_profile.server = ""
        with pytest.raises(ValueError):
            tmp_pm.update(sample_profile)


class TestDelete:
    def test_delete_existing(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        result = tmp_pm.delete(sample_profile.id)
        assert result is True
        assert tmp_pm.get(sample_profile.id) is None

    def test_delete_nonexistent_returns_false(self, tmp_pm: ProfileManager) -> None:
        assert tmp_pm.delete("ghost-id") is False

    def test_delete_clears_default(self, tmp_pm: ProfileManager, sample_profile: Profile) -> None:
        tmp_pm.create(sample_profile)
        tmp_pm.delete(sample_profile.id)
        assert tmp_pm.get_default() is None

    def test_delete_reassigns_default(self, tmp_pm: ProfileManager) -> None:
        p1 = Profile(name="A", server="s1.example.com", username="u1")
        p2 = Profile(name="B", server="s2.example.com", username="u2")
        tmp_pm.create(p1)
        tmp_pm.create(p2)
        tmp_pm.delete(p1.id)
        new_default = tmp_pm.get_default()
        assert new_default is not None
        assert new_default.id == p2.id


# ---------------------------------------------------------------------------
# Default profile
# ---------------------------------------------------------------------------


class TestDefault:
    def test_set_and_get_default(self, tmp_pm: ProfileManager) -> None:
        p1 = Profile(name="A", server="s1.example.com", username="u1")
        p2 = Profile(name="B", server="s2.example.com", username="u2")
        tmp_pm.create(p1)
        tmp_pm.create(p2)
        tmp_pm.set_default(p2.id)
        assert tmp_pm.get_default().id == p2.id  # type: ignore[union-attr]

    def test_set_default_nonexistent_raises(self, tmp_pm: ProfileManager) -> None:
        with pytest.raises(KeyError):
            tmp_pm.set_default("ghost-id")

    def test_get_default_empty_store(self, tmp_pm: ProfileManager) -> None:
        assert tmp_pm.get_default() is None


# ---------------------------------------------------------------------------
# 2FA fields — serialisation and migration
# ---------------------------------------------------------------------------


from snxui.core.types import TwoFactorMethod  # noqa: E402 (append to file)


class TestTwoFactorSerialization:
    def test_serialize_two_factor_method_totp(self, sample_profile: Profile) -> None:
        """Profile with TOTP method must round-trip through to/from dict."""
        sample_profile.two_factor_method = TwoFactorMethod.TOTP
        sample_profile.save_totp_secret = True
        d = _profile_to_dict(sample_profile)
        assert d["two_factor_method"] == "totp"
        assert d["save_totp_secret"] is True

        restored = _profile_from_dict(d)
        assert restored.two_factor_method == TwoFactorMethod.TOTP
        assert restored.save_totp_secret is True

    def test_serialize_default_two_factor_method(self, sample_profile: Profile) -> None:
        """Default (NONE) method must serialize as 'none'."""
        d = _profile_to_dict(sample_profile)
        assert d["two_factor_method"] == "none"
        assert d["save_totp_secret"] is False

    def test_deserialize_all_two_factor_methods(self) -> None:
        """All TwoFactorMethod values must round-trip correctly."""
        base_dict = {
            "id": "abc",
            "name": "test",
            "server": "s",
            "username": "u",
            "ssl_port": 443,
            "ca_list": "/etc/ssl/certs",
            "certificate": None,
            "reauth": True,
            "save_password": False,
            "cipher": None,
            "save_totp_secret": False,
        }
        for method in TwoFactorMethod:
            d = {**base_dict, "two_factor_method": method.value}
            restored = _profile_from_dict(d)
            assert restored.two_factor_method == method, f"Failed for method {method}"

    def test_unknown_2fa_method_defaults_to_none(self) -> None:
        """An unrecognised 2FA method value must default to NONE without raising."""
        d = {
            "id": "abc",
            "name": "x",
            "server": "s",
            "username": "u",
            "ssl_port": 443,
            "ca_list": "/etc/ssl/certs",
            "certificate": None,
            "reauth": True,
            "save_password": False,
            "cipher": None,
            "two_factor_method": "foobar",
            "save_totp_secret": False,
        }
        restored = _profile_from_dict(d)
        assert restored.two_factor_method == TwoFactorMethod.NONE


class TestMigrationV1ToV2:
    def test_migration_adds_2fa_defaults(self, tmp_pm: ProfileManager) -> None:
        """A v1 profiles.json without 2FA fields must gain defaults after migration."""
        # Write a v1 file manually (no two_factor_method, no save_totp_secret)
        v1_data = {
            "version": 1,
            "default_id": "pid-1",
            "profiles": {
                "pid-1": {
                    "id": "pid-1",
                    "name": "Old VPN",
                    "server": "vpn.example.com",
                    "username": "alice",
                    "ssl_port": 443,
                    "ca_list": "/etc/ssl/certs",
                    "certificate": None,
                    "reauth": True,
                    "save_password": False,
                    "cipher": None,
                }
            },
        }
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text(json.dumps(v1_data), encoding="utf-8")

        # Load via ProfileManager — migration must run
        profiles = tmp_pm.list_all()
        assert len(profiles) == 1
        p = profiles[0]
        assert p.two_factor_method == TwoFactorMethod.NONE
        assert p.save_totp_secret is False

    def test_migration_updates_version_in_file(self, tmp_pm: ProfileManager) -> None:
        """After migration, the saved file must have version=2."""
        v1_data = {
            "version": 1,
            "default_id": None,
            "profiles": {},
        }
        tmp_pm._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_pm._path.write_text(json.dumps(v1_data), encoding="utf-8")

        # Any operation that loads-and-saves migrates the file
        profile = Profile(name="New", server="vpn.example.com", username="bob")
        tmp_pm.create(profile)

        saved = json.loads(tmp_pm._path.read_text(encoding="utf-8"))
        assert saved["version"] == 6

    def test_v2_file_not_re_migrated(self, tmp_pm: ProfileManager) -> None:
        """A v2 file must load and migrate to current version."""
        from snxui.core.profile_manager import _FILE_FORMAT_VERSION
        assert _FILE_FORMAT_VERSION == 6

        profile = Profile(
            name="Current",
            server="vpn.example.com",
            username="carol",
            two_factor_method=TwoFactorMethod.TOTP,
            save_totp_secret=True,
        )
        tmp_pm.create(profile)

        # Reload
        loaded = tmp_pm.get(profile.id)
        assert loaded is not None
        assert loaded.two_factor_method == TwoFactorMethod.TOTP
        assert loaded.save_totp_secret is True


# ---------------------------------------------------------------------------
# validate() — ssl_port range check
# ---------------------------------------------------------------------------


class TestValidateSslPort:
    def test_valid_port_443_passes(self, tmp_pm: ProfileManager) -> None:
        p = Profile(name="x", server="s", username="u", ssl_port=443)
        tmp_pm.validate(p)  # must not raise

    def test_valid_port_boundary_1_passes(self, tmp_pm: ProfileManager) -> None:
        p = Profile(name="x", server="s", username="u", ssl_port=1)
        tmp_pm.validate(p)  # must not raise

    def test_valid_port_boundary_65535_passes(self, tmp_pm: ProfileManager) -> None:
        p = Profile(name="x", server="s", username="u", ssl_port=65535)
        tmp_pm.validate(p)  # must not raise

    def test_port_zero_raises(self, tmp_pm: ProfileManager) -> None:
        p = Profile(name="x", server="s", username="u", ssl_port=0)
        with pytest.raises(ValueError, match="ssl_port"):
            tmp_pm.validate(p)

    def test_port_65536_raises(self, tmp_pm: ProfileManager) -> None:
        p = Profile(name="x", server="s", username="u", ssl_port=65536)
        with pytest.raises(ValueError, match="ssl_port"):
            tmp_pm.validate(p)

    def test_port_minus_1_raises(self, tmp_pm: ProfileManager) -> None:
        p = Profile(name="x", server="s", username="u", ssl_port=-1)
        with pytest.raises(ValueError, match="ssl_port"):
            tmp_pm.validate(p)

    def test_create_with_invalid_port_raises(self, tmp_pm: ProfileManager) -> None:
        """validate() is called inside create(), so an invalid port must prevent persistence."""
        p = Profile(name="x", server="s", username="u", ssl_port=99999)
        with pytest.raises(ValueError, match="ssl_port"):
            tmp_pm.create(p)
