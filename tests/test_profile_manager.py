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
