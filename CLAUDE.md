# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
make test                          # or: .venv/bin/python -m pytest tests/ -v

# Run a single test file
.venv/bin/python -m pytest tests/test_snx_rs_backend.py -v

# Run a single test by name
.venv/bin/python -m pytest tests/test_ccc_auth.py::TestRedactCcc -v

# Format and lint
make format                        # black
make lint                          # mypy + black check

# Install (dev environment, includes snx-rs)
make install-deps

# Build .deb package
make deb
```

## Architecture

The application is a GTK4/Libadwaita GUI wrapper for Check Point SNX VPN. Entry point: `snxui/app.py` → `main()`.

### Layer separation

```
snxui/ui/           — GTK4 pages and dialogs (main thread only)
snxui/core/         — business logic, auth, profiles (thread-safe)
snxui/system/       — OS integration (polkit, tray, autostart)
```

### VPN backend abstraction (`snxui/core/vpn_backend.py`)

`VPNBackend` ABC with two implementations, selected by `BackendFactory.create(profile)` based on `profile.backend` ("auto"/"snx_rs"/"snx"):

- **`SNXRsBackend`** (`snx_rs_backend.py`) — drives the `snx-rs` daemon via `snxctl`. Writes `~/.config/snx-rs/snx-rs.conf` (base64 password, chmod 0o600 atomically via `os.open`), then runs `snxctl connect` through a pexpect PTY to inject OTP when the daemon prompts.
- **`SNXBinaryBackend`** (`snx_backend.py`) — pexpect PTY automation of `/usr/bin/snx`. Full auth pipeline: optional portal auth → optional CCC auth → SNX PTY with password/OTP injection.

### Authentication pipeline (SNX binary backend)

When `profile.portal_auth=True`:
1. `PortalAuth` (`portal_auth.py`) — HTTPS portal: GET /Login/Login → POST step1 (RSA-encrypted password) → POST step2 RADIUS OTP → `CPCVPN_SESSION_ID` cookie
2. `CCCAuth` (`ccc_auth.py`) — CCC S-expression protocol: ClientHello → UserPass → MultiChallange (OTP) → `active_key` written to `~/.snxrc` as `auth_id`
3. SNX binary launched with `-r` (reconnect) if `active_key` obtained

`portal_auth=False` → SNX PTY only, password/OTP sent directly to the binary.

### Threading model

`connect()` always runs in a `daemon=True` background thread. Communication back to GTK main thread uses `GLib.idle_add()`. 2FA dialogs use `GLib.idle_add` to show the dialog + `threading.Event.wait(120)` to block the background thread until the user responds.

### Profile storage (`snxui/core/profile_manager.py`)

JSON at `~/.config/snxui/profiles.json`, format version 7 (auto-migrates v1→v7). **Passwords are never stored here** — they live in the system keyring (`CredentialStore`, wraps `keyring` library with in-memory fallback).

### Key data types (`snxui/core/types.py`)

- `Profile` — all connection settings; `backend`, `login_type`, `ignore_server_cert` fields added in v7 for snx-rs
- `ConnectionStatus` — state snapshot passed to UI via callbacks
- `TwoFactorMethod` — NONE/TOTP/HOTP/RSA_SECURID/CHALLENGE_RESPONSE/RADIUS
- `TwoFactorCallback = Callable[[str], Optional[str]]` — prompt text in, OTP string or None out

### CCC protocol notes (`snxui/core/ccc_auth.py`)

- Endpoint: `POST /clients/` with `User-Agent: SNXClient` and `Content-Type: application/x-snx-request`
- S-expression wire format: `:type (ClientHello|UserPass|MultiChallange)` — "MultiChallange" is intentionally misspelled in the Check Point protocol
- `client_type` must be string `TRAC` (not numeric); `username` field (not `userName`); `selected_login_option` (not `selectedRealm`)
- Success: `return_code=0` OR `authn_status=done` (server can return rc=600 with `authn_status=done` + `active_key`)
- `_redact_ccc()` must be applied before logging any raw CCC response (masks `active_key` values)

### snx-rs daemon notes (`snxui/core/snx_rs_backend.py`)

- Binaries: `snx-rs` (daemon, `snx-rs -m command`) + `snxctl` (control CLI) — installed from GitHub releases via `make install-snx-rs`
- `login_type` is required in config; discover via `NO_PROXY="*" snx-rs -m info -s <server>`
- pexpect PTY pattern uses `\s*[:\?]` suffix to match only actual prompts, not descriptive text

### Security invariants to maintain

- Config files with credentials: created with `os.open(O_CREAT|O_TRUNC, 0o600)`, never `write_text` + `chmod` (TOCTOU)
- `verify_ssl` defaults to `True` in `CCCAuth` and `PortalAuth`; callers pass `not profile.ignore_server_cert`
- No `shell=True` in any subprocess call
- Sensitive values (active_key, passwords) not logged in full; `_redact_ccc()` for CCC responses
