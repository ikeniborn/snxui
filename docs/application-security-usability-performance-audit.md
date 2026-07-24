# Application Security, Usability, and Performance Audit

| Field | Value |
|---|---|
| Audit date | 2026-07-24 |
| Canonical topic | `application-security-usability-performance-audit` |
| Baseline | `test` / `8ae3e2d` |
| Audited application | snxui GTK4/Libadwaita desktop VPN client |
| Overall risk | **High** |
| Release recommendation | **Do not treat the current build as production-ready for shared or high-assurance systems until the High findings are fixed.** |

## Executive Summary

The audit found no confirmed remote code execution or tracked hard-coded credentials. TLS verification is enabled by default, shell interpolation is avoided in the privileged helper, profile writes are atomic, and the test suite has a solid functional baseline.

The current release still has several release-blocking issues:

1. An active local user can invoke the root network helper without authentication and request broad route, DNS, TUN ownership, and interface operations.
2. A complete VPN `active_key` can reach the normal, unbounded log because the redactor does not cover the real unquoted protocol form and DEBUG records are enabled even without `--debug`.
3. Route and DNS setup failures are ignored, so the UI can report `CONNECTED` while intended traffic or DNS bypasses the VPN.
4. AppImage and GitHub Actions release inputs are mutable or trusted on first use; the pipeline can publish an upstream-compromised artifact with repository write permission.
5. The tunnel loop can stall on inbound backlog, partial frames, or blocked writes, while disconnect and process shutdown do not wait for privileged network teardown.
6. Several security-sensitive controls do not match behavior: certificate authentication and custom CA paths are not implemented end to end, HOTP generates a TOTP code, and the TOTP storage opt-out is ignored.

The recommended order is: close the privileged-helper boundary, stop secret logging, make networking fail closed, repair teardown, then fix authentication controls and the release chain. Usability and performance work should follow on the same release branch because several UX defects currently hide security failures.

## Guidance for Current Users

Until the High findings are fixed:

- Avoid installing or running snxui on a shared multi-user workstation.
- Do not enable **Ignore Server Certificate**. It disables gateway authentication and permits interception by a network attacker.
- Do not rely on **Certificate File**, **CA Certificates Path**, or **HOTP**; the current backend does not honor them correctly.
- Treat existing `snxui.log` files as potentially sensitive. Do not attach them to public issues without inspection and redaction.
- Do not assume that a green `CONNECTED` state proves routes and DNS were installed successfully.
- Prefer artifacts built from reviewed source in a controlled pipeline over artifacts from the current mutable AppImage flow.

## Scope and Method

### Reviewed

- GTK application lifecycle, main workflows, dialogs, settings, tray, and autostart.
- Profile and credential persistence.
- CCC authentication, TLS setup, SLIM framing, packet loop, routes, DNS, and teardown.
- Polkit policy and the installed-style root network helper.
- AppImage, Debian/RPM, Makefile, and GitHub Actions release paths.
- Automated tests, typing, formatting, static security checks, dependency advisories, and coverage.
- Non-destructive dynamic probes for logging, permissions, route conversion, protocol limits, GTK state, and selected failure paths.

### Not Performed

- No destructive invocation of the privileged helper against the host network.
- No authentication against a live Check Point gateway.
- No network MITM, fuzzing campaign, root namespace integration test, or external penetration test.
- No clean-distribution installation matrix, screen-reader session, or real StatusNotifierWatcher matrix.
- Dependency audit is a snapshot of the exact direct packages available during the audit, not a reproducible transitive audit because the project has no lock file.

### Severity

| Severity | Meaning |
|---|---|
| Critical | Direct, broadly exploitable compromise with little or no prerequisite. None confirmed. |
| High | Serious confidentiality, integrity, availability, or correctness failure; release blocker. |
| Medium | Significant failure requiring a local condition, unusual input, or constrained environment. |
| Low | Hardening, maintainability, or limited-impact issue. |

## Priority Matrix

| ID | Severity | Area | Finding | Primary impact |
|---|---|---|---|---|
| SEC-01 | High | Privilege boundary | Active users receive unauthenticated network-admin-equivalent operations | Local traffic interception, route/DNS manipulation, denial of service |
| SEC-02 | High | Secrets/logging | Full `active_key` can be logged; DEBUG is always active; log is unbounded | VPN session disclosure and disk exhaustion |
| NET-01 | High | Network correctness | Route/DNS command failures are ignored before `CONNECTED` | Traffic and DNS bypass the VPN without warning |
| SUP-01 | High | Supply chain | Mutable/TOFU build inputs and broad CI token permissions | Compromised release artifacts and repository impact |
| PERF-01 | High | Tunnel loop | Backlog, partial reads, and blocked writes can stall the sole packet loop | Multi-minute tunnel freezes and slow cancellation |
| REL-01 | High | Lifecycle | Disconnect/shutdown do not wait for network cleanup | Stale TUN, routes, DNS, and reconnect races |
| UX-01 | High | Authentication | Certificate/custom-CA controls are not implemented end to end | Failed setup or pressure to disable TLS verification |
| UX-02 | High | MFA/credentials | HOTP is wrong and storage/forget controls do not match behavior | Failed login and storage of secrets against user choice |
| UX-03 | High | Profile management | CRUD can partially apply and fail silently | Lost credentials, misleading success, unrecoverable form input |
| UX-04 | High | Application access | Minimized autostart can leave no usable window when tray is unavailable | Application appears missing while process remains active |
| NET-02 | Medium | Split tunnel | Arbitrary IPv4 ranges become one incorrect CIDR | Required traffic bypass or unintended traffic capture |
| SEC-03 | Medium | Configuration | JSON strings such as `"false"` enable security booleans | Crafted profile can disable TLS verification |
| SEC-04 | Medium | Credential cache | Password and TOTP fallback keys can collide | TOTP seed may be sent as a password to another profile gateway |
| REL-02 | Medium | Cleanup/protocol | Exceptional tunnel paths leak handles; CCC truncates at 8192 bytes | Stale state and false authentication failure |
| PERF-02 | Medium | Responsiveness | Keyring and file locks run on GTK thread | UI freezes for up to lock/service timeout |
| UX-05 | Medium | Feedback/state | Toasts are not hosted; connecting, timeout, and error states disagree | Important warnings and failures are invisible |
| UX-06 | Medium | Persistence/navigation | Selection, defaults, color scheme, and read errors are mishandled | Wrong profile use and settings that appear not to persist |
| QA-01 | Medium | Quality gates | Tests pass, but typing/format gates fail and critical paths lack integration coverage | Regressions can enter release undetected |

## Detailed Findings

### SEC-01: Privileged Helper Authorization Is Too Broad

**Evidence**

- [snxui/data/com.snxui.policy:15](../snxui/data/com.snxui.policy#L15) sets `allow_active` to `yes`, so an active local session needs no authentication.
- [snxui/helpers/snxui-net-helper:60](../snxui/helpers/snxui-net-helper#L60) accepts any UID from 0 through 1,048,576 rather than deriving it from the authenticated caller.
- [snxui/helpers/snxui-net-helper:119](../snxui/helpers/snxui-net-helper#L119) accepts any syntactically valid interface name, address, routes, and DNS servers.
- [snxui/helpers/snxui-net-helper:138](../snxui/helpers/snxui-net-helper#L138) deletes a matching interface, creates a caller-owned persistent TUN, adds routes, and applies global `~.` DNS routing.
- [snxui/helpers/snxui-net-helper:163](../snxui/helpers/snxui-net-helper#L163) permits deletion by arbitrary interface name without verifying creator or owner.
- The policy enables `org.freedesktop.policykit.exec.allow_gui`, although the helper is non-GUI. The [pkexec reference](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html) explicitly discourages this annotation except for legacy programs.

Polkit documents `yes` as unconditional authorization and notes that even `auth_self` is generally insufficient for multi-user systems; `auth_admin` is normally recommended for privileged actions. See the [polkit action reference](https://polkit.pages.freedesktop.org/polkit/polkit.8.html).

**Impact**

An active local user can create a TUN they own, route system traffic into it, alter DNS routing, or disrupt existing virtual interfaces. Input syntax validation prevents shell injection but does not enforce authorization semantics.

**Required fix**

- Change the policy to `auth_admin_keep`, or replace the helper with a narrowly scoped root daemon/NetworkManager integration.
- Derive UID from trusted caller context such as `PKEXEC_UID`; reject UID 0 and other users.
- Use a fixed application-owned interface namespace and verify ownership/state before destroy.
- Cap, normalize, and validate routes and DNS semantically; use absolute executable paths.
- Remove `exec.allow_gui`.
- Add network-namespace integration tests proving unauthorized calls fail and unrelated interfaces cannot be changed.

### SEC-02: VPN Token Disclosure and Unbounded Logging

**Evidence**

- [snxui/core/ccc_auth.py:133](../snxui/core/ccc_auth.py#L133) redacts only a quoted `:active_key ("...")` shape, while protocol responses and fixtures use an unquoted value.
- [snxui/core/ccc_auth.py:647](../snxui/core/ccc_auth.py#L647) logs CCC response bodies at DEBUG, allowing the complete unquoted `active_key` through the filter. A focused probe reproduced the leak.
- [snxui/core/debug_log.py:111](../snxui/core/debug_log.py#L111) forces the `snxui` logger to DEBUG. Because records propagate directly to ancestor handlers, the root logger's INFO level does not filter those records; this matches the [Python logging propagation model](https://docs.python.org/3/library/logging.html#logging.Logger.propagate).
- [snxui/app.py:20](../snxui/app.py#L20) uses an unbounded `FileHandler` with no rotation or retention.
- A normal `setup_logging(False)` probe still emitted a DEBUG sentinel. An existing audit-environment log had grown to about 109 MB; its contents were not inspected.
- With a common `umask 002`, dynamic creation produced directories with mode `0775` and files with mode `0664`; code does not enforce `0700`/`0600` for logs or profile metadata.

**Impact**

A same-machine user, support bundle recipient, or backup reader can obtain an active VPN bearer token. A chatty or malicious gateway can also grow the log until the user runs out of disk space.

**Required fix**

- Never log CCC bodies, active keys, session identifiers, passwords, or token prefixes.
- Add a handler-level sensitive-data filter covering quoted, unquoted, XML, and JSON forms as defense in depth.
- Set explicit handler levels; enable DEBUG only after `--debug`.
- Use size-bounded rotation and retention.
- Create data/config directories as `0700` and files atomically as `0600`; repair permissions on existing files.
- Add tests that inject unique synthetic secrets and assert they do not occur in any captured record or file.

### NET-01: Network Setup Fails Open

**Evidence**

- [snxui/helpers/snxui-net-helper:151](../snxui/helpers/snxui-net-helper#L151) ignores all route-add failures.
- [snxui/helpers/snxui-net-helper:155](../snxui/helpers/snxui-net-helper#L155) ignores DNS configuration failures, including a missing or failed `resolvectl`.
- The helper still prints `OK`; [snxui/core/ssl_tunnel_backend.py:264](../snxui/core/ssl_tunnel_backend.py#L264) continues the connection flow without verifying the kernel's resulting routes and DNS.

**Impact**

Corporate traffic or DNS queries can continue over the physical network while the UI reports a successful VPN connection. This is a privacy and policy failure, not only a diagnostic issue.

**Required fix**

- Fail closed on every required route and DNS operation.
- Apply changes transactionally and roll back all prior changes on failure.
- Verify the actual interface, route, and resolver state before publishing `CONNECTED`.
- Distinguish full-tunnel and split-tunnel success criteria.
- Test conflict, missing-tool, permission, partial-route, and rollback cases in an isolated network namespace.

### SUP-01: Release Inputs Are Not Immutable

**Evidence**

- [packaging/appimage/build-appimage.sh:50](../packaging/appimage/build-appimage.sh#L50) downloads Python standalone; the first download records its own checksum rather than comparing against a repository-pinned expected value.
- [packaging/appimage/build-appimage.sh:70](../packaging/appimage/build-appimage.sh#L70) executes the mutable AppImageKit `continuous` artifact with the same trust-on-first-use checksum pattern.
- [packaging/appimage/build-appimage.sh:224](../packaging/appimage/build-appimage.sh#L224) falls back to broad `>=` dependencies because `requirements-appimage.txt` is absent.
- [.github/workflows/release.yml:10](../.github/workflows/release.yml#L10) grants `contents: write` globally and references Actions by movable major-version tags.
- [Makefile:109](../Makefile#L109) downloads and installs a third-party `.deb` with `sudo dpkg` without a pinned digest or signature check.

GitHub states that a full commit SHA is the only immutable Action reference and recommends least-privilege token permissions. See [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

**Impact**

Compromise of an upstream release, movable tag, package resolution, or first download can inject code into distributed artifacts. The release job's broad token increases repository impact.

**Required fix**

- Pin all downloaded executables to committed SHA-256 values or verified signatures.
- Replace `continuous` and `latest` references with immutable versions/digests.
- Generate a transitive, hash-locked dependency set for every package format.
- Pin Actions to reviewed full commit SHAs, set `persist-credentials: false`, and grant permissions per job.
- Publish checksums, signatures, SBOM, and build provenance/attestations.
- Verify the downloaded `.deb` before privileged installation.

### PERF-01: The Sole Packet Loop Can Stall

**Evidence**

- [snxui/core/ssl_tunnel.py:394](../snxui/core/ssl_tunnel.py#L394) drains at most 64 already-decrypted frames, then calls `select()` even when `SSLSocket.pending()` remains positive. A mock probe drained 64 frames and then selected with about 150 seconds remaining.
- [snxui/core/ssl_tunnel.py:568](../snxui/core/ssl_tunnel.py#L568) uses blocking exact-length reads inside the only packet loop.
- [snxui/core/ssl_tunnel.py:527](../snxui/core/ssl_tunnel.py#L527) uses blocking `sendall()` on the same loop while the socket retains a 30-second timeout.

**Impact**

An inbound burst larger than roughly 86 KiB can wait for another kernel event or keepalive. A slow partial frame or backpressured gateway can block traffic in both directions, stop handling, and keepalives for up to 30 seconds per operation.

**Required fix**

- Use a nonblocking, selector-driven incremental SLIM parser and buffered SSL writes.
- If decrypted bytes remain, continue fair bounded draining or select with zero timeout.
- Add tests for more than 64 pending frames, partial frame cancellation, SSL write backpressure, and bidirectional fairness.

### REL-01: Disconnect Completes Before Teardown

**Evidence**

- [snxui/ui/home_page.py:618](../snxui/ui/home_page.py#L618) runs connection work in an untracked daemon thread.
- [snxui/core/ssl_tunnel_backend.py:101](../snxui/core/ssl_tunnel_backend.py#L101) requests stop and publishes `DISCONNECTED` without waiting for the packet loop's `finally` cleanup.
- [snxui/app.py:104](../snxui/app.py#L104) does not join the worker during shutdown.
- [snxui/core/ssl_tunnel.py:455](../snxui/core/ssl_tunnel.py#L455) removes persistence and tears down networking only later in the loop's cleanup path.

**Impact**

Fast reconnect can race with the previous `tunsnx`, and process exit can occur before TUN, routes, and DNS are removed.

**Required fix**

- Own the worker and expose explicit `CONNECTING`, `DISCONNECTING`, and cleanup-complete states.
- Request cancellation, join with a bounded timeout, and provide a verified fallback teardown.
- Publish `DISCONNECTED` only after cleanup finishes.
- Add an integration test that exits during every connect phase and confirms no interface, route, DNS, thread, or file descriptor remains.

### UX-01: Certificate and CA Controls Misrepresent Support

**Evidence**

- [snxui/ui/dialogs.py:394](../snxui/ui/dialogs.py#L394) offers certificate authentication and a custom CA path.
- Certificate mode saves an empty username, but [snxui/core/profile_manager.py:335](../snxui/core/profile_manager.py#L335) rejects it. The dialog closes and the profile does not appear; the exception is only logged.
- [snxui/core/ssl_tunnel_backend.py:182](../snxui/core/ssl_tunnel_backend.py#L182) still performs username/password CCC authentication.
- [snxui/core/ssl_tunnel_backend.py:217](../snxui/core/ssl_tunnel_backend.py#L217) creates a default SSL context but never loads the configured CA path or client certificate.
- The UI exposes **Ignore Server Certificate** with only a subtitle and no persistent connected-state warning.

TLS server authentication protects confidentiality, integrity, and gateway identity; client certificates require actual mutual-TLS handling. See the [OWASP TLS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).

**Impact**

Certificate profiles cannot be created reliably, custom enterprise CAs do not work, and users are nudged toward disabling server verification to make a legitimate internal gateway connect.

**Required fix**

- Immediately hide unsupported certificate and CA controls, or implement `load_verify_locations()`, client key/certificate loading, authentication flow, and validation end to end.
- Keep server verification enabled; require an explicit confirmation for any temporary bypass and show a persistent insecure-state indicator.
- Add positive and negative tests with a private CA, wrong hostname, expired certificate, and client-certificate requirement.

### UX-02: MFA and Credential Controls Do Not Match Behavior

**Evidence**

- [snxui/ui/home_page.py:673](../snxui/ui/home_page.py#L673) calls `generate_totp()` for both TOTP and HOTP; no HOTP counter is stored or incremented.
- [snxui/ui/profiles_page.py:171](../snxui/ui/profiles_page.py#L171) saves an entered TOTP seed regardless of `save_totp_secret`.
- [snxui/ui/home_page.py:513](../snxui/ui/home_page.py#L513) reads a stored password independently of the current save flag.
- Turning password/TOTP saving off does not delete an old keyring entry.
- [snxui/core/credential_store.py:143](../snxui/core/credential_store.py#L143) can fall back to session memory, but callers ignore the failure result and tell the user nothing.

**Impact**

HOTP logins fail. Sensitive MFA material may be stored against explicit user choice, and an unchecked control may leave an old credential active.

**Required fix**

- Remove HOTP until a durable, transactional counter is implemented, or implement RFC 4226 state correctly.
- Save a TOTP seed only when the switch is on; delete old secrets on true-to-false transitions.
- Use explicit **Remember** and **Forget stored credential** actions.
- Tell the user when storage is session-only or keyring access fails.
- Test all false/true transitions and keyring failure modes.

### UX-03: Profile Operations Are Partial and Silent

**Evidence**

- [snxui/ui/profiles_page.py:171](../snxui/ui/profiles_page.py#L171) writes the TOTP secret before profile creation/update succeeds.
- [snxui/ui/profiles_page.py:191](../snxui/ui/profiles_page.py#L191) closes the dialog and only logs create/update exceptions.
- [snxui/ui/profiles_page.py:220](../snxui/ui/profiles_page.py#L220) can delete credentials even when profile deletion fails.
- [snxui/core/profile_manager.py:181](../snxui/core/profile_manager.py#L181) converts unreadable/corrupt profile data into an empty document, which the UI presents as a real no-profiles state.

**Impact**

A disk-full, lock, validation, or parsing failure appears successful; form input is lost, credentials can become orphaned or removed, and a corrupt configuration looks like user data disappeared.

**Required fix**

- Make profile and credential changes an ordered transaction with compensation on failure.
- Keep the dialog open and show a retryable, specific error.
- Separate empty, loading, and read-error states; preserve the original corrupt file for recovery.
- Test lock timeout, disk-full, validation, keyring, and delete failures.

### UX-04: Tray Failure Can Make the Application Invisible

**Evidence**

- [snxui/system/autostart.py:26](../snxui/system/autostart.py#L26) always starts with `--minimized`.
- [snxui/app.py:120](../snxui/app.py#L120) ignores the effective result of tray startup.
- [snxui/system/tray_manager.py:527](../snxui/system/tray_manager.py#L527) can report success even when no StatusNotifierWatcher is available.
- [snxui/ui/main_window.py:300](../snxui/ui/main_window.py#L300) hides the window on close by default.

**Impact**

On a desktop without a compatible tray watcher, autostart can produce a running process with no discoverable window. The same behavior can trap a user after closing the window.

**Required fix**

- Confirm watcher registration before considering the tray available.
- Show the window when tray startup fails and disable hide-to-tray for that session.
- Add watcher-present and watcher-absent startup tests.

## Medium and Low Findings

### NET-02: IPv4 Range Conversion Is Incorrect

[snxui/core/ssl_tunnel.py:109](../snxui/core/ssl_tunnel.py#L109) reduces an arbitrary inclusive range to one CIDR. Dynamic probes produced:

| Input | Current result | Correct result |
|---|---|---|
| `10.0.0.5-10.0.0.6` | `10.0.0.4/31` | two `/32` routes |
| `10.0.0.1-10.0.0.254` | `10.0.0.0/25` | 14 CIDRs covering the exact range |

Use `ipaddress.summarize_address_range()`, return a list, validate start <= end, and cap expansion. Tests must prove exact coverage with no omitted or extra addresses.

### SEC-03: Security Booleans Are Coerced Loosely

[snxui/core/profile_manager.py:121](../snxui/core/profile_manager.py#L121) applies `bool()` to JSON values. Therefore the string `"false"` becomes true and can enable `ignore_server_cert` or credential storage. Validate a strict schema before migration; reject non-boolean values and fail safe for security flags.

### SEC-04: Fallback Credential Keys Collide

[snxui/core/credential_store.py:83](../snxui/core/credential_store.py#L83), [snxui/core/credential_store.py:164](../snxui/core/credential_store.py#L164), and [snxui/core/credential_store.py:278](../snxui/core/credential_store.py#L278) share a flat in-memory key space. With keyring unavailable, a crafted profile ID such as `totp:victim-id` can make `get_password()` return another profile's TOTP seed and send it to the configured gateway. Use separate typed maps and validate profile IDs as UUIDs.

### REL-02: Exceptional Cleanup and CCC Response Limits

- [snxui/core/ssl_tunnel.py:544](../snxui/core/ssl_tunnel.py#L544) raises `RuntimeError` for an oversized frame outside the loop's caught exception set. Teardown runs, but backend cleanup can be skipped and handles remain referenced/open.
- If privileged helper creation succeeds but opening or attaching the TUN fails, close does not reliably undo the persistent interface.
- [snxui/core/ccc_auth.py:648](../snxui/core/ccc_auth.py#L648) silently reads only 8192 bytes. A synthetic 8212-byte response lost a trailing `active_key` and produced a false authentication failure.

Use unconditional nested `try/finally`, transactional rollback after every privileged step, and a bounded streaming response reader that raises an explicit overflow error.

### PERF-02: Main-Thread I/O Freezes the UI

First keyring access can perform a write/read/delete probe, and profile operations can wait up to five seconds on a file lock. These paths run in GTK callbacks at [snxui/ui/home_page.py:523](../snxui/ui/home_page.py#L523) and [snxui/ui/profiles_page.py:180](../snxui/ui/profiles_page.py#L180). Move keyring and persistence work to `Gio.Task`/workers and marshal final state through GLib.

Additional performance work:

- [snxui/core/ssl_tunnel_backend.py:159](../snxui/core/ssl_tunnel_backend.py#L159) repeats login-type discovery on every connection and can repeat the CCC exchange. Cache/persist or reuse the discovery response.
- [snxui/helpers/snxui-net-helper:152](../snxui/helpers/snxui-net-helper#L152) launches one `ip` subprocess per route with no count/deduplication limit. Cap and deduplicate routes; batch or use netlink.
- [snxui/system/tray_manager.py:585](../snxui/system/tray_manager.py#L585) emits tray layout changes every three seconds even if state is unchanged. Emit only on changes.
- [snxui/ui/debug_window.py:162](../snxui/ui/debug_window.py#L162) lets the visible text buffer grow while the backing debug history is bounded. Prune the widget buffer too.
- `pexpect` remains a runtime dependency although every profile currently maps to the Python SSL backend. Remove it after confirming no supported path imports it.

### UX-05: Important Feedback Is Missing or Contradictory

- [snxui/ui/main_window.py:128](../snxui/ui/main_window.py#L128) does not wrap content in `Adw.ToastOverlay`; calls intended to show no-profile, split-tunnel, error-copy, and other toasts do not reach a toast-capable root.
- [snxui/ui/home_page.py:293](../snxui/ui/home_page.py#L293) disables the main button during connection without offering Cancel, while the tray still appears disconnected and permits another Connect action.
- [snxui/ui/home_page.py:694](../snxui/ui/home_page.py#L694) lets a 2FA dialog remain open after its 120-second callback expires.
- The split-tunnel and insecure-certificate conditions are not shown as persistent connection-state warnings.

Add a real toast overlay, a single connection state machine shared with the tray, cancellable connect, an expiring 2FA dialog with countdown, and persistent security-state indicators.

### UX-06: Selection and Settings Are Not Durable

- Replacing the profile dropdown model resets selection to index 0; the stored default profile is not restored. Preserve selection by profile ID and use `get_default()`.
- With no profiles, the Connect button remains enabled and only attempts a toast. Disable it and provide a direct **Add profile** action.
- [snxui/ui/settings_page.py:103](../snxui/ui/settings_page.py#L103) always shows System color scheme and does not persist changes.
- Settings write failures can leave switches visually changed; an unguarded directory creation path can raise.
- New profiles with multiple login realms silently select the first option. Present and persist a realm choice.

Low-priority UX/hardening items:

- About reports GPL-3 while `pyproject.toml` declares MIT.
- English UI is mixed with Russian traffic/tray strings; add gettext and one locale per session.
- Add an accessible label to the profile dropdown, announce dynamic status/errors, focus the first invalid field, and test with Orca/AT-SPI.
- Add explicit accessible names/tooltips and common accelerators to menu actions.
- Wrap or ellipsize long profile names in password/2FA dialogs and add narrow-width visual tests.
- Limit profile JSON size, depth, and count before migration to prevent a crafted local file from causing startup resource exhaustion.
- Do not claim that immutable Python strings can be securely wiped; shorten password lifetime and consider disabling core dumps where appropriate.

## Verification Results

| Check | Result | Interpretation |
|---|---|---|
| `make test` | **459 passed** | Existing functional suite is green. |
| Coverage | **72% total** | Core parsing is stronger; GUI/lifecycle paths remain weak (`debug_window` 0%, `main_window` 17%, `tray_manager` 54%). |
| `make lint` | **Failed: 162 mypy errors in 10 files** | Type gate is not usable as a release gate. |
| Black check | **Failed: 17 files would reformat** | Repository is not formatter-clean. |
| Ruff | **Failed: 25 current findings** | Additional lint debt remains. |
| `compileall` | Passed | Python sources compile. |
| Shell syntax | Passed | Reviewed release/helper shell entry points parse with `bash -n`. |
| Bandit 1.9.4 | No High; 3 Medium false-positive bind-address matches; 4 Low | No actionable high-severity syntactic finding; Bandit did not detect the authorization and protocol issues above. |
| `pip-audit` 2.10.1 | No known advisories in exact current direct runtime versions | Snapshot only; no lock means incomplete/non-reproducible transitive assurance. |
| `pip check` | Environment mismatch: `PyNaCl 1.5.0` expected missing `cffi` | Audit environment signal, not attributed to application code without a clean locked install. |
| Polkit XML / desktop metadata | Parsed/validated | Syntax validity does not address authorization semantics. |
| Wiki lint | Clean: 3 pages, no broken/orphan/stale references | Current semantic wiki is internally consistent. |

### Confirmed Dynamic Reproductions

- DEBUG record emitted with `setup_logging(False)`.
- Unquoted synthetic `active_key` survived redaction.
- Default-umask files/directories were created as `0664`/`0775`.
- Non-aligned IPv4 ranges produced omitted and extra addresses.
- More than 64 pending TLS frames left decrypted data behind before a long select timeout.
- A CCC response over 8192 bytes was silently truncated.
- Certificate mode failed profile validation with an empty username.
- HOTP selected the TOTP generator.
- Replacing the GTK dropdown model reset the selected profile.
- UI probes confirmed that `ApplicationWindow` has no toast API while `Adw.ToastOverlay` does.

## Test Gaps

Highest-value missing tests:

1. Polkit authorization and helper ownership/namespace tests in a disposable network namespace.
2. Route/DNS failure, actual-state verification, exact range expansion, and full rollback.
3. Secret redaction for all protocol forms, INFO/DEBUG handler behavior, secure modes, and log rotation.
4. More than 64 pending frames, partial-frame cancellation, SSL backpressure, and abnormal-loop cleanup.
5. Completed teardown on disconnect, shutdown, connection failure, and immediate reconnect.
6. Certificate/custom-CA/mTLS, hostname mismatch, expired certificate, and explicit insecure-mode UX.
7. HOTP counter behavior or removal, TOTP storage opt-out, password forget, keyring fallback, and cache collision.
8. Real GTK toast/error flows, watcher-less tray, selection persistence, connect cancellation, and settings-write failure.
9. Clean locked package builds, immutable build inputs, checksum/signature verification, and artifact provenance.
10. AT-SPI/Orca, keyboard navigation, narrow window, long translations, and long profile names.

## Remediation Roadmap

### P0: Before the Next Release

1. Restrict the polkit action and helper to authenticated, caller-bound, application-owned operations.
2. Stop logging authentication bodies/tokens; correct log levels, permissions, rotation, and retention.
3. Make route and DNS setup fail closed with rollback and actual-state verification.
4. Replace the range-to-CIDR implementation with exact multi-CIDR expansion.
5. Wait for tunnel cleanup before `DISCONNECTED` and process exit.
6. Hide broken certificate/custom-CA/HOTP features and honor secret-storage opt-outs until full implementations are tested.

### P1: Next Engineering Sprint

1. Convert the tunnel loop to incremental nonblocking reads/writes and cover backlog/backpressure.
2. Make all tunnel/helper lifecycle paths transactional and exception-safe.
3. Lock release inputs, Actions, dependencies, images, and downloaded executables; reduce CI permissions.
4. Add strict profile schema validation and separate typed credential caches.
5. Make profile/credential CRUD atomic and surface errors through a real toast/error layer.
6. Unify window/tray connection states, add cancellation, and guarantee a visible fallback window.

### P2: Quality and Product Hardening

1. Move keyring/profile I/O off the GTK thread and avoid repeated discovery.
2. Preserve profile/default selection and persist all settings.
3. Fix localization, license metadata, accessibility, and responsive text behavior.
4. Restore green mypy, Black, and Ruff gates; raise coverage around privileged, lifecycle, and real-GTK paths.
5. Add release SBOM, signatures, provenance, and clean-distribution install tests.

## Acceptance Criteria

The audit can be considered remediated only when all of the following are demonstrated:

- An unprivileged active session cannot invoke helper operations without the intended authentication, cannot choose another UID, and cannot modify an unrelated interface.
- Any required route or DNS failure prevents `CONNECTED` and leaves no network state behind.
- Synthetic tokens never occur in console, file, debug-window, crash, or support output; log files are `0600`, bounded, and rotated.
- Exact split-tunnel ranges contain every requested address and no address outside the range.
- Packet flow remains responsive under backlog, partial frames, and write backpressure; cancellation completes within a defined bound.
- Disconnect, failure, and exit leave no TUN, route, DNS, worker, pipe, or SSL handle behind.
- Every visible authentication and persistence control has a passing end-to-end test matching its label.
- A watcher-less desktop always gets a usable window and all warnings/errors are visible.
- Release builds consume immutable verified inputs with least-privilege CI permissions and publish verifiable provenance.
- Functional tests, mypy, formatter, linter, package consistency, and targeted security integration tests all pass in a clean environment.

## Positive Controls Already Present

- TLS certificate verification defaults to enabled.
- No tracked private keys, passwords, or hard-coded production tokens were found.
- Privileged subprocess calls use argument arrays and avoid `shell=True`.
- Major CCC/portal responses and SLIM frames have basic size caps.
- Profile writes use an atomic replace and cross-process file lock.
- Connection work is normally moved off the GTK thread.
- Delete confirmation defaults to Cancel and uses destructive styling.
- Password and 2FA dialogs handle Enter, Escape, cancellation, and exactly-once callbacks.
- Status uses icon, text, and spinner rather than color alone.
- The existing suite provides 459 passing regression tests.

These controls reduce risk but do not compensate for the authorization, logging, fail-open networking, lifecycle, and misleading-control findings above.
