# План реализации поддержки 2FA в snxui

## Контекст

snxui взаимодействует с Check Point SNX через pexpect PTY. Текущая реализация поддерживает
только один цикл: `Password:` → sendline → `Connected/Error`. VPN серверы с включённым
RADIUS MFA, RSA SecurID, TOTP или challenge-response вызывают 60-секундный timeout,
так как код не умеет обрабатывать дополнительные prompt'ы от SNX.

Цель: добавить полноценный интерактивный 2FA без нарушения backward compatibility.

---

## Типы 2FA для поддержки

| Тип | SNX prompt примеры | Способ ввода |
|---|---|---|
| TOTP/HOTP | "Verification code:", "OTP:", "Two-factor code:" | Авто из keyring **или** диалог |
| RSA SecurID | "Enter SecurID PASSCODE:", "PASSCODE:" | Всегда диалог |
| Challenge-Response | "Challenge: DEADBEEF", "Enter response:" | Всегда диалог |
| RADIUS | "Enter RADIUS token:", "Token:" | Всегда диалог |

---

## Архитектурные решения

### Синхронизация threads
`connect()` работает в background thread. GTK диалоги требуют main thread.
Механизм: `GLib.idle_add(show_dialog)` + `threading.Event.wait(120)` — стандартный
паттерн для GTK threading, уже используется в проекте для `status_callback`.

### TOTP без зависимостей
Реализация RFC 6238 / RFC 4226 через stdlib (`hmac`, `hashlib`, `struct`, `time`, `base64`).
pyotp не требуется.

### Backward compatibility
- `connect()` без `two_factor_callback` работает идентично текущей версии
- Старые `profiles.json` без полей 2FA загружаются с defaults через migration

---

## Файлы и изменения

### 1. `snxui/core/types.py`

**Изменить** `from typing import Optional` → `from typing import Callable, Optional`

**Добавить** после `ConnectionState`:
```python
class TwoFactorMethod(Enum):
    """Supported two-factor authentication methods."""
    NONE = "none"
    TOTP = "totp"
    HOTP = "hotp"
    RSA_SECURID = "rsa"
    CHALLENGE_RESPONSE = "challenge"
    RADIUS = "radius"


# Type alias — здесь, чтобы ui и core могли импортировать без circular import
TwoFactorCallback = Callable[[str], Optional[str]]
# str — prompt_text от SNX; Optional[str] — код для ввода или None (отмена)
```

**Добавить** в `Profile` dataclass два поля (после `cipher`):
```python
two_factor_method: TwoFactorMethod = TwoFactorMethod.NONE
save_totp_secret: bool = False
```

---

### 2. `snxui/core/totp.py` — новый файл (только stdlib)

```python
"""TOTP/HOTP implementation (RFC 6238 / RFC 4226) using stdlib only."""
from __future__ import annotations
import base64, hashlib, hmac, struct, time

def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """Compute HOTP code. Raises ValueError on invalid secret."""
    secret_b32 = secret_b32.upper().strip()
    padding = (8 - len(secret_b32) % 8) % 8
    key = base64.b32decode(secret_b32 + "=" * padding)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

def generate_totp(secret_b32: str, digits: int = 6, step: int = 30) -> str:
    """Return current TOTP code."""
    return _hotp(secret_b32, int(time.time()) // step, digits)

def seconds_remaining(step: int = 30) -> int:
    """Seconds until the current TOTP code expires."""
    return step - (int(time.time()) % step)
```

---

### 3. `snxui/core/credential_store.py` — хранение TOTP-секрета

**Добавить** рядом с `_KEY_PREFIX`:
```python
_TOTP_PREFIX = "totp:"

def _make_totp_key(profile_id: str) -> str:
    return f"{_TOTP_PREFIX}{profile_id}"
```

**Добавить** три метода в `CredentialStore` по точной аналогии с `set/get/delete_password`
(тот же keyring → memory fallback, те же блокировки, тот же `wipe_string`),
но с ключом `_make_totp_key(profile_id)` вместо `_make_key(profile_id)`.

Сигнатуры:
```python
def set_totp_secret(self, profile_id: str, secret: str) -> bool: ...
def get_totp_secret(self, profile_id: str) -> Optional[str]: ...
def delete_totp_secret(self, profile_id: str) -> bool: ...
```

Примечание: `_memory_cache: dict[str, str]` хранит и пароли, и TOTP-секреты.
Ключи разные (`"profile:{id}"` vs `"totp:{id}"`), коллизий нет.

Также дополнить `clear_all()` — добавить удаление TOTP-ключей из `_memory_cache`.

---

### 4. `snxui/core/profile_manager.py` — сериализация + migration

**Изменить** `_FILE_FORMAT_VERSION = 1` → `_FILE_FORMAT_VERSION = 2`

**Добавить** в `_profile_to_dict()`:
```python
"two_factor_method": profile.two_factor_method.value,
"save_totp_secret": profile.save_totp_secret,
```

**Добавить** в `_profile_from_dict()` (с импортом `from .types import TwoFactorMethod`):
```python
raw_2fa = data.get("two_factor_method", "none")
try:
    two_factor_method = TwoFactorMethod(raw_2fa)
except ValueError:
    logger.warning("Unknown 2FA method %r — defaulting to NONE.", raw_2fa)
    two_factor_method = TwoFactorMethod.NONE
# В Profile(...)
two_factor_method=two_factor_method,
save_totp_secret=bool(data.get("save_totp_secret", False)),
```

**Расширить** `_migrate()` — ветка `if version < 2`:
```python
if version < 2:
    for profile_data in data.get("profiles", {}).values():
        profile_data.setdefault("two_factor_method", "none")
        profile_data.setdefault("save_totp_secret", False)
    data["version"] = 2
```

---

### 5. `snxui/core/snx_backend.py` — центральное изменение

#### 5a. Обновить импорты:
```python
from .types import ConnectionState, ConnectionStatus, Profile, TwoFactorCallback
```

#### 5b. Добавить regex-паттерны (после `_RE_DISCONNECTED`):
```python
# --- 2FA prompts (all use re.IGNORECASE only, no MULTILINE) ---

_RE_2FA_RSA = re.compile(
    r"Enter\s+SecurID\s+PASSCODE\s*:|SecurID\s+passcode\s*:|PASSCODE\s*:",
    re.IGNORECASE,
)
_RE_2FA_RADIUS = re.compile(
    r"Enter\s+RADIUS\s+(?:token|passcode)\s*:|RADIUS\s+(?:token|passcode)\s*:"
    r"|\bToken\s*:",
    re.IGNORECASE,
)
_RE_2FA_CHALLENGE = re.compile(
    r"Challenge\s*:\s*\S+|Your\s+challenge\s+is\s*:\s*\S+|Enter\s+response\s*:",
    re.IGNORECASE,
)
_RE_2FA_GENERIC = re.compile(
    r"Enter\s+one.time\s+(?:password|code)\s*:|Verification\s+code\s*:|"
    r"\bOTP\s*:|Two.factor\s+code\s*:",
    re.IGNORECASE,
)

# Объединённый паттерн для expect() списка
_RE_2FA_ANY = re.compile(
    r"Enter\s+SecurID\s+PASSCODE\s*:|SecurID\s+passcode\s*:|PASSCODE\s*:|"
    r"Enter\s+RADIUS\s+(?:token|passcode)\s*:|RADIUS\s+(?:token|passcode)\s*:|"
    r"\bToken\s*:|"
    r"Challenge\s*:\s*\S+|Enter\s+response\s*:|"
    r"Enter\s+one.time\s+(?:password|code)\s*:|Verification\s+code\s*:|"
    r"\bOTP\s*:|Two.factor\s+code\s*:",
    re.IGNORECASE,
)
```

#### 5c. Изменить сигнатуру `connect()`:
```python
def connect(
    self,
    profile: Profile,
    password: str,
    status_callback: Optional[Callable[[ConnectionStatus], None]] = None,
    two_factor_callback: Optional[TwoFactorCallback] = None,  # НОВЫЙ
) -> bool:
```
В теле — передать `two_factor_callback` в `_handle_post_password()`:
```python
return self._handle_post_password(child, profile, status_callback, two_factor_callback)
#                                                                   ↑ добавить
```

#### 5d. Извлечь `_finish_connected()` из текущей логики успеха:
```python
def _finish_connected(
    self,
    child: "pexpect.spawn",
    profile: Profile,
    callback: Optional[Callable[[ConnectionStatus], None]],
    full_output: str,
) -> bool:
    """Finalize a successful connection: update status, start monitor, close PTY."""
    ip_address = self._parse_office_ip(full_output)
    logger.info("SNX connected. Office IP: %s", ip_address or "unknown")
    with self._lock:
        snapshot = self._update_status(
            ConnectionState.CONNECTED,
            profile=profile,
            ip_address=ip_address,
            interface="tunsnx",
            connected_at=time.time(),
        )
    child.close()
    self._invoke_callback(callback, snapshot)
    self._start_monitor(profile, callback)
    return True
```

#### 5e. Переписать `_handle_post_password()`:
```python
def _handle_post_password(
    self,
    child: "pexpect.spawn",
    profile: Profile,
    callback: Optional[Callable[[ConnectionStatus], None]],
    two_factor_callback: Optional[TwoFactorCallback] = None,  # НОВЫЙ
) -> bool:
    _2FA_LOOP_LIMIT = 3

    for _round in range(_2FA_LOOP_LIMIT):
        idx = child.expect(
            [
                _RE_CONNECTED,    # 0
                _RE_AUTH_FAILED,  # 1
                _RE_CONN_FAILED,  # 2
                pexpect.EOF,      # 3
                pexpect.TIMEOUT,  # 4
                _RE_2FA_ANY,      # 5 — новый
            ],
            timeout=_CONNECT_TIMEOUT,
        )
        full_output = (child.before or "") + (
            child.after if isinstance(child.after, str) else ""
        )

        if idx == 0:
            return self._finish_connected(child, profile, callback, full_output)

        if idx in (1, 2, 3, 4):
            # Текущая error_map логика без изменений
            error_map = {
                1: "Authentication failed — check username and password.",
                2: "Connection failed — check server address and network.",
                3: "Unexpected SNX process termination.",
                4: "SNX timed out waiting for connection confirmation.",
            }
            error_msg = error_map.get(idx, "Unknown SNX error.")
            logger.error("SNX connect failed (idx=%d): %s", idx, error_msg)
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR, profile=profile, error_message=error_msg,
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        # idx == 5: 2FA prompt
        if two_factor_callback is None:
            logger.error("SNX requested 2FA but no two_factor_callback provided.")
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR, profile=profile,
                    error_message="VPN requires two-factor authentication. "
                                  "Configure 2FA method in profile settings.",
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        code = two_factor_callback(full_output)  # Блокирует bg thread

        if code is None:
            logger.info("User cancelled 2FA input.")
            with self._lock:
                snapshot = self._update_status(
                    ConnectionState.ERROR, profile=profile,
                    error_message="Two-factor authentication cancelled.",
                )
            child.close()
            self._invoke_callback(callback, snapshot)
            return False

        child.sendline(code)
        # Продолжить цикл

    # Превышен _2FA_LOOP_LIMIT
    logger.error("2FA loop limit exceeded.")
    with self._lock:
        snapshot = self._update_status(
            ConnectionState.ERROR, profile=profile,
            error_message="Too many 2FA rounds — connection aborted.",
        )
    child.close()
    self._invoke_callback(callback, snapshot)
    return False
```

---

### 6. `snxui/ui/dialogs.py` — новый диалог + расширение ProfileDialog

#### 6a. Добавить module-level константы (перед классами):
```python
# Используется в ProfileDialog._build_form_rows и _build_action_area
_2FA_METHOD_LABELS = [
    "None", "TOTP (Time-based)", "HOTP (Counter-based)",
    "RSA SecurID", "Challenge-Response", "RADIUS Token",
]
_2FA_METHOD_VALUES = ["none", "totp", "hotp", "rsa", "challenge", "radius"]
```

#### 6b. Добавить `TwoFactorDialog` после `PasswordDialog`:

```python
class TwoFactorDialog:
    """Modal dialog для ввода 2FA кода.
    Callback: callback(code: Optional[str]) — None при отмене.
    """

    def __init__(self, profile_name: str = "", prompt_text: str = "") -> None:
        if not _GTK_AVAILABLE:
            raise ImportError("GTK4/Libadwaita is required for TwoFactorDialog.")
        self._profile_name = profile_name
        self._prompt_text = prompt_text

    def show(
        self,
        callback: Callable[[Optional[str]], None],
        parent: object = None,
    ) -> None:
        dialog = Adw.Dialog(title="Two-Factor Authentication")
        dialog.set_content_width(360)
        content_box = self._build_content(dialog, callback)
        dialog.set_child(content_box)
        dialog.present(parent)

    def _build_content(self, dialog, callback):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24); box.set_margin_bottom(24)
        box.set_margin_start(24); box.set_margin_end(24)

        heading = Gtk.Label(label=f"2FA Required — {self._profile_name}")
        heading.add_css_class("title-3")
        heading.set_halign(Gtk.Align.START)
        box.append(heading)

        if self._prompt_text.strip():
            prompt_label = Gtk.Label(label=self._prompt_text.strip())
            prompt_label.add_css_class("caption")
            prompt_label.set_wrap(True)
            prompt_label.set_halign(Gtk.Align.START)
            box.append(prompt_label)

        prefs_group = Adw.PreferencesGroup()
        # EntryRow (не PasswordEntryRow) — 2FA коды принято видеть при вводе
        code_row = Adw.EntryRow(title="Authentication Code")
        code_row.set_input_purpose(Gtk.InputPurpose.DIGITS)
        prefs_group.add(code_row)
        box.append(prefs_group)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_halign(Gtk.Align.END)

        cancel_btn = Gtk.Button(label="Cancel")
        # Читаем значение ДО close() — паттерн из PasswordDialog
        cancel_btn.connect("clicked", lambda _b: (dialog.close(), callback(None)))
        btn_box.append(cancel_btn)

        ok_btn = Gtk.Button(label="Authenticate")
        ok_btn.add_css_class("suggested-action")
        ok_btn.connect(
            "clicked",
            lambda _b: (
                callback(code_row.get_text().strip() or None),
                dialog.close(),
            ),
        )
        btn_box.append(ok_btn)
        box.append(btn_box)
        return box
```

#### 6c. Расширить `ProfileDialog`:

**Изменить** тип callback в `__init__`:
```python
callback: Callable[[Optional["Profile"], Optional[str]], None]
# Второй аргумент: TOTP секрет или None
```

**В `_build_form_rows()`** добавить вторую группу после `scroll.set_child(prefs_page)`:
```python
tfa_group = Adw.PreferencesGroup(title="Two-Factor Authentication")
prefs_page.add(tfa_group)

method_model = Gtk.StringList()
for label in _2FA_METHOD_LABELS:
    method_model.append(label)
method_row = Adw.ComboRow(title="2FA Method", model=method_model)
# Выставить текущий индекс из профиля
cur_method_idx = 0
if p and p.two_factor_method.value in _2FA_METHOD_VALUES:
    cur_method_idx = _2FA_METHOD_VALUES.index(p.two_factor_method.value)
method_row.set_selected(cur_method_idx)
tfa_group.add(method_row)

totp_row = Adw.PasswordEntryRow(title="TOTP Secret (Base32, optional)")
# Не заполняем хранимым секретом — только пустое поле для нового ввода
totp_row.set_visible(cur_method_idx in (1, 2))  # TOTP / HOTP
tfa_group.add(totp_row)

save_totp_row = Adw.SwitchRow(title="Save TOTP Secret in Keyring")
save_totp_row.set_active(p.save_totp_secret if p else False)
save_totp_row.set_visible(cur_method_idx in (1, 2))
tfa_group.add(save_totp_row)

def _on_method_changed(row: object, _param: object) -> None:
    is_totp = method_row.get_selected() in (1, 2)
    totp_row.set_visible(is_totp)
    save_totp_row.set_visible(is_totp)
method_row.connect("notify::selected", _on_method_changed)

# Добавить в rows
rows["2fa_method"] = method_row
rows["totp_secret"] = totp_row
rows["save_totp"] = save_totp_row
```

**В `_build_action_area` / `_on_save`** — добавить чтение 2FA полей и изменить вызов callback:
```python
def _on_save(_btn: object) -> None:
    ...  # существующая валидация без изменений
    from snxui.core.types import Profile, TwoFactorMethod  # TwoFactorMethod добавить
    method_idx = rows["2fa_method"].get_selected()
    two_factor_method = TwoFactorMethod(_2FA_METHOD_VALUES[method_idx])
    totp_secret: Optional[str] = rows["totp_secret"].get_text().strip() or None
    profile = Profile(
        ...  # существующие поля
        two_factor_method=two_factor_method,
        save_totp_secret=rows["save_totp"].get_active(),
    )
    dialog.close()
    self._callback(profile, totp_secret)  # ← было self._callback(profile)
```

**В `cancel_btn`** обновить lambda:
```python
cancel_btn.connect("clicked", lambda _b: (dialog.close(), self._callback(None, None)))
#                                                                              ↑ добавить
```

---

### 7. `snxui/ui/profiles_page.py`

**В `_on_add`** и **`_on_edit`** изменить `_on_saved`:
```python
def _on_saved(profile: Optional["Profile"], totp_secret: Optional[str]) -> None:
    if profile is None:
        return
    # Сохранить TOTP секрет если передан
    if totp_secret is not None and self._cs is not None:
        try:
            self._cs.set_totp_secret(profile.id, totp_secret)
        except Exception as exc:
            logger.warning("Failed to save TOTP secret: %s", exc)
    try:
        self._pm.create(profile)  # или self._pm.update(profile) в _on_edit
    except Exception as exc:
        logger.error("Failed to create/update profile: %s", exc)
    self.refresh()
```

**В `_on_delete`** добавить удаление TOTP-секрета:
```python
if self._cs is not None:
    try:
        self._cs.delete_password(profile.id)
        self._cs.delete_totp_secret(profile.id)  # НОВОЕ
    except Exception as exc:
        logger.warning(...)
```

---

### 8. `snxui/ui/home_page.py` — 2FA callback

**В `TYPE_CHECKING` блок** добавить:
```python
from snxui.core.types import TwoFactorCallback  # добавить к существующей строке
```

**В `_start_connect()`** добавить:
```python
two_factor_callback = self._build_two_factor_callback(profile)

def _run() -> None:
    success = self._backend.connect(
        profile, password,
        status_callback=self.update_status,
        two_factor_callback=two_factor_callback,  # НОВОЕ
    )
    ...  # остальное без изменений
```

**Добавить** два новых метода в `HomePage`:

```python
def _build_two_factor_callback(
    self, profile: "Profile"
) -> "Optional[TwoFactorCallback]":
    """Return appropriate 2FA callback based on profile's method."""
    from snxui.core.types import TwoFactorMethod
    if profile.two_factor_method == TwoFactorMethod.NONE:
        return None
    if profile.two_factor_method in (TwoFactorMethod.TOTP, TwoFactorMethod.HOTP):
        secret: Optional[str] = None
        try:
            secret = self._cs.get_totp_secret(profile.id)
        except Exception:
            pass
        if secret is not None:
            # Явное non-optional связывание для mypy strict
            _secret: str = secret

            def _auto_totp(_prompt: str) -> Optional[str]:
                from snxui.core.totp import generate_totp
                try:
                    return generate_totp(_secret)
                except ValueError as exc:
                    logger.error("TOTP generation failed: %s", exc)
                    return None
            return _auto_totp
    # RSA, challenge, RADIUS, TOTP без хранимого секрета — интерактивный диалог
    return self._make_interactive_two_factor_callback(profile)


def _make_interactive_two_factor_callback(
    self, profile: "Profile"
) -> "TwoFactorCallback":
    """Build a callback that shows TwoFactorDialog from the GTK main thread.

    Blocks the background thread via threading.Event until the user acts.
    """
    def _callback(prompt_text: str) -> Optional[str]:
        result: dict[str, Optional[str]] = {"code": None}
        event = threading.Event()

        def _show_dialog() -> bool:  # GLib.SOURCE_REMOVE compatible
            from snxui.ui.dialogs import TwoFactorDialog

            def _on_response(code: Optional[str]) -> None:
                result["code"] = code
                event.set()

            parent = self._page.get_root()
            TwoFactorDialog(
                profile_name=profile.name or profile.server,
                prompt_text=prompt_text,
            ).show(callback=_on_response, parent=parent)
            return GLib.SOURCE_REMOVE

        GLib.idle_add(_show_dialog)
        if not event.wait(timeout=120.0):
            logger.warning("2FA dialog timed out after 120s.")
            return None
        return result["code"]

    return _callback
```

---

## Тесты

### `tests/test_totp.py` (новый)
```python
# RFC 4226 Appendix D test vectors (secret = b"12345678901234567890")
def test_hotp_rfc_vectors() -> None:
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert _hotp(secret, 0) == "755224"
    assert _hotp(secret, 1) == "287082"
    assert _hotp(secret, 9) == "520489"

def test_totp_deterministic_with_fixed_time(monkeypatch) -> None:
    monkeypatch.setattr("snxui.core.totp.time.time", lambda: 59.0)
    secret = base64.b32encode(b"12345678901234567890").decode()
    # counter = 59 // 30 = 1
    assert generate_totp(secret) == _hotp(secret, 1)

def test_generate_totp_length_and_digits() -> None:
    secret = base64.b32encode(b"test").decode()
    code = generate_totp(secret)
    assert len(code) == 6
    assert code.isdigit()

def test_invalid_secret_raises() -> None:
    with pytest.raises(Exception):
        _hotp("NOT_VALID_BASE32!!!", 0)

def test_seconds_remaining_in_range() -> None:
    assert 0 <= seconds_remaining() <= 30
```

### `tests/test_2fa_regex.py` (новый)
```python
# Параметризованные тесты для _RE_2FA_RSA, _RE_2FA_RADIUS, _RE_2FA_CHALLENGE, _RE_2FA_GENERIC
# Каждый паттерн проверяется на 3-4 реальных примера из SNX

def test_password_prompt_not_matched_by_2fa_any() -> None:
    assert not _RE_2FA_ANY.search("Password:")
    assert not _RE_2FA_ANY.search("Enter password:")
```

### `tests/test_snx_backend.py` (расширить)

Добавить класс `TestConnect2FA` с методами (использовать `_make_child_mock`):

| Тест | `expect.side_effect` | 2FA callback | Ожидаемый результат |
|---|---|---|---|
| `test_rsa_securid_then_connected` | `[0, 5, 0]` | возвращает "123456" | `True`, `sendline("123456")` вызван |
| `test_otp_prompt_then_connected` | `[0, 5, 0]` | возвращает "654321" | `True` |
| `test_challenge_response` | `[0, 5, 0]` | возвращает "RESP" | `True`, проверить prompt_text передан |
| `test_2fa_cancelled` | `[0, 5]` | возвращает `None` | `False`, state=ERROR, msg contains "cancelled" |
| `test_2fa_no_callback` | `[0, 5]` | нет callback | `False`, state=ERROR, msg contains "Configure 2FA" |
| `test_2fa_loop_limit` | `[0, 5, 5, 5, 5]` | всегда "000000" | `False`, callback вызван ≤ 3 раз |
| `test_backward_compat` | `[0, 0]` | нет callback | `True` (как раньше) |

### `tests/test_credential_store.py` (расширить)
- `test_set_get_totp_secret` (memory fallback)
- `test_delete_totp_secret`
- `test_totp_key_independent_of_password_key` — один profile_id, оба ключа независимы

### `tests/test_profile_manager.py` (расширить)
- `test_serialize_two_factor_method_totp` — `TwoFactorMethod.TOTP` round-trip
- `test_migration_v1_to_v2` — старый dict без 2FA полей → defaults
- `test_unknown_2fa_method_defaults_to_none` — значение "foobar" → NONE без Exception

---

## Порядок реализации

1. `snxui/core/types.py`
2. `snxui/core/totp.py` (новый)
3. `tests/test_totp.py` (новый)
4. `snxui/core/credential_store.py`
5. `snxui/core/profile_manager.py`
6. `snxui/core/snx_backend.py`
7. `snxui/ui/dialogs.py`
8. `snxui/ui/profiles_page.py`
9. `snxui/ui/home_page.py`
10. `tests/test_2fa_regex.py` (новый)
11. `tests/test_snx_backend.py` (расширить)
12. `tests/test_credential_store.py` (расширить)
13. `tests/test_profile_manager.py` (расширить)

---

## Верификация

```bash
cd /home/ikeniborn/Documents/Project/snxui

# Все тесты
python -m pytest tests/ -v

# Только новые 2FA тесты
python -m pytest tests/test_totp.py tests/test_2fa_regex.py -v

# Mypy strict
python -m mypy snxui/ --strict

# Backward compat — старые тесты не должны сломаться
python -m pytest tests/test_snx_backend.py::TestConnect -v
python -m pytest tests/test_profile_manager.py -v
```
