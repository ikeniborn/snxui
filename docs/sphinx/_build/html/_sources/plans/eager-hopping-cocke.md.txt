# Рефакторинг: Pluggable VPN Backend (snx-rs + snx binary)

## Контекст

**Почему сейчас**: Накопленный опыт интеграции с `ug.vpn.rt.ru` выявил системные проблемы текущей архитектуры, которые нельзя решить локальными патчами:

| Проблема | Проявление | Корень |
|----------|-----------|--------|
| Двойной OTP | Пользователь вводит OTP дважды (портал + PTY) | PTY-подход требует свой OTP после portal auth |
| Низкая скорость | Хуже, чем snx-rs или браузер | snx binary поддерживает только SSL туннель |
| Хрупкость PTY | Новая версия snx binary ломает подключение | 10+ regex на PTY вывод |
| HTML scraping | Portal auth регрессирует при апдейтах портала | regex вместо DOM parser |
| Сложность | 1400 LOC snx_backend.py, 1300 LOC portal_auth.py | 3 auth протокола в одном файле |

**snx-rs** (Rust, open source, работает на том же сервере) решает всё: CCC протокол нативно, IPSec/SSL туннели, единственный OTP через CCC MultiChallenge.

**Цель**: Pluggable backend архитектура — snx-rs как primary, /usr/bin/snx как fallback. Профиль выбирает backend.

---

## Архитектура

```
┌─────────────────────────────────────────┐
│  GTK4 UI (home_page, dialogs)           │
│  ConnectionState, StatusCallback        │
└─────────────┬───────────────────────────┘
              │ VPNBackend (ABC)
    ┌─────────┴──────────┐
    │                    │
┌───▼──────────┐  ┌──────▼──────────┐
│ SNXRsBackend │  │ SNXBinaryBackend│
│ (snxd/snxctl)│  │ (pexpect PTY)   │
│ NEW          │  │ существующий код│
└──────────────┘  └─────────────────┘
```

---

## Файлы: что создать / изменить / удалить

### Новые файлы

**`snxui/core/vpn_backend.py`** (~80 LOC)
- ABC `VPNBackend` с методами `connect()`, `disconnect()`, `state`
- `BackendFactory.create(profile)` — выбор backend по `profile.backend` и доступности
- `detect_snx_rs()` — `shutil.which("snxd")`
- `detect_snx_binary()` — `shutil.which("snx")`

**`snxui/core/snx_rs_backend.py`** (~350 LOC)
- `SNXRsBackend(VPNBackend)` — интеграция со snx-rs
- `_write_config(profile, password)` → `~/.config/snx-rs/snx-rs.conf`
- `_ensure_daemon()` — запустить snxd через privilege_handler если не запущен
- `connect(profile, password, status_cb, two_factor_cb)`:
  1. Записать конфиг
  2. Поднять snxd daemon
  3. Если нужен OTP → `two_factor_cb` → получить код → `snxctl connect --mfa-code CODE`
  4. Иначе → `snxctl connect`
  5. Поллинг `snxctl status` каждые 2с до Connected
- `disconnect()` → `snxctl disconnect`
- `_parse_status(output)` → `ConnectionState` + IP
- `fetch_login_types(server)` → `snxctl info` → список realm/login-type для UI

**`tests/test_snx_rs_backend.py`** (~100 LOC)
- Мокирование subprocess для snxd, snxctl
- Тесты: connect success, connect with MFA, disconnect, status parsing

### Изменить существующие

**`snxui/core/types.py`**
```python
@dataclass
class Profile:
    # Новые поля для snx-rs backend:
    backend: Literal["auto", "snx_rs", "snx"] = "auto"
    login_type: str = ""           # CCC login type (snx-rs: required)
    transport_type: str = "auto"   # snx-rs: auto/kernel/udp/tcpt
    ignore_server_cert: bool = False  # snx-rs TLS bypass
    # tunnel_type уже есть (SSL/IPSec) ✓
```

**`snxui/core/profile_manager.py`**
- Версия формата v7 (v6 → v7): добавить `backend`, `login_type`, `transport_type`, `ignore_server_cert`
- Миграция: v6 записи получают `backend="snx"` (не "auto") — сохраняют текущее поведение

**`snxui/core/snx_backend.py`**
- Переименовать `SNXBackend` → `SNXBinaryBackend`, унаследовать от `VPNBackend`
- Сохранить весь существующий код без изменений (обратная совместимость)
- Файл остаётся `snx_backend.py` для совместимости с импортами

**`snxui/ui/home_page.py`**
- Заменить `SNXBackend()` на `BackendFactory.create(profile)` при connect
- Остальная логика неизменна (интерфейс `VPNBackend` совпадает)

**`snxui/ui/dialogs.py`** (ProfileDialog)
- Добавить группу "Backend" с:
  - Selector: Auto / snx-rs / snx binary
  - `login_type` поле (Adw.EntryRow) с кнопкой "Discover" (запускает `snxctl info`)
  - `transport_type` ComboRow (auto/kernel/udp/tcpt)
  - `ignore_server_cert` toggle
- Скрыть `portal_auth`, `combined_auth`, `portal_reconnect_mode` когда backend=snx_rs
  (они специфичны для snx binary)

**`pyproject.toml`**
- Добавить в [tool.poetry.extras] или README: "требует snx-rs (snxd, snxctl)"
- Добавить в `[project]` → `optional-dependencies` или системные требования

---

## snx-rs config format

```ini
# ~/.config/snx-rs/snx-rs.conf (генерируется snxui)
server-name = ug.vpn.rt.ru
user-name = i.y.tischenko
login-type = vpn_ssl_vpn_UF-Username_RADIUS
tunnel-type = ipsec
transport-type = auto
ignore-server-cert = false
```

**Пароль**: НЕ сохраняется в конфиге — передаётся через переменную окружения или stdin снxd при запуске. Keyring снxui уже хранит пароль — читаем через `CredentialStore`, передаём в snxd через безопасный канал (stdin, env var `SNX_PASSWORD`).

---

## MFA Flow (snx-rs backend)

```
SNXRsBackend.connect()
  │
  ├─ profile.two_factor_method == TOTP + secret в keyring?
  │   → auto_totp() → mfa_code = "123456"
  │
  ├─ profile.two_factor_method == RADIUS/CHALLENGE?
  │   → GLib.idle_add → TwoFactorDialog (как сейчас)
  │   → Event.wait(120) → mfa_code = "654321"
  │
  └─ two_factor_method == NONE?
      → mfa_code = None (snx-rs попробует без OTP)
  │
  ↓
snxctl connect [--mfa-code {mfa_code}]
```

**Единственный OTP** — не нужен второй ввод. CCC MultiChallenge обрабатывает snx-rs внутри.

---

## Daemon Lifecycle

```
snxui запуск:
  snxctl status → Connected? → синхронизировать UI state

Нажать Connect:
  snxd запущен? нет → sudo snxd --daemon (через privilege_handler)
  snxctl connect [--mfa-code ...]
  poll snxctl status (2с) до Connected или ERROR

Нажать Disconnect:
  snxctl disconnect
  (snxd остаётся запущенным для следующего connect)

snxui завершение:
  если Connected → показать диалог "Отключить VPN?" → snxctl disconnect
  snxd оставить работать (пользователь может переподключиться)
```

---

## Что убирается из сложности (при использовании snx-rs)

| Убирается | LOC | Причина |
|-----------|-----|---------|
| PTY pexpect автоматизация | ~600 | snx-rs не нужен PTY |
| HTML scraping portal_auth.py | ~800 | CCC нативно в snx-rs |
| ccc_auth.py (используется snx-rs) | ~500 | snx-rs делает сам |
| regex паттерны PTY вывода | ~50 | нет PTY |
| combined_auth логика | ~80 | не нужна |
| portal_reconnect_mode | ~120 | не нужен |

Эти файлы **остаются** для snx binary fallback. Но для snx-rs backend — не используются.

---

## Фазы реализации

### Фаза 1: ABC + типы (1 день)
1. Создать `vpn_backend.py` с `VPNBackend` ABC и `BackendFactory`
2. Обновить `types.py`: новые поля Profile
3. Обновить `profile_manager.py`: миграция v6→v7
4. Рефакторинг `SNXBackend` → `SNXBinaryBackend(VPNBackend)`
5. Обновить `home_page.py`: использовать `BackendFactory`
6. Обновить тесты

### Фаза 2: SNXRsBackend (2 дня)
1. Создать `snx_rs_backend.py`
2. Config generation, daemon management, status polling
3. MFA integration (TwoFactorDialog → --mfa-code)
4. Unit тесты с мокированием subprocess

### Фаза 3: UI (1 день)
1. ProfileDialog: backend selector + login_type + transport_type
2. "Discover" кнопка → `snxctl info` → заполнить login_type
3. Скрыть snx-binary-specific поля при backend=snx_rs
4. Тесты диалога

### Фаза 4: Интеграция и тестирование (1 день)
1. End-to-end тест с реальным snx-rs (на сервере пользователя)
2. Проверка fallback на snx binary
3. Проверка auto-detect при разных комбинациях установленных бинарей
4. Обновление README: инструкция по установке snx-rs

---

## Критические файлы

| Файл | Действие | Риск |
|------|----------|------|
| `snxui/core/vpn_backend.py` | CREATE | Низкий |
| `snxui/core/snx_rs_backend.py` | CREATE | Средний (subprocess, async) |
| `snxui/core/types.py` | MODIFY | Низкий (additive) |
| `snxui/core/profile_manager.py` | MODIFY | Средний (миграция данных) |
| `snxui/core/snx_backend.py` | MODIFY | Низкий (rename class) |
| `snxui/ui/home_page.py` | MODIFY | Низкий (1 строка замены) |
| `snxui/ui/dialogs.py` | MODIFY | Средний (новая UI группа) |

Существующие файлы `portal_auth.py`, `ccc_auth.py` — **без изменений** (используются SNXBinaryBackend).

---

## Верификация

```bash
# 1. Тесты без snx-rs установленного
python3 -m pytest tests/ -q
# Ожидаем: 570+ passed (все старые + новые)

# 2. Тест auto-detect
python3 -c "from snxui.core.vpn_backend import detect_snx_rs; print(detect_snx_rs())"

# 3. Тест config generation
python3 -c "
from snxui.core.snx_rs_backend import SNXRsBackend
from snxui.core.types import Profile
p = Profile(server='vpn.test', username='user', login_type='vpn_test')
backend = SNXRsBackend()
print(backend._build_config(p))
"

# 4. Реальное подключение (требует snx-rs установленный)
# Запустить snxui, создать профиль с backend=snx_rs, нажать Connect
# Ожидаем: одиночный OTP, IPSec туннель, скорость выше
```
