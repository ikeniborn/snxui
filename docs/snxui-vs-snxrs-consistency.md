# Консистентность snxui python_ssl и snx-rs

**Дата:** 2026-03-05 (обновлено)
**Статус:** Финальный — по результатам отладки, анализа исходного кода snx-rs и архитектурного рефакторинга

---

## 1. Краткий вывод

`snxui python_ssl` (бэкенд `PythonSSLBackend + SSLTunnel`) реализует тот же протокол,
что и `snx-rs`, на уровне TLS/SLIM/CCC.
**Протокольная консистентность: полная** (с учётом исправлений, сделанных в сессиях 2026-03-05).

`python_ssl` является **единственным поддерживаемым бэкендом** для новых установок.
Режим `"auto"` в `BackendFactory` теперь всегда возвращает `PythonSSLBackend`.
Все существующие профили мигрируют на `python_ssl` при загрузке (формат v9).

TUN-устройство создаётся через привилегированный хелпер `snxui-net-helper` (pkexec),
что полностью устраняет необходимость в `setcap cap_net_admin` на интерпретаторе Python.

---

## 2. Кросс-таблица: равенство и различия

### 2.1 CCC-аутентификация

| Аспект | snxui `python_ssl` | snx-rs |
|--------|-------------------|--------|
| Эндпоинт | `POST /clients/` | `POST /clients/` |
| User-Agent | `SNXClient` | `SNXClient` |
| Content-Type | `application/x-snx-request` | `application/x-snx-request` |
| Тип запроса ClientHello | `(client_hello ...)` | `(client_hello ...)` |
| Поле `:OM` в client_hello | ✓ (serde rename из `office_mode`) | ✓ |
| `protocol_version` | `(1)` | `(1)` |
| `protocol_minor_version` | `(1)` | `(1)` |
| `client_type` | `("4")` строка в кавычках | `("4")` |
| `cookie` | `("<active_key>")` | `("<active_key>")` |
| XOR-обфускация пароля | ✓ `_snx_obfuscate()` | ✓ `util.rs::obfuscate()` |
| XOR-таблица (77 байт) | Идентична snx-rs | `util.rs::XOR_TABLE` |
| MultiChallange (OTP) | ✓ | ✓ |
| Орфография "MultiChallange" | ✓ намеренная | ✓ намеренная |
| Определение успеха | `rc=0` или `authn_status=done` | аналогично |
| `credentials_rejected` flag | `rc=14` | аналогично |
| Auto-discover login_type | ✓ `discover_login_options()` | ✓ `snx-rs -m info -s <server>` |
| Источник кода | `snxui/core/ccc_auth.py` | `snx-rs/ccc.rs`, `proto.rs` |

**Вывод:** CCC-аутентификация реализована в `ccc_auth.py` и **полностью разделяется**
всеми бэкендами snxui. snx-rs и snxui используют одинаковый протокол.

---

### 2.2 SLIM-фреймирование (SSL туннель)

| Аспект | snxui `python_ssl` | snx-rs |
|--------|-------------------|--------|
| Формат фрейма | `[4B BE LENGTH][4B BE TYPE][payload]` | `[4B BE LENGTH][4B BE TYPE][payload]` |
| Control frame type | `1` | `1` |
| Data frame type | `2` | `2` |
| Null-терминатор в control | ✓ `payload + b"\x00"`, включён в LENGTH | ✓ `data.push(b'\0')` (`codec.rs`) |
| Удаление null при чтении | ✓ `removesuffix(b"\x00")` | ✓ |
| TLS drain до `select()` | ✓ `ssl_sock.pending()` loop | аналогично (Tokio async read) |
| Stop-сигнал | `os.pipe()` + `select()` | Tokio CancellationToken |
| Источник | `snxui/core/ssl_tunnel.py` | `snx-rs/ssl.rs`, `codec.rs` |

**Вывод:** Формат фреймов идентичен. Критическое исправление произошло в сессии 2026-03-05:
изначально был ошибочный порядок `[TYPE][LENGTH]` — исправлен на `[LENGTH][TYPE]`.

---

### 2.3 Client_hello S-expression

| Поле | snxui `python_ssl` | snx-rs `ssl.rs` |
|------|-------------------|-----------------|
| Корневой тег | `(client_hello ...)` | `(client_hello ...)` |
| `:client_version` | `(1)` | `(1)` |
| `:protocol_version` | `(1)` | `(1)` |
| `:protocol_minor_version` | `(1)` | `(1)` |
| `:OM :ipaddr` | `("0.0.0.0")` | `("0.0.0.0")` |
| `:OM :keep_address` | `(false)` | `(false)` |
| `:optional :client_type` | `("4")` | `("4")` |
| `:cookie` | `("<active_key>")` | `("<active_key>")` |
| Формат отступов | TAB (1 пробел?) | TAB |
| Экранирование cookie | `\\`, `\"`, `\n`, `\r` | аналогично |
| session_id в header | не отправляется | не отправляется |

---

### 2.4 Keepalive

| Аспект | snxui `python_ssl` | snx-rs |
|--------|-------------------|--------|
| Тип keepalive | Control frame, S-expression | аналогично |
| S-expression | `(keepalive\n :id ("0")\n)\n` | `(keepalive :id "0")` |
| ID поле | Всегда `"0"` (константа) | Всегда `"0"` (`keepalive.rs`) |
| Интервал | `keepalive_timeout // 2` сек | аналогично |
| Источник интервала | hello_reply от сервера | hello_reply от сервера |
| Ограничение сверху | 300 сек (`_MAX_KEEPALIVE_SECS`) | нет (Rust безопасен) |

---

### 2.5 TUN-устройство и сеть

| Аспект | snxui `python_ssl` | snx-rs |
|--------|-------------------|--------|
| Устройство | `/dev/net/tun` | `/dev/net/tun` |
| Флаги | `IFF_TUN \| IFF_NO_PI` | аналогично |
| Ioctl | `TUNSETIFF (0x400454CA)` | аналогично |
| Интерфейс | `tunsnx` (константа) | `tunsnx` или настраивается |
| MTU | 1350 | 1350 (default) |
| Назначение IP | `ip tuntap add … user <uid>` + `ip addr add <ip>/32 dev tunsnx` | `ip addr add` напрямую (root) |
| Маршруты | `ip route add <net>/<prefix> dev tunsnx` | аналогично |
| Привилегии | **pkexec + snxui-net-helper** (polkit `auth_self_keep`) | `CAP_NET_ADMIN` на snx-rs binary |
| Деконфигурация | `pkexec snxui-net-helper destroy tunsnx` (`ip link delete`) | аналогично |
| setcap на интерпретаторе | ✗ **не требуется** | ✗ (setcap на snx-rs binary) |

**Ключевое архитектурное решение (сессия 2026-03-05):** TUN создаётся как
`ip tuntap add dev tunsnx mode tun user <uid>` — ядро Linux разрешает `TUNSETIFF`
без `CAP_NET_ADMIN` процессу, чей UID совпадает с `tun->owner`. Это полностью
устраняет `setcap cap_net_admin+ep /usr/bin/python3`.

---

### 2.6 Транспорт и архитектура

| Аспект | snxui `python_ssl` | snx-rs |
|--------|-------------------|--------|
| SSL туннель | ✓ | ✓ |
| IPSec (IKEv1/ESP) | ✗ не реализован | ✓ |
| Язык | Python 3.10+ | Rust |
| Процесс | In-process (daemon thread) | Отдельный daemon (`snx-rs`) |
| Управление | Прямой вызов Python API | `snxctl connect/disconnect/status` |
| Конфиг-файл | Нет (in-memory) | `~/.config/snx-rs/snx-rs.conf` |
| Пароль в памяти | Только во время connect() | base64 в файле (chmod 0o600) |
| Polling статуса | Нет (колбэк напрямую) | `snxctl status` каждые 2 сек |
| OTP-интерфейс | `TwoFactorCallback` (callable) | PTY через pexpect + snxctl |
| Зависимости OS | `pkexec`, `ip` | `CAP_NET_ADMIN`, `ip`, `snx-rs`, `snxctl` |
| Бинарные зависимости | `snxui-net-helper` (входит в пакет) | `snx-rs` + `snxctl` (~10 MB, внешние) |
| Версия протокола | Та же (из анализа snx-rs) | актуальная Rust-реализация |

---

## 3. Плюсы и минусы каждого решения

### 3.1 `python_ssl` backend (snxui)

#### Плюсы

| # | Плюс | Пояснение |
|---|------|-----------|
| 1 | **Нет внешних бинарников** | Не нужен snx-rs или /usr/bin/snx. Работает где есть Python 3.10+ |
| 2 | **Решает RADIUS MultiChallenge** | OTP расходуется один раз в CCC; SNX binary не запускается повторно |
| 3 | **Пароль не хранится на диске** | Пароль живёт только в памяти во время `connect()`, не пишется в файл |
| 4 | **Быстрый старт** | Нет запуска daemon-процесса, нет polling через `snxctl status` |
| 5 | **Единая кодовая база** | Все протокольные детали в Python — легко отлаживать, нет subprocess IPC |
| 6 | **Полный контроль над потоком** | Можно добавить логирование, packet inspection, метрики без патча snx-rs |
| 7 | **In-process OTP callback** | `TwoFactorCallback` вызывается напрямую из GTK — без PTY/pexpect |
| 8 | **Прозрачные ошибки** | Python exceptions с полным traceback, не парсинг PTY-вывода |
| 9 | **Нет setcap на интерпретаторе** | `pkexec snxui-net-helper` — root-права только у одного проверенного скрипта |

#### Минусы

| # | Минус | Пояснение |
|---|-------|-----------|
| 1 | **Нет IPSec** | snx-rs поддерживает IKEv1/ESP; python_ssl — только SSL tunnel |
| 2 | **Протокол "догнать" Rust** | Реализация основана на reverse engineering snx-rs. Могут быть edge cases |
| 3 | **GIL и производительность** | Python GIL может быть проблемой при высоком трафике (select loop с GIL) |
| 4 | **Меньше тестирования на железе** | snx-rs используется годами; python_ssl — новый код |
| 5 | **Нет reconnect/resume** | При потере связи — полный переconnect с re-auth (snx-rs может иметь reconnect) |
| 6 | **Один polkit-промпт на сессию** | `auth_self_keep` — один диалог при первом connect; при многократных reconnect может повториться |

---

### 3.2 `snx-rs` backend (через SNXRsBackend)

> **Примечание:** `snx-rs` по-прежнему поддерживается через `profile.backend = "snx_rs"`,
> но не является бэкендом по умолчанию. Новые профили используют `python_ssl`.

#### Плюсы

| # | Плюс | Пояснение |
|---|------|-----------|
| 1 | **Зрелая реализация** | snx-rs активно поддерживается, тестируется сообществом |
| 2 | **IPSec поддержка** | IKEv1 Phase 1+2, ESP на UDP 4500 — для серверов без SSL туннеля |
| 3 | **Memory safety** | Rust без GC, без GIL, нет утечек памяти, безопасная работа с сетью |
| 4 | **Высокая производительность** | Zero-copy packet forwarding, Tokio async runtime |
| 5 | **Daemon-архитектура** | `snx-rs` работает независимо от UI; snxui — только frontend |
| 6 | **Протокол всегда актуален** | Авторы snx-rs следят за изменениями Check Point протокола |

#### Минусы

| # | Минус | Пояснение |
|---|-------|-----------|
| 1 | **Бинарная зависимость** | Нужны `snx-rs` + `snxctl` — загрузка с GitHub, нет в apt/dnf |
| 2 | **Пароль пишется в файл** | `~/.config/snx-rs/snx-rs.conf` хранит пароль base64 (не шифрование!) |
| 3 | **IPC через pexpect** | snxui управляет snx-rs через `snxctl` + PTY — хрупко, зависит от формата вывода |
| 4 | **Polling статуса** | `snxctl status` вызывается каждые 2 сек до 60 сек — неэффективно |
| 5 | **OTP через PTY** | snxctl читает OTP через PTY — сложная цепочка против прямого callback |
| 6 | **Версия фиксирована** | snx-rs версия прибита в Makefile; обновление — ручное |
| 7 | **Требует совместимость ABI** | snx-rs — 64-bit; на некоторых системах нет всех зависимостей |
| 8 | **Сложнее отлаживать** | Проблемы в daemon-процессе; нужен `journalctl` / `snx-rs.log` |

---

## 4. Матрица совместимости с серверами

| Тип сервера | `python_ssl` | `snx-rs` | SNX binary |
|-------------|:------------:|:--------:|:----------:|
| CCC + SSL tunnel | ✓ | ✓ | ✓ (с `ccc_only_auth`) |
| RADIUS MultiChallenge | ✓ | ✓ | ✗ (OTP расходуется) |
| IPSec-only сервер | ✗ | ✓ | ✗ |
| Portal-only (без CCC) | ✗ | ✗ | ✓ (`portal_auth=True`) |
| SSL + IPSec (оба) | SSL only | Оба | SSL only |

---

## 5. Выявленные расхождения и исправления

### 5.1 Протокольные исправления (сессия 2026-03-05, первая часть)

| # | Расхождение | Статус | Источник истины |
|---|-------------|--------|-----------------|
| 1 | **Порядок байт SLIM**: был `[TYPE][LENGTH]`, должно быть `[LENGTH][TYPE]` | ✅ Исправлено | `snx-rs/codec.rs` |
| 2 | **Null-терминатор**: не добавлялся в control frames | ✅ Исправлено | `snx-rs/codec.rs` line: `data.push(b'\0')` |
| 3 | **Keepalive ID**: был счётчик, должно быть всегда `"0"` | ✅ Исправлено | `snx-rs/keepalive.rs` |
| 4 | **`assert` vs RuntimeError**: `assert ssl_sock` небезопасен с `-O` | ✅ Исправлено | best practice |
| 5 | **`rstrip` vs `removesuffix`**: `rstrip` удаляет все нули | ✅ Исправлено | correctness |
| 6 | **`_range_to_cidr` fallback**: возвращал untrusted `from_ip` в subprocess | ✅ Исправлено | security review |
| 7 | **`create_tun` без валидации**: имя интерфейса шло в ioctl без проверки | ✅ Исправлено | security review |
| 8 | **`configure_net` без валидации IP**: `assigned_ip` шёл в subprocess без `inet_aton` | ✅ Исправлено | security review |
| 9 | **`keepalive_timeout` без ограничения**: hostile gateway мог заморозить loop | ✅ Исправлено | security review |
| 10 | **`ValueError` не ловился в `_do_connect`**: новая валидация создавала утечку SSL-сокета | ✅ Исправлено | verify |
| 11 | **S-expression wrapper**: изначально был `CCCclientRequest`, должен быть `client_hello` | ✅ Исправлено (prior session) | `snx-rs/proto.rs` |
| 12 | **`protocol_version`**: был `(100)`, должен быть `(1)` | ✅ Исправлено (prior session) | `snx-rs/proto.rs` |

### 5.2 Архитектурные изменения (сессия 2026-03-05, вторая часть)

| # | Изменение | Статус | Обоснование |
|---|-----------|--------|-------------|
| 13 | **Удалён `setcap cap_net_admin`**: заменён на `pkexec snxui-net-helper` | ✅ Реализовано | security — `setcap` на `/usr/bin/python3` даёт `CAP_NET_ADMIN` любому Python-скрипту |
| 14 | **Создан `snxui/helpers/snxui-net-helper`**: привилегированный Python-скрипт, root:root 0755, `/usr/lib/snxui/` | ✅ Реализовано | polkit isolation |
| 15 | **Polkit action `com.snxui.tun`**: `auth_self_keep` + `exec.path` привязан к хелперу | ✅ Реализовано | один диалог на desktop-сессию |
| 16 | **`create_tun()` — только валидация**: OS-вызовы перенесены в `configure_net()` | ✅ Реализовано | чёткое разделение ответственности |
| 17 | **`configure_net()` → pkexec + `os.open` + `ioctl`**: TUN-device открывается без `CAP_NET_ADMIN` после `ip tuntap add … user <uid>` | ✅ Реализовано | kernel owner-check |
| 18 | **`_run()` удалена из `ssl_tunnel.py`**: функция стала мёртвым кодом после рефакторинга | ✅ Исправлено | verify |
| 19 | **`python_ssl` — единственный бэкенд по умолчанию**: `BackendFactory "auto"` → `PythonSSLBackend` | ✅ Реализовано | упрощение для новых пользователей |
| 20 | **Миграция профилей v9**: все существующие профили переводятся на `backend="python_ssl"` | ✅ Реализовано | seamless upgrade |
| 21 | **ProfileDialog упрощён**: удалены строки выбора backend/transport/portal_auth/combined_auth/ccc_only_auth | ✅ Реализовано | UI соответствует возможностям |
| 22 | **Docstring `BackendFactory`** описывал старую логику auto (snx-rs first) | ✅ Исправлено | verify |
| 23 | **Тесты `test_dialogs.py`**: `SwitchRow.side_effect` содержал 6 элементов, реально создаётся 3 — 3-й SwitchRow получал неверный мок | ✅ Исправлено | verify |
| 24 | **Тесты `test_ssl_tunnel_backend.py`**: 9 методов патчили удалённый `_run`; исправлены на `subprocess.run` | ✅ Исправлено | verify |
| 25 | **`privilege_handler.py` удалён**: класс `PrivilegeHandler` (запуск SNX через pkexec) нигде не вызывался — мёртвый код с момента перехода на python_ssl | ✅ Удалено | verify |
| 26 | **`com.snxui.connect` / `com.snxui.disconnect` удалены** из `com.snxui.policy` — не используются ни одним активным бэкендом | ✅ Удалено | verify |
| 27 | **`auth_admin_keep` → `auth_self_keep`** в `com.snxui.tun`: обычный пользователь (не admin) вводит свой пароль, не нужен sudo/root | ✅ Реализовано | usability |
| 28 | **Tunnel Type заблокирован в ProfileDialog**: `set_sensitive(False)` + subtitle — IPSec не реализован в python_ssl backend | ✅ Реализовано | UX |

---

## 6. Архитектура привилегированного хелпера

```
snxui (GTK, user context)
    │
    │ SSLTunnel.configure_net()
    │
    ▼
subprocess.run(["pkexec", "/usr/lib/snxui/snxui-net-helper", "create",
                iface, uid, ip, *routes])
    │
    │ polkit: com.snxui.tun, auth_self_keep
    │ (один диалог на desktop-сессию)
    │
    ▼
snxui-net-helper (root context)
    ├── _validate_iface(iface)      — re.match + длина
    ├── _validate_uid(uid)          — int, 0..1_048_576
    ├── _validate_ip(ip)            — socket.inet_aton()
    ├── _validate_route(r)          — net/prefix форма
    │
    ├── ip link delete <iface>      (check=False — интерфейс может не существовать)
    ├── ip tuntap add dev <iface> mode tun user <uid>
    ├── ip addr add <ip>/32 dev <iface>
    ├── ip link set <iface> mtu 1350 up
    └── ip route add <net>/<prefix> dev <iface> (check=False — дубли игнорируются)

snxui (user context, после pkexec)
    └── os.open("/dev/net/tun", O_RDWR)
        └── fcntl.ioctl(fd, TUNSETIFF, ...)   ← разрешено: tun->owner == current_fsuid()
```

**Почему `TUNSETIFF` работает без `CAP_NET_ADMIN`:**
Ядро Linux проверяет `tun->owner == current_fsuid()` — если TUN-устройство создано
с `user <uid>`, процесс этого же UID может вызвать `TUNSETIFF` без `CAP_NET_ADMIN`.
(Исходник: `drivers/net/tun.c`, функция `tun_chr_open`.)

---

## 7. Итоговая рекомендация

### Когда использовать `python_ssl` (по умолчанию)

- Сервер использует **RADIUS MultiChallenge** (OTP) — главный use case
- snx-rs **не установлен** и `/usr/bin/snx` недоступен
- Нужна **только SSL** транспортировка (большинство серверов)
- Предпочтительна **минимальная зависимость от внешних бинарников**
- Требуется **отладка протокола** — Python traceback значительно информативнее
- Нежелателен `setcap` на системном Python-интерпретаторе

### Когда использовать `snx-rs` (явно: `profile.backend = "snx_rs"`)

- Сервер требует **IPSec транспорт** (редко, корпоративные среды)
- Нужна **максимальная производительность** при высоком трафике
- Требуется **daemon-режим** (VPN без UI, autostart системный)
- Уже установлен snx-rs и переход на python_ssl нецелесообразен

### Когда использовать SNX binary (`profile.backend = "snx"`)

- Сервер использует **portal-only auth** (нет CCC endpoint)
- **Legacy-серверы** (старый Check Point, нет SLIM)
- Тестирование совместимости — SNX binary как эталон

---

## 8. Файловая карта реализации

```
snxui/
├── helpers/
│   └── snxui-net-helper         # Привилегированный хелпер (root:root, 0755)
│       ├── cmd_create()         # ip tuntap + ip addr + ip route
│       └── cmd_destroy()        # ip link delete
│
├── data/
│   └── com.snxui.policy         # Polkit: com.snxui.tun (auth_self_keep)
│
└── core/
    ├── ccc_auth.py              # CCC-протокол — общий для всех бэкендов
    │   ├── CCCAuth.authenticate()     → active_key
    │   ├── discover_login_options()   → [(id, label)]
    │   └── _snx_obfuscate()           → XOR-обфускация (идентично snx-rs util.rs)
    │
    ├── ssl_tunnel.py            # SLIM-протокол (python_ssl backend)
    │   ├── SSLTunnel.connect()        → TunnelConfig (TLS + SLIM client_hello)
    │   ├── SSLTunnel.create_tun()     → валидация имени, возвращает 0
    │   ├── SSLTunnel.configure_net()  → pkexec helper + os.open + TUNSETIFF
    │   ├── SSLTunnel._teardown_net()  → pkexec helper destroy (best-effort)
    │   ├── SSLTunnel.run_packet_loop() → блокирует до disconnect
    │   └── SSLTunnel.stop()           → сигнал через os.pipe()
    │
    ├── ssl_tunnel_backend.py    # Orchestration (python_ssl backend)
    │   └── PythonSSLBackend(VPNBackend)
    │       └── _do_connect(): discover → CCC auth → tunnel → pkexec → CONNECTED → loop
    │
    ├── snx_rs_backend.py        # snx-rs через snxctl (опциональный)
    │   └── SNXRsBackend(VPNBackend)
    │
    ├── snx_backend.py           # SNX binary через pexpect (опциональный)
    │   └── SNXBinaryBackend(VPNBackend)
    │
    └── vpn_backend.py           # Абстракция и фабрика
        └── BackendFactory.create(profile)
            ├── "python_ssl" / "auto" → PythonSSLBackend()
            ├── "snx_rs"              → SNXRsBackend()  (если бинарники найдены)
            └── "snx"                 → SNXBinaryBackend()
```

---

*Документ основан на анализе исходного кода snx-rs (codec.rs, ssl.rs, proto.rs, keepalive.rs, sexpr.rs, util.rs),
отладке python_ssl на сервере ug.vpn.rt.ru (RADIUS MultiChallenge), и анализе ядра Linux `drivers/net/tun.c`.*
