# snxui

GTK4 GUI-клиент для подключения к корпоративному VPN Check Point SNX на Linux.

Работает без `/usr/bin/snx` и без `snx-rs` — протокол реализован напрямую на Python
(CCC-аутентификация + SSL/SLIM туннель), что обеспечивает полную поддержку
RADIUS MultiChallenge OTP и устраняет зависимость от проприетарных бинарников Check Point.

## Что решает

| Задача | Решение |
|--------|---------|
| RADIUS MultiChallenge OTP | OTP расходуется один раз на уровне CCC; SNX binary не нужен |
| Нет `setcap cap_net_admin` на `python3` | TUN-устройство создаётся через `pkexec snxui-net-helper` |
| Пароль не хранится на диске | Только системный keyring (libsecret / KDE Wallet) |
| Управление несколькими серверами | Профили с независимыми настройками auth |
| Работа без snx-rs и snx binary | Встроенная Python реализация CCC + SLIM протокола |

## Основа

- **Python 3.10+**, GTK4, Libadwaita — UI для GNOME и совместимых сред
- **CCC S-expression протокол** — аутентификация (идентично snx-rs/ccc.rs)
- **SLIM протокол** — SSL туннель поверх TLS (идентично snx-rs/ssl.rs)
- **polkit** — привилегированный хелпер для создания TUN-интерфейса
- **pexpect** — опциональное взаимодействие с SNX binary / snxctl (legacy бэкенды)

## Функционал

- **Подключение к VPN** без `/usr/bin/snx` и без `snx-rs`
- **RADIUS MultiChallenge OTP** — TOTP/HOTP/RSA SecurID через диалог или keyring
- **Автоматическое определение login_type** (`snx-rs -m info -s <server>` не нужен вручную)
- **Профили** — несколько серверов, переключение без перезапуска
- **Системный keyring** — пароль и TOTP-секрет хранятся в libsecret / KDE Wallet
- **Системный трей** — быстрое подключение / отключение, индикатор статуса
- **Трафик в реальном времени** — скорость RX/TX на главной странице
- **Автозапуск** — опционально, через XDG autostart
- **polkit auth_self_keep** — один пароль-промпт за рабочую сессию (без sudo)

## Установка

### Релиз (рекомендуется)

Скачать `.deb` или AppImage с [Releases](https://github.com/ikeniborn/snxui/releases):

```bash
sudo apt install ./snxui_*.deb
```

### Из исходников

```bash
make install          # Ubuntu/Debian
make install-alt      # ALT Linux p10
```

```bash
make install-deps     # + dev-зависимости (pytest, mypy, black, debhelper)
```

## Использование

```bash
snxui              # запустить с окном
snxui --minimized  # запустить в трей
snxui --debug      # с отладочным логом
```

## Разработка

```bash
make test           # pytest
make format         # black
make lint           # mypy + black --check
make deb            # собрать .deb пакет
```

## Сравнение с snx-rs

[snx-rs](https://github.com/ancwrd1/snx-rs) — независимая Rust-реализация того же протокола.

| | snxui (python\_ssl) | snx-rs |
|--|---------------------|--------|
| Язык | Python 3.10+ | Rust |
| GTK4 UI | ✅ встроен | ✅ отдельно — `snx-rs` daemon + snxctl |
| SSL туннель | ✅ | ✅ |
| IPSec (IKEv1/ESP) | ✗ не реализован | ✅ |
| RADIUS MultiChallenge | ✅ OTP один раз | ✅ |
| Пароль на диске | ✗ только keyring | ⚠ base64 в `snx-rs.conf` |
| Зависимость от бинарников | `pkexec` + `ip` | `snx-rs` + `snxctl` (~10 MB) |
| setcap на интерпретаторе | ✗ не нужен | ✗ setcap на snx-rs binary |
| Производительность | Python (GIL) | Rust, Tokio, zero-copy |

**Выбирайте snxui** если нужен GUI, RADIUS OTP работает через OTP-диалог,
и не нужен IPSec.

**Выбирайте snx-rs** если нужен IPSec, максимальная производительность,
или daemon без UI.

## Безопасность

- Пароли — только в системном keyring, не в JSON-профилях
- TUN-интерфейс создаётся через `pkexec snxui-net-helper` — root-права только у одного проверенного скрипта
- polkit `auth_self_keep` — любой пользователь (не только sudo/wheel) вводит **свой** пароль один раз за сессию
- Нет `shell=True` в subprocess-вызовах; IP-адреса и маршруты валидируются перед передачей хелперу
- `verify_ssl=True` по умолчанию; отключение только явным флагом в профиле

## Логи

```
~/.local/share/snxui/snxui.log
```
