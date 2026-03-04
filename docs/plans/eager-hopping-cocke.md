# Трафик и скорость VPN в трее (tooltip + UI)

## Контекст

Пользователь хочет видеть входящий/исходящий трафик и скорость соединения рядом с иконкой трея. Основной способ отображения — tooltip при наведении на иконку. Дополнительно — мини-строка в главном окне.

Сейчас `TrayManager.set_connected()` показывает только имя профиля. Никаких данных о трафике в коде нет. Монитор SNXBinaryBackend (`_monitor_connection`, 5s) только проверяет существование интерфейса и IP.

---

## Источник данных

`/proc/net/dev` — встроенный в ядро Linux счётчик байт per-interface. Нет subprocess, нет sudo. Формат:

```
 tunsnx:  RX_BYTES packets errs ... TX_BYTES packets errs ...
```

Поля: `[0]` = rx_bytes, `[8]` = tx_bytes. Читается через `open()` — ~0.1 мс.

Интерфейс: `tunsnx` (SNX binary) или `tunsnx0` (snx-rs). `TrafficMonitor` сам находит нужный по наличию в `/proc/net/dev`.

---

## Архитектура

```
HomePage._apply_connected()
    ├── TrafficMonitor.start(iface)      # GLib.timeout_add(3000, _tick)
    │       └── каждые 3s: читает /proc/net/dev → вычисляет скорость
    │           → callback(rx_bps, tx_bps, rx_total, tx_total)
    │               → TrayManager.set_connected(True, name, rx_bps, tx_bps, ...)
    │               → HomePage._speed_label обновляется
    └── (существующий путь через GLib.idle_add остаётся без изменений)

HomePage._apply_disconnected/_apply_error()
    └── TrafficMonitor.stop()            # отменяет GLib timer
```

**Почему `GLib.timeout_add` а не thread?** Таймер GLib работает в GTK main thread. Не нужен lock, не нужен Event. D-Bus обновление tooltip тоже выполняется в glib mainloop. Идеальное совпадение.

**Почему не в `ConnectionStatus`?** `ConnectionStatus` — одноразовый snapshot события. Трафик меняется непрерывно — для него нужен отдельный цикл обновлений.

---

## Формат tooltip (результат)

```
SNX VPN — Подключено
Профиль: Work VPN
↓ 2.4 MB/s   ↑ 320 KB/s
Получено: 145 MB · Отправлено: 23 MB
```

*(Если данные ещё не получены — только имя профиля)*

---

## Файлы

### CREATE `snxui/system/traffic_monitor.py` (~90 LOC)

```python
class TrafficMonitor:
    def __init__(self, callback: Callable[[float, float, int, int], None]) -> None
    def start(self, iface: str = "tunsnx") -> None   # GLib.timeout_add(3000, _tick)
    def stop(self) -> None                            # GLib.source_remove(_timer_id)
    def _tick(self) -> bool                          # True=continue, False=stop

def _read_iface_bytes(iface: str) -> Optional[tuple[int, int]]  # /proc/net/dev parser
def format_speed(bps: float) -> str                              # "2.4 MB/s", "320 KB/s"
def format_bytes(total: int) -> str                              # "145 MB", "1.2 GB"
```

Логика `_tick`:
1. Читает `/proc/net/dev` для заданного iface
2. Если iface не найден — `stop()` (VPN отключился)
3. Вычисляет `delta_bytes / delta_time` = скорость в bps
4. Вызывает `callback(rx_bps, tx_bps, rx_total_from_start, tx_total_from_start)`
5. Возвращает `GLib.SOURCE_CONTINUE`

### MODIFY `snxui/system/tray_manager.py`

Расширить `set_connected()`:
```python
def set_connected(
    self, connected: bool, profile_name: str = "",
    rx_bps: Optional[float] = None, tx_bps: Optional[float] = None,
    rx_total: Optional[int] = None, tx_total: Optional[int] = None,
) -> None:
    body = f"Профиль: {profile_name}" if profile_name else "VPN активен"
    if rx_bps is not None:
        body += f"\n↓ {format_speed(rx_bps)}   ↑ {format_speed(tx_bps)}"
        body += f"\nПолучено: {format_bytes(rx_total)} · Отправлено: {format_bytes(tx_total)}"
```

Импорт `format_speed`, `format_bytes` из `traffic_monitor`.

### MODIFY `snxui/ui/home_page.py`

**`__init__`**: `self._traffic: Optional[TrafficMonitor] = None`, `self._last_profile_name: str = ""`

**`_build_status_group()`**: после `self._info_label` добавить:
```python
self._speed_label = Gtk.Label()
self._speed_label.add_css_class("caption")   # мелкий шрифт Adwaita
self._speed_label.set_visible(False)
```

**`_apply_connected(status)`**:
```python
self._last_profile_name = status.profile.name or status.profile.server if status.profile else ""
iface = status.interface or "tunsnx"
if self._traffic:
    self._traffic.stop()
self._traffic = TrafficMonitor(self._on_traffic_update)
self._traffic.start(iface)
```

**`_apply_disconnected()` и `_apply_error()`**: добавить stop трафика:
```python
if self._traffic:
    self._traffic.stop()
    self._traffic = None
self._speed_label.set_visible(False)
```

**`_on_traffic_update(rx_bps, tx_bps, rx_total, tx_total)`** (вызывается в main thread):
```python
self._speed_label.set_label(f"↓ {format_speed(rx_bps)}  ↑ {format_speed(tx_bps)}")
self._speed_label.set_visible(True)
if self._tray:
    self._tray.set_connected(True, self._last_profile_name, rx_bps, tx_bps, rx_total, tx_total)
```

### CREATE `tests/test_traffic_monitor.py` (~60 LOC)

- Тесты `format_speed()` и `format_bytes()` (граничные значения: B/s, KB/s, MB/s, GB)
- `test_read_iface_bytes_found` — мокирует содержимое `/proc/net/dev`
- `test_read_iface_bytes_not_found` — интерфейса нет, возвращает None
- `test_traffic_monitor_stop_without_start` — не падает
- `test_traffic_monitor_callback_called` — мокирует GLib и файл, проверяет callback

---

## Критические файлы

| Файл | Действие |
|------|----------|
| `snxui/system/traffic_monitor.py` | CREATE |
| `snxui/system/tray_manager.py` | MODIFY (set_connected signature + body) |
| `snxui/ui/home_page.py` | MODIFY (speed_label + TrafficMonitor lifecycle) |
| `tests/test_traffic_monitor.py` | CREATE |

---

## Верификация

```bash
# 1. Тесты
.venv/bin/python -m pytest tests/test_traffic_monitor.py -v
.venv/bin/python -m pytest tests/ -q   # все 618+ должны пройти

# 2. Проверить вручную (пока VPN подключён)
cat /proc/net/dev | grep tunsnx        # видим RX/TX байты

# 3. Запуск приложения
snxui --debug   # подключиться → навести на иконку трея
                # ожидаем: через 3s в tooltip появляется скорость и объём
                # ожидаем: в главном окне под IP-строкой — мини-лейбл со скоростью
```
