#!/bin/bash
# build-appimage.sh — сборка AppImage для snxui с бандленным Python
#
# Использование:
#   ./build-appimage.sh [VERSION] [PYTHON_VERSION] [ARCH]
#
# Примеры:
#   ./build-appimage.sh                        # v0.1.0, Python 3.11.10, текущая арх.
#   ./build-appimage.sh 1.0.0                  # версия 1.0.0
#   ./build-appimage.sh 1.0.0 3.12.7           # Python 3.12.7
#   ./build-appimage.sh 1.0.0 3.11.10 aarch64  # кросс-сборка (требует QEMU)
#
# Зависимости на машине сборки:
#   Ubuntu/Debian:
#     sudo apt install gcc pkg-config \
#       libgirepository1.0-dev libcairo2-dev libglib2.0-dev libdbus-1-dev
#   ALT Linux:
#     sudo apt-get install gcc pkg-config \
#       gobject-introspection-devel libcairo-devel glib2-devel libdbus-devel
#
# Что бандлится в AppImage:
#   + Python 3.x (python-build-standalone)
#   + PyGObject, pexpect, keyring, SecretStorage, filelock, dbus-python
#   + GLib/GObject/Gio typelibs (базовые, от gobject-introspection)
#
# Что берётся из системы целевой машины:
#   ~ GTK4 (libgtk-4.so)      — ALT Linux p10: libgtk4
#   ~ libadwaita               — ALT Linux p10: libadwaita
#   ~ GTK4/Adw typelibs        — ALT Linux p10: libgtk4-gir, libadwaita-gir
#   ~ libsecret                — ALT Linux p10: libsecret
#   ~ libdbus-1                — везде есть
#   ~ polkit/pkexec            — ALT Linux p10: polkit
#   ~ libgirepository-1.0      — ALT Linux p10: gobject-introspection

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

VERSION="${1:-$(tr -d '[:space:]' < "${PROJECT_ROOT}/VERSION" 2>/dev/null || echo "0.0.0")}"
PYTHON_VERSION="${2:-3.11.10}"
ARCH="${3:-$(uname -m)}"

# Тег релиза python-build-standalone (дата): github.com/indygreg/python-build-standalone
PBS_RELEASE="${PBS_RELEASE:-20241016}"

APPDIR="${PROJECT_ROOT}/AppDir"
BUILD_CACHE="${PROJECT_ROOT}/.appimage-cache"

_PY_ARCHIVE="cpython-${PYTHON_VERSION}+${PBS_RELEASE}-${ARCH}-unknown-linux-gnu-install_only.tar.gz"
_PY_URL="https://github.com/indygreg/python-build-standalone/releases/download/${PBS_RELEASE}/${_PY_ARCHIVE}"
# Файл-слепок SHA256 рядом с кешем — фиксирует хеш при первой загрузке.
# Для проверки против заранее известного хеша задайте переменную окружения:
#   _PY_SHA256=<hex>  bash build-appimage.sh
# Найти актуальный хеш: https://github.com/indygreg/python-build-standalone/releases
_PY_SHA256_FILE="${BUILD_CACHE}/${_PY_ARCHIVE}.sha256"
_PY_SHA256="${_PY_SHA256:-}"

_APPIMAGETOOL_BIN="${BUILD_CACHE}/appimagetool-${ARCH}.AppImage"
_APPIMAGETOOL_SHA256_FILE="${BUILD_CACHE}/appimagetool-${ARCH}.AppImage.sha256"
# NOTE: 'continuous' is a mutable rolling tag. Once downloaded, the binary is
# locked via SHA256 stored alongside the cache. To update appimagetool, delete
# .appimage-cache/appimagetool-*.AppImage* and re-run the build.
_APPIMAGETOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage"

OUTPUT_APPIMAGE="${PROJECT_ROOT}/snxui-${VERSION}-${ARCH}.AppImage"

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

log()  { printf '\033[32m[snxui-appimage]\033[0m %s\n' "$*"; }
step() { printf '\033[36m[snxui-appimage]\033[0m \033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m[WARNING]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
    local cmd="$1" hint="${2:-}"
    command -v "${cmd}" &>/dev/null \
        || die "'${cmd}' не найден.${hint:+ Установите: ${hint}}"
}

download() {
    local url="$1" dest="$2" label="${3:-${url##*/}}"
    log "Загрузка: ${label}"
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O "${dest}.tmp" "${url}"
    elif command -v curl &>/dev/null; then
        curl -L --progress-bar -o "${dest}.tmp" "${url}"
    else
        die "Требуется wget или curl."
    fi
    mv "${dest}.tmp" "${dest}"
}

# ---------------------------------------------------------------------------
# 1. Проверка зависимостей сборки
# ---------------------------------------------------------------------------

check_build_deps() {
    step "1/7 Проверка зависимостей сборки"

    require_cmd gcc        "gcc / build-essential"
    require_cmd pkg-config "pkg-config"

    # gobject-introspection — нужен для pip install PyGObject
    pkg-config --exists gobject-introspection-1.0 2>/dev/null \
        || die "gobject-introspection-1.0 не найден.
  Ubuntu/Debian : sudo apt install libgirepository1.0-dev
  ALT Linux     : sudo apt-get install gobject-introspection-devel"

    # cairo — нужен для _gi_cairo.so (используется GTK4)
    pkg-config --exists cairo 2>/dev/null \
        || die "cairo dev-заголовки не найдены.
  Ubuntu/Debian : sudo apt install libcairo2-dev
  ALT Linux     : sudo apt-get install libcairo-devel"

    # dbus-1 — нужен для компиляции dbus-python (заголовок dbus/dbus.h)
    pkg-config --exists dbus-1 2>/dev/null \
        || die "dbus-1 dev-заголовки не найдены.
  Ubuntu/Debian : sudo apt install libdbus-1-dev
  ALT Linux     : sudo apt-get install libdbus-devel"

    # Определяем каталог системных typelibs для копирования базовых GLib/GObject/Gio
    local gi_repo
    gi_repo="$(pkg-config --variable=typelibdir gobject-introspection-1.0 2>/dev/null || true)"
    if [[ -z "${gi_repo}" || ! -d "${gi_repo}" ]]; then
        # Fallback: стандартные пути для x86_64 Ubuntu / ALT Linux
        for candidate in \
            "/usr/lib/${ARCH}-linux-gnu/girepository-1.0" \
            "/usr/lib/girepository-1.0" \
            "/usr/lib64/girepository-1.0"; do
            if [[ -d "${candidate}" ]]; then
                gi_repo="${candidate}"
                break
            fi
        done
    fi
    [[ -n "${gi_repo}" ]] \
        || die "Не удалось определить каталог GI typelibs."

    GI_REPO="${gi_repo}"
    log "GI typelibs: ${GI_REPO}"
}

# ---------------------------------------------------------------------------
# 2. Загрузка и установка Python (python-build-standalone)
# ---------------------------------------------------------------------------

setup_python() {
    step "2/7 Настройка Python ${PYTHON_VERSION} (${ARCH})"
    mkdir -p "${BUILD_CACHE}"

    local archive="${BUILD_CACHE}/${_PY_ARCHIVE}"
    if [[ ! -f "${archive}" ]]; then
        download "${_PY_URL}" "${archive}" "Python ${PYTHON_VERSION}"
        # Фиксируем SHA256 при первой загрузке
        sha256sum "${archive}" | awk '{print $1}' > "${_PY_SHA256_FILE}"
        log "Python archive SHA256 записан → $(cat "${_PY_SHA256_FILE}")"
    else
        log "Используем кеш: ${_PY_ARCHIVE}"
        # Проверяем целостность кеша
        if [[ -f "${_PY_SHA256_FILE}" ]]; then
            local expected actual
            expected=$(cat "${_PY_SHA256_FILE}")
            actual=$(sha256sum "${archive}" | awk '{print $1}')
            if [[ "${expected}" != "${actual}" ]]; then
                warn "Python archive: SHA256 не совпадает (кеш повреждён), перезагрузка..."
                download "${_PY_URL}" "${archive}" "Python ${PYTHON_VERSION}"
                sha256sum "${archive}" | awk '{print $1}' > "${_PY_SHA256_FILE}"
            fi
        else
            # Sidecar отсутствует (кеш перенесён без него) — создаём ретроспективно
            sha256sum "${archive}" | awk '{print $1}' > "${_PY_SHA256_FILE}"
            log "Python archive SHA256 записан (ретроспективно) → $(cat "${_PY_SHA256_FILE}")"
        fi
    fi

    # Если задан ожидаемый SHA256 — сверяем (опциональная внешняя пиннинг)
    if [[ -n "${_PY_SHA256}" ]]; then
        local actual_sha256
        actual_sha256=$(sha256sum "${archive}" | awk '{print $1}')
        if [[ "${actual_sha256}" != "${_PY_SHA256}" ]]; then
            rm -f "${archive}" "${_PY_SHA256_FILE}"
            die "Python archive SHA256 не совпадает с ожидаемым!
  Ожидался : ${_PY_SHA256}
  Получен  : ${actual_sha256}"
        fi
        log "Python archive SHA256 OK (внешняя верификация)."
    fi

    log "Распаковка Python в AppDir..."
    rm -rf "${APPDIR}"
    mkdir -p "${APPDIR}"
    tar -xf "${archive}" -C "${APPDIR}"

    # python-build-standalone распаковывается в директорию python/
    # Переносим в usr/ согласно FHS-структуре AppDir
    [[ -d "${APPDIR}/python" ]] \
        || die "Неожиданная структура архива: каталог python/ не найден."
    mv "${APPDIR}/python" "${APPDIR}/usr"

    PYTHON_BIN="${APPDIR}/usr/bin/python3"
    [[ -x "${PYTHON_BIN}" ]] \
        || die "Python binary не найден: ${PYTHON_BIN}"

    # Версия вида "3.11"
    PYTHON_XY="$("${PYTHON_BIN}" -c \
        'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"

    log "Python ${PYTHON_XY} готов."
}

# ---------------------------------------------------------------------------
# 3. Установка Python-зависимостей в бандленный Python
# ---------------------------------------------------------------------------

install_python_deps() {
    step "3/7 Установка Python-зависимостей"

    # Детерминированная установка: если рядом со скриптом есть lock-файл,
    # используем его (создаётся через: pip freeze > requirements-appimage.txt).
    # Без lock-файла pip разрешает >= ограничения на лету — результат меняется
    # при выходе новых версий пакетов.
    local lockfile="${SCRIPT_DIR}/requirements-appimage.txt"

    if [[ -f "${lockfile}" ]]; then
        log "Lock-файл найден — установка точно зафиксированных версий."
        "${PYTHON_BIN}" -m pip install --quiet -r "${lockfile}"
    else
        warn "requirements-appimage.txt не найден — используются >= ограничения (недетерминировано)."
        warn "Для воспроизводимых сборок создайте lock-файл:"
        warn "  \${PYTHON_BIN} -m pip install pexpect>=4.8 keyring>=24.0 SecretStorage>=3.3 filelock>=3.12 dbus-python>=1.3 PyGObject>=3.44"
        warn "  \${PYTHON_BIN} -m pip freeze > packaging/appimage/requirements-appimage.txt"

        log "Установка пакетов (pexpect, keyring, SecretStorage, filelock, dbus-python)..."
        "${PYTHON_BIN}" -m pip install --quiet \
            "pexpect>=4.8"        \
            "keyring>=24.0"       \
            "SecretStorage>=3.3"  \
            "filelock>=3.12"      \
            "dbus-python>=1.3"

        log "Установка PyGObject (требует dev-заголовки на машине сборки)..."
        "${PYTHON_BIN}" -m pip install --quiet "PyGObject>=3.44"
    fi

    log "Установка snxui..."
    "${PYTHON_BIN}" -m pip install --quiet --no-deps "${PROJECT_ROOT}"
}

# ---------------------------------------------------------------------------
# 4. Копирование GI typelibs
# ---------------------------------------------------------------------------

install_typelibs() {
    step "4/7 Копирование GI typelibs"

    local dest="${APPDIR}/usr/lib/girepository-1.0"
    mkdir -p "${dest}"

    # Бандлим только базовые typelibs от gobject-introspection.
    # GTK4, Adw, libsecret — берутся из системы целевой машины.
    # Бандленные typelibs используются как fallback (AppRun выставляет
    # GI_TYPELIB_PATH так, что системные пути идут первыми).
    local typelibs=(
        "GLib-2.0.typelib"
        "GObject-2.0.typelib"
        "Gio-2.0.typelib"
        "GModule-2.0.typelib"
    )

    local copied=0
    for tl in "${typelibs[@]}"; do
        if [[ -f "${GI_REPO}/${tl}" ]]; then
            cp "${GI_REPO}/${tl}" "${dest}/"
            log "  + ${tl}"
            copied=$(( copied + 1 ))
        else
            warn "typelib пропущен (не найден): ${GI_REPO}/${tl}"
        fi
    done

    log "${copied} typelib(s) скопировано."
}

# ---------------------------------------------------------------------------
# 5. Структура AppDir
# ---------------------------------------------------------------------------

setup_appdir_structure() {
    step "5/7 Структура AppDir"

    mkdir -p "${APPDIR}/usr/bin"
    mkdir -p "${APPDIR}/usr/share/applications"
    mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"
    mkdir -p "${APPDIR}/usr/share/polkit-1/actions"

    # Placeholder в usr/bin/ — appimagetool требует, чтобы здесь лежал
    # исполняемый файл с именем, совпадающим с Exec= в .desktop.
    # Реальный запуск приложения всегда идёт через AppRun.
    cat > "${APPDIR}/usr/bin/snxui" <<'WRAPPER'
#!/bin/sh
# Этот скрипт не вызывается напрямую: AppRun перехватывает запуск.
# Нужен только как placeholder в usr/bin/ для appimagetool.
exec "$(dirname "$(readlink -f "$0")")/python3" -m snxui.app "$@"
WRAPPER
    chmod +x "${APPDIR}/usr/bin/snxui"

    # Desktop-файл (минимальный — без %U и без системных полей)
    cat > "${APPDIR}/usr/share/applications/snxui.desktop" <<'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=SNX VPN
Name[ru]=SNX VPN
GenericName=VPN Client
GenericName[ru]=VPN-клиент
Comment=Check Point SNX VPN client for Linux
Comment[ru]=Клиент Check Point SNX VPN для Linux
Exec=snxui
Icon=snxui
Terminal=false
Categories=Network;Security;
Keywords=vpn;snx;checkpoint;network;
StartupNotify=true
StartupWMClass=snxui
DESKTOP

    # Иконка
    cp "${PROJECT_ROOT}/snxui/data/icons/snxui.svg" \
        "${APPDIR}/usr/share/icons/hicolor/scalable/apps/snxui.svg"

    # Polkit policy — кладём в AppDir, но устанавливается отдельно (требует root)
    cp "${PROJECT_ROOT}/snxui/data/com.snxui.policy" \
        "${APPDIR}/usr/share/polkit-1/actions/"

    # Привилегированный хелпер — кладём в AppDir для последующей ручной установки.
    # Пользователь должен скопировать его в /usr/lib/snxui/ (см. инструкцию ниже).
    mkdir -p "${APPDIR}/usr/lib/snxui"
    install -Dm755 "${PROJECT_ROOT}/snxui/helpers/snxui-net-helper" \
        "${APPDIR}/usr/lib/snxui/snxui-net-helper"

    # Корневые файлы AppImage (обязательны для спецификации AppImage)
    ln -sf "usr/share/icons/hicolor/scalable/apps/snxui.svg" "${APPDIR}/snxui.svg"
    cp "${APPDIR}/usr/share/applications/snxui.desktop"        "${APPDIR}/snxui.desktop"

    log "Структура AppDir готова."
}

# ---------------------------------------------------------------------------
# 6. AppRun — генерируется динамически с учётом версии Python
# ---------------------------------------------------------------------------

install_apprun() {
    step "6/7 Генерация AppRun"

    cat > "${APPDIR}/AppRun" <<APPRUN
#!/bin/bash
# AppRun для snxui AppImage
# Python ${PYTHON_VERSION} бандлован; GTK4 + libadwaita берутся из системы.

SELF=\$(readlink -f "\$0")
HERE=\${SELF%/*}

# ---------- Python окружение ------------------------------------------------
# PYTHONHOME — корень бандленного Python (stdlib, dynload, site-packages).
# PYTHONPATH — явно указываем site-packages для надёжности.
export PYTHONHOME="\${HERE}/usr"
export PYTHONPATH="\${HERE}/usr/lib/python${PYTHON_XY}/site-packages"

# ---------- Нативные .so (libpython, PyGObject, dbus-python и др.) ----------
# libpython${PYTHON_XY}.so.1.0 лежит в usr/lib/ внутри AppImage.
export LD_LIBRARY_PATH="\${HERE}/usr/lib:\${LD_LIBRARY_PATH:-}"

# ---------- GI typelibs -----------------------------------------------------
# Системные пути идут ПЕРВЫМИ — GTK4/Adw typelibs берутся из системы.
# Бандленные typelibs (GLib/GObject/Gio) — запасной вариант.
_sys_gi=""
for _d in \\
    "/usr/lib/\$(uname -m)-linux-gnu/girepository-1.0" \\
    "/usr/lib64/girepository-1.0"                       \\
    "/usr/lib/girepository-1.0"; do
    [ -d "\${_d}" ] && _sys_gi="\${_sys_gi}:\${_d}"
done
export GI_TYPELIB_PATH="\${_sys_gi}:\${HERE}/usr/lib/girepository-1.0:\${GI_TYPELIB_PATH:-}"
unset _sys_gi _d

# ---------- XDG данные ------------------------------------------------------
export XDG_DATA_DIRS="\${HERE}/usr/share:\${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"

# ---------- Запуск ----------------------------------------------------------
exec "\${HERE}/usr/bin/python3" -m snxui.app "\$@"
APPRUN

    chmod +x "${APPDIR}/AppRun"
    log "AppRun сгенерирован (Python ${PYTHON_XY})."
}

# ---------------------------------------------------------------------------
# 7. Сборка AppImage через appimagetool
# ---------------------------------------------------------------------------

build_appimage() {
    step "7/7 Сборка AppImage"

    if [[ ! -f "${_APPIMAGETOOL_BIN}" ]]; then
        download "${_APPIMAGETOOL_URL}" "${_APPIMAGETOOL_BIN}" "appimagetool"
        chmod +x "${_APPIMAGETOOL_BIN}"
        # Record SHA256 so future cache hits can verify binary integrity
        sha256sum "${_APPIMAGETOOL_BIN}" | awk '{print $1}' > "${_APPIMAGETOOL_SHA256_FILE}"
        log "appimagetool: SHA256 записан → $(cat "${_APPIMAGETOOL_SHA256_FILE}")"
    else
        log "appimagetool: используем кеш."
        # Verify cached binary has not been corrupted or silently replaced
        if [[ -f "${_APPIMAGETOOL_SHA256_FILE}" ]]; then
            local expected actual
            expected=$(cat "${_APPIMAGETOOL_SHA256_FILE}")
            actual=$(sha256sum "${_APPIMAGETOOL_BIN}" | awk '{print $1}')
            if [[ "${expected}" != "${actual}" ]]; then
                warn "appimagetool: SHA256 не совпадает (кеш повреждён), перезагрузка..."
                download "${_APPIMAGETOOL_URL}" "${_APPIMAGETOOL_BIN}" "appimagetool"
                chmod +x "${_APPIMAGETOOL_BIN}"
                sha256sum "${_APPIMAGETOOL_BIN}" | awk '{print $1}' > "${_APPIMAGETOOL_SHA256_FILE}"
            fi
        else
            # Sidecar отсутствует (кеш перенесён без него) — создаём ретроспективно
            sha256sum "${_APPIMAGETOOL_BIN}" | awk '{print $1}' > "${_APPIMAGETOOL_SHA256_FILE}"
            log "appimagetool: SHA256 записан (ретроспективно) → $(cat "${_APPIMAGETOOL_SHA256_FILE}")"
        fi
    fi

    rm -f "${OUTPUT_APPIMAGE}"

    # ARCH экспортируется для appimagetool (используется в имени файла)
    ARCH="${ARCH}" "${_APPIMAGETOOL_BIN}" --no-appstream \
        "${APPDIR}" "${OUTPUT_APPIMAGE}"

    log "AppImage создан: ${OUTPUT_APPIMAGE}"
    log "Размер: $(du -sh "${OUTPUT_APPIMAGE}" | cut -f1)"
}

# ---------------------------------------------------------------------------
# Постсборочная информация
# ---------------------------------------------------------------------------

print_summary() {
    printf '\n'
    printf '\033[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
    printf '  AppImage готов: \033[1m%s\033[0m\n' "$(basename "${OUTPUT_APPIMAGE}")"
    printf '\033[32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n'
    printf '\n'
    printf 'Требования на целевой машине (ALT Linux p10):\n'
    printf '  sudo apt-get install libgtk4 libadwaita libsecret polkit\n'
    printf '  sudo apt-get install libgtk4-gir libadwaita-gir\n'
    printf '\n'
    printf 'Однократная системная установка (нужен root):\n'
    printf '  # Извлечь файлы из AppImage:\n'
    printf '  ./%s --appimage-extract\n' "$(basename "${OUTPUT_APPIMAGE}")"
    printf '\n'
    printf '  # Установить привилегированный хелпер (pkexec использует его для TUN):\n'
    printf '  sudo install -Dm755 squashfs-root/usr/lib/snxui/snxui-net-helper \\\n'
    printf '    /usr/lib/snxui/snxui-net-helper\n'
    printf '\n'
    printf '  # Установить polkit policy:\n'
    printf '  sudo install -Dm644 squashfs-root/usr/share/polkit-1/actions/com.snxui.policy \\\n'
    printf '    /usr/share/polkit-1/actions/com.snxui.policy\n'
    printf '\n'
    printf 'Запуск:\n'
    printf '  chmod +x %s\n' "$(basename "${OUTPUT_APPIMAGE}")"
    printf '  ./%s\n' "$(basename "${OUTPUT_APPIMAGE}")"
    printf '\n'
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
    printf '\n'
    step "Сборка snxui AppImage v${VERSION} · Python ${PYTHON_VERSION} · ${ARCH}"
    printf '\n'

    check_build_deps
    setup_python
    install_python_deps
    install_typelibs
    setup_appdir_structure
    install_apprun
    build_appimage
    print_summary
}

main "$@"
