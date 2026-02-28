# SNX VPN GUI Client

Graphical client for Check Point SNX VPN on Ubuntu/Debian with support for GNOME, KDE Plasma, and XFCE.

## Features

- Profile management (multiple server connections)
- Secure password storage (GNOME Keyring / KDE Wallet)
- System tray with quick connect/disconnect
- Autostart on login
- Install as .deb or AppImage

## Requirements

- Ubuntu 22.04+ / Debian 12+
- Python 3.10+
- GTK4 + Libadwaita
- Check Point SNX binary (snx)
- polkit >= 0.105

## Installation

### Option 1: pip (development)

```bash
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-dbus \
    python3-keyring python3-secretstorage python3-pexpect python3-filelock
pip install -e .
# Install polkit policy (requires sudo)
sudo install -m644 snxui/data/com.snxui.policy /usr/share/polkit-1/actions/
```

### Option 2: make install

```bash
make install-deps
make install
```

## Usage

```bash
snxui              # launch with window
snxui --minimized  # launch to tray
snxui --debug      # with debug logging
```

## Security

- Passwords are stored in the system keyring (libsecret/KDE Wallet), not in files
- SNX is launched with root privileges via polkit (no sudo password in the UI)
- Profiles are stored in `~/.config/snxui/profiles.json` (without passwords)
- Logs in `~/.local/share/snxui/snxui.log`

## Development

```bash
make test           # run tests
make test-coverage  # tests with coverage report
make format         # format with black
make lint           # mypy + black check
```
