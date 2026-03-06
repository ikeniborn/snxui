Name:           snxui
Version:        0.0.0
Release:        1%{?dist}
Summary:        GUI client for Check Point SNX VPN on Linux
License:        MIT
URL:            https://github.com/snxui/snxui
BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel

Requires:       python3 >= 3.10
Requires:       python3-gobject >= 3.44
Requires:       gtk4
Requires:       libadwaita
Requires:       python3-dbus
Requires:       python3-keyring
Requires:       python3-secretstorage
Requires:       python3-filelock
Requires:       python3-pexpect
Requires:       libsecret
Requires:       polkit >= 0.105
Suggests:       libayatana-appindicator-gtk3

%description
SNX UI provides a graphical interface for the Check Point SNX VPN.
Uses a pure Python CCC + SSL/SLIM tunnel implementation — no SNX binary
or snx-rs required.

Features: profile management, RADIUS MultiChallenge OTP, secure credential
storage via the system keyring, system tray integration, and autostart.

Supports GNOME, KDE Plasma, XFCE and other desktop environments.

%prep
# Source is provided via the %%{srcdir} macro — no tarball to unpack.

%build
# Pure Python package — nothing to compile.

%install
cd %{srcdir}
python3 -m pip install \
    --no-deps \
    --root=%{buildroot} \
    --prefix=/usr \
    --no-compile \
    .

install -Dm755 snxui/helpers/snxui-net-helper \
    %{buildroot}/usr/lib/snxui/snxui-net-helper
install -Dm644 snxui/data/com.snxui.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/com.snxui.policy
install -Dm644 snxui/data/snxui.desktop \
    %{buildroot}%{_datadir}/applications/snxui.desktop
install -Dm644 snxui/data/icons/snxui.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/snxui.svg

%files
%{_bindir}/snxui
%{python3_sitelib}/snxui/
%{python3_sitelib}/snxui-*.dist-info/
/usr/lib/snxui/snxui-net-helper
%{_datadir}/polkit-1/actions/com.snxui.policy
%{_datadir}/applications/snxui.desktop
%{_datadir}/icons/hicolor/scalable/apps/snxui.svg

%changelog
* Wed Mar 04 2026 SNX UI Contributors <snxui@example.com> - 0.0.0-1
- Initial RPM packaging.
