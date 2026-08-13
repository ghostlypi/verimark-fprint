%global tod_driver_dir %{_libdir}/libfprint-2/tod-1
%global module_name libfprint-tod-verimark.so

Name:           verimark-fprint
Version:        0.1.0
Release:        1%{?dist}
Summary:        libfprint driver for the Kensington VeriMark Desktop 2.0 fingerprint reader

License:        BSD-3-Clause
URL:            https://github.com/ghostlypi/verimark-fprint
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  meson >= 0.59
BuildRequires:  ninja-build
BuildRequires:  pkgconfig(libfprint-2-tod-1)
BuildRequires:  pkgconfig(openssl) >= 3.0
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gmodule-2.0)

# The driver is a plugin loaded by libfprint-tod at runtime.
Requires:       libfprint-tod%{?_isa}
# fprintd exposes it over D-Bus; GNOME and PAM talk to fprintd, not libfprint.
Requires:       fprintd
Recommends:     fprintd-pam
# used by %%post / %%postun and by "verimark-setup"
Requires:       authselect

# Only meaningful on machines that have the reader, but harmless otherwise.
Supplements:    (libfprint-tod and fprintd)

%description
A libfprint Touch OEM Driver (TOD) plugin for the Kensington VeriMark Desktop
2.0 (USB 047d:8228), a Realtek RTS5816-class match-on-chip fingerprint sensor.

The sensor speaks the Realtek bulk protocol, but gates enrollment behind
Microsoft's Secure Device Connection Protocol (SDCP): the host must complete an
ECDH P-256 handshake against the sensor's attestation certificate and prove
knowledge of the derived key before the device will store a template. This
driver implements that handshake, so enrollment and matching both work natively
on Linux without any vendor blob.

Because it ships as a TOD plugin rather than a libfprint patch, it survives
distribution updates to libfprint.

Installing this package does not change your authentication configuration. Run
"verimark-setup enable" to turn on fingerprint login, sudo and polkit. Your
password continues to work either way, so a sensor that stops responding can
never lock you out.

%prep
%autosetup -n %{name}-%{version}

%build
%meson -Dtod_driver_dir=%{tod_driver_dir}
%meson_build

%install
%meson_install

%post
# The plugin must carry the same SELinux label as libfprint's own drivers.
if [ -x /usr/sbin/restorecon ]; then
    /usr/sbin/restorecon -F %{tod_driver_dir}/%{module_name} >/dev/null 2>&1 || :
fi
# fprintd is D-Bus activated; drop any running instance so it picks up the driver.
systemctl try-restart fprintd.service >/dev/null 2>&1 || :

if [ $1 -eq 1 ]; then
    cat <<'EOF'

verimark-fprint: driver installed. To turn on fingerprint login/sudo/polkit:

    sudo verimark-setup enable

This is deliberately not done automatically: it runs authselect, which
regenerates the system dconf databases, and on GNOME 50.4 that has been
observed to crash gnome-shell and end the session. Run it from a TTY or
right after a fresh boot, before you have work open.

EOF
fi

%postun
if [ $1 -eq 0 ]; then
    systemctl try-restart fprintd.service >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc README.md docs/PROTOCOL.md
%{tod_driver_dir}/%{module_name}
%{_bindir}/verimark-setup
%{_bindir}/verimark-diag

%changelog
* Wed Aug 12 2026 Parth <mnmprop@gmail.com> - 0.1.0-1
- Initial package: native enrollment and matching over SDCP
