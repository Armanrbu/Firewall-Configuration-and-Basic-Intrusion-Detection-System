Name:           netguard-ids
Version:        2.0.0
Release:        1%{?dist}
Summary:        Advanced Firewall and Intrusion Detection System with ML anomaly detection

License:        MIT
URL:            https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System
Source0:        %{name}-%{version}.tar.gz

BuildArch:      x86_64
BuildRequires:  python3-devel >= 3.10
BuildRequires:  python3-pip
BuildRequires:  systemd-rpm-macros

Requires:       python3 >= 3.10
Requires:       python3-pip
Requires:       iptables >= 1.8
Requires:       libpcap
Recommends:     python3-libpcap

%description
NetGuard IDS is a production-ready network security tool that combines a
stateful firewall controller with an ML-powered intrusion detection engine.

Features:
  * Real-time connection monitoring via psutil / pcap
  * Rule-based and ML anomaly detection (IsolationForest, ECOD)
  * Deep Packet Inspection plugin with 7 signature categories
  * Config hot-reload and ML A/B testing
  * REST API (FastAPI), CLI (Typer), and PySide6 GUI frontends
  * Docker and systemd deployment support

%prep
%setup -q

%build
python3 -m pip install --no-deps --ignore-installed \
    --prefix=%{buildroot}/opt/netguard-ids \
    .

%install
mkdir -p %{buildroot}/opt/netguard-ids
mkdir -p %{buildroot}/etc/netguard
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/usr/share/doc/%{name}
mkdir -p %{buildroot}/var/log/netguard

install -m 644 config.yaml   %{buildroot}/etc/netguard/config.yaml
install -m 644 rules/builtin.yaml %{buildroot}/opt/netguard-ids/builtin.yaml

# Wrapper scripts
cat > %{buildroot}/usr/bin/netguard << 'EOF'
#!/bin/bash
exec python3 -m main "$@"
EOF
cat > %{buildroot}/usr/bin/netguard-cli << 'EOF'
#!/bin/bash
exec python3 -m cli "$@"
EOF
chmod 755 %{buildroot}/usr/bin/netguard
chmod 755 %{buildroot}/usr/bin/netguard-cli

# systemd unit
install -m 644 packaging/linux/netguard-ids.service \
    %{buildroot}/lib/systemd/system/netguard-ids.service

%post
%systemd_post netguard-ids.service

%preun
%systemd_preun netguard-ids.service

%postun
%systemd_postun_with_restart netguard-ids.service

%files
%license LICENSE
%doc CHANGELOG.md README.md
/opt/netguard-ids/
/etc/netguard/
%{_bindir}/netguard
%{_bindir}/netguard-cli
/lib/systemd/system/netguard-ids.service
%dir /var/log/netguard

%changelog
* Thu Mar 12 2026 Arman <arman@example.com> - 2.0.0-1
- v2.0.0: Advanced Features — DPI, ML A/B testing, hot-reload, flow viz
* Wed Jan 01 2025 Arman <arman@example.com> - 1.0.0-1
- Initial RPM package
