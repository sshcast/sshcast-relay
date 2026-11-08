%global debug_package %{nil}

Name:           sockcast-relay
Version:        0.1.0
Release:        1%{?dist}
Summary:        Target Host Relay Daemon for Sockcast Roaming SSH Agent
License:        MIT OR Apache-2.0
URL:            https://github.com/theraphim/sockcast-relay
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sockcast Target Host Relay (sockcast-relay) is a systemd --user socket-activated
daemon listening on /run/user/$UID/sockcast.sock. It inspects deep caller
process ancestry (/proc/<pid>), parses RFC 4252 SSH authentication requests,
cryptographically signs SignRequests with its node Ed25519 key, and forwards
them over gRPC to sockcast-server.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --frozen --offline

%check
cargo test --release --frozen --offline

%install
install -D -m 0755 target/release/sockcast-relay %{buildroot}%{_bindir}/sockcast-relay
install -D -m 0644 systemd/sockcast-relay.socket %{buildroot}%{_userunitdir}/sockcast-relay.socket
install -D -m 0644 systemd/sockcast-relay.service %{buildroot}%{_userunitdir}/sockcast-relay.service
install -D -m 0644 systemd/sockcast-relay.sh %{buildroot}%{_sysconfdir}/profile.d/sockcast-relay.sh

%post
%systemd_user_post sockcast-relay.socket sockcast-relay.service

%preun
%systemd_user_preun sockcast-relay.socket sockcast-relay.service

%files
%doc doc/roaming_ssh_agent_architecture_spec.md
%{_bindir}/sockcast-relay
%{_userunitdir}/sockcast-relay.socket
%{_userunitdir}/sockcast-relay.service
%config(noreplace) %{_sysconfdir}/profile.d/sockcast-relay.sh

%changelog
* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sockcast-relay
