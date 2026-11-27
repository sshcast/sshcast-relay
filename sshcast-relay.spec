%global debug_package %{nil}
%global rustflags_codegen_units 16

Name:           sshcast-relay
Version:        0.1.1
Release:        1%{?dist}
Summary:        Target Host Relay Daemon for Sshcast Roaming SSH Agent
License:        MIT OR Apache-2.0
URL:            https://github.com/sshcast/sshcast-relay
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sshcast Target Host Relay (sshcast-relay) is a systemd --user socket-activated
daemon listening on /run/user/$UID/sshcast.sock. It inspects deep caller
process ancestry (/proc/<pid>), parses RFC 4252 SSH authentication requests,
cryptographically signs SignRequests with its node Ed25519 key, and forwards
them over gRPC to sshcast-server.

%prep
%autosetup -n %{name}-%{version}

%build
export CARGO_BUILD_JOBS="${RPM_BUILD_NCPUS:-$(nproc)}"
if [ -d vendor ]; then
    cargo build %{?_smp_mflags} --release --offline --locked --bins
else
    cargo build %{?_smp_mflags} --release --locked --bins
fi

%check
export CARGO_BUILD_JOBS="${RPM_BUILD_NCPUS:-$(nproc)}"
if [ -d vendor ]; then
    cargo test %{?_smp_mflags} --release --offline --locked
else
    cargo test %{?_smp_mflags} --release --locked
fi

%install
install -D -m 0755 target/release/sshcast-relay %{buildroot}%{_bindir}/sshcast-relay
install -D -m 0644 systemd/sshcast-relay.socket %{buildroot}%{_userunitdir}/sshcast-relay.socket
install -D -m 0644 systemd/sshcast-relay.service %{buildroot}%{_userunitdir}/sshcast-relay.service
install -D -m 0644 systemd/sshcast-zellij-web.service %{buildroot}%{_userunitdir}/sshcast-zellij-web.service
install -D -m 0644 systemd/sshcast-relay.sh %{buildroot}%{_sysconfdir}/profile.d/sshcast-relay.sh
install -D -m 0644 systemd/sshcast-relay.fish %{buildroot}%{_sysconfdir}/fish/conf.d/sshcast-relay.fish

%post
%systemd_user_post sshcast-relay.socket sshcast-relay.service sshcast-zellij-web.service
if [ $1 -ge 2 ] && [ -x "/usr/lib/systemd/systemd-update-helper" ]; then
    /usr/lib/systemd/systemd-update-helper mark-restart-user-units sshcast-relay.service || :
fi

%preun
%systemd_user_preun sshcast-relay.socket sshcast-relay.service sshcast-zellij-web.service

%postun
%systemd_user_postun_with_restart sshcast-relay.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc doc/roaming_ssh_agent_architecture_spec.md
%{_bindir}/sshcast-relay
%{_userunitdir}/sshcast-relay.socket
%{_userunitdir}/sshcast-relay.service
%{_userunitdir}/sshcast-zellij-web.service
%config(noreplace) %{_sysconfdir}/profile.d/sshcast-relay.sh
%config(noreplace) %{_sysconfdir}/fish/conf.d/sshcast-relay.fish

%changelog
* Fri Nov 27 2026 Paul Komkoff <i@stingr.net> - 0.1.1-1
- Prompt before overwriting existing relay.toml on init (--force to skip) and restart running sshcast-relay.service

* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sshcast-relay
