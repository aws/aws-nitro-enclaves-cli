%define _nitro_cli_bin nitro-cli
%define _vsock_proxy_bin vsock-proxy

Summary:    AWS Nitro Enclaves tools for managing enclaves
Name:       aws-nitro-enclaves-cli
Version:    0.1
Release:    1%{?dist}

License:    Amazon Proprietary

BuildArch: x86_64

Source0: aws-nitro-enclaves-cli.tar.gz
Source1: nitro-cli-dependencies.tar.gz

BuildRequires: openssl-devel
BuildRequires: rust >= 1.38
BuildRequires: cargo >= 1.38
BuildRequires: make
BuildRequires: systemd

%systemd_requires

Requires: systemd
Requires: docker
Requires: openssl
Requires: openssl-libs
Requires: curl
Requires: jq


%description
AWS Nitro CLI a set of tools used for setting up and managing enclaves

%prep
%setup -a 1 -c %{name}
mkdir .cargo
cp tools/cargo_vendor_config_template .cargo/config

%build
make nitro-cli-native
make vsock-proxy-native

%install
make NITRO_CLI_INSTALL_DIR=%{buildroot} SBIN_DIR=%{_sbindir} UNIT_DIR=%{_unitdir} VAR_DIR=%{_var} install-tools

%post
systemctl --system daemon-reload
%systemd_post %{_vsock_proxy_bin}.service
%systemd_postun_with_restart %{_vsock_proxy_bin}.service

%preun
%systemd_preun %{_vsock_proxy_bin}.service

%files
%defattr(0755,root,root,0755)

%{_sbindir}/%{_nitro_cli_bin}
%{_sbindir}/%{_vsock_proxy_bin}
%config(noreplace) %{_sysconfdir}/vsock_proxy/config.yaml

%attr(0644,root,root) %{_unitdir}/%{_vsock_proxy_bin}.service

%changelog
* Wed Mar 25 2020 Alexandru Gheorghe <aggh@amazon.com> - 0.1-0
- Initial draft
