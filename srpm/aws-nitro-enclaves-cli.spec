%define _nitro_cli_bin nitro-cli
%define _nitro_cli_blobs_dir %{_var}/nitro_cli
%define _vsock_proxy_bin vsock-proxy

%define _systemctl /bin/systemctl
%{?!_unitdir:%define _unitdir /lib/systemd/system}

%{?!_logrotate_confdir:%define _logrotate_confdir /etc/logrotate.d}

Summary:    AWS Nitro Enclaves tools for managing enclaves
Name:       aws-nitro-enclaves-cli
Version:    0.1
Release:    0%{?dist}

License:    Amazon Proprietary

BuildArch: x86_64

Source0: aws-nitro-enclaves-cli.tar.gz

BuildRequires: openssl-devel
BuildRequires: rust
BuildRequires: cargo
BuildRequires: make

Requires: systemd

Requires: docker
Requires: openssl
Requires: openssl-libs
Requires: curl


%description
AWS Nitro CLI a set of tools used for setting up and managing enclaves

%prep
%setup -c %{name}

%build
make nitro-cli-native
make vsock-proxy-native

%install
NITRO_CLI_INSTALL_DIR=%{buildroot} make install-tools

%post
%{_systemctl} --system daemon-reload
if [ $1 -eq 2 ]; then
	# upgrade package
	%{_systemctl} restart %{_vsock_proxy_bin}.service 2>&1 || :
else
	# install package
	%{_systemctl} enable %{_vsock_proxy_bin}.service 2>&1 || :
	%{_systemctl} start %{_vsock_proxy_bin}.service 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
	# uninstall package
	%{_systemctl} --no-reload disable %{_vsock_proxy_bin}.service 2>&1 || :
	%{_systemctl} stop %{_vsock_proxy_bin}.service 2>&1 || :
fi

%clean
make clean

%files
%defattr(0755,root,root,0755)

%{_sbindir}/%{_nitro_cli_bin}
%{_sbindir}/%{_vsock_proxy_bin}

/var/vsock_proxy/config.yaml
%dir %{_nitro_cli_blobs_dir}

%attr(0644,root,root) %{_unitdir}/%{_vsock_proxy_bin}.service

%attr(0644,root,root) %{_logrotate_confdir}/%{_vsock_proxy_bin}

%changelog
* Wed Mar 25 2020 Alexandru Gheorghe <aggh@amazon.com> - 0.1-0
- Initial draft
