%define _nitro_cli_bin nitro-cli
%define _vsock_proxy_bin vsock-proxy
%define _config_enclave_resources config-enclave-resources
%define _ne_log_path /var/log/nitro_enclaves
%define _ne_log_file nitro_enclaves.log

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
BuildRequires: llvm
BuildRequires: clang
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


%package integration-tests
Summary: RPM for running integration tests
Group: NitroEnclaves

Requires: python3-pip
Requires: python3

%description integration-tests
RPM for running integration tests for the AWS Nitro Enclaves CLI.


%package devel
Summary: Additional resources required by AWS Nitro CLI
Group: NitroEnclaves

%description devel
RPM containing additional resources required in order to build enclave images


%prep
%setup -a 1 -c %{name}
mkdir .cargo
cp tools/cargo_vendor_config_template .cargo/config


%build
make nitro-cli-native
make vsock-proxy-native


%install
# Main Nitro CLI tools installation
make NITRO_CLI_INSTALL_DIR=%{buildroot} SBIN_DIR=%{_sbindir} UNIT_DIR=%{_unitdir} VAR_DIR=%{_var} install-tools

# Resource configuration service and files
install -D -m 0755 config/service/%{_config_enclave_resources} %{buildroot}%{_sbindir}/%{_config_enclave_resources}
install -D -m 0644 config/service/%{_config_enclave_resources}.service %{buildroot}%{_unitdir}/%{_config_enclave_resources}.service
cp config/configs/ne_conf %{buildroot}%{_sysconfdir}
cp config/install %{buildroot}%{_sysconfdir}

# Blob files, needed in order to build EIFs
mkdir -p %{buildroot}%{_datadir}/nitro_enclaves/blobs/
cp blobs/* %{buildroot}%{_datadir}/nitro_enclaves/blobs/

# Directories needed by the integration tests subpackage
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_datadir}/nitro_enclaves/tests/integration/

install -D -m 0755 run-nitro-cli-integration-tests %{buildroot}%{_sbindir}/run-nitro-cli-integration-tests
install -D -m 0755 config/nitro-cli-config %{buildroot}%{_sbindir}/nitro-cli-config

cp -r tests/integration/* %{buildroot}%{_datadir}/nitro_enclaves/tests/integration/

cp -r drivers/ %{buildroot}%{_datadir}/nitro_enclaves/
cp -r include/ %{buildroot}%{_datadir}/nitro_enclaves/


%post
# Manually perform log file initialization steps
mkdir -p %{_ne_log_path}
chown root:ne %{_ne_log_path}
chmod 775 %{_ne_log_path}

touch %{_ne_log_path}/%{_ne_log_file}
chown root:ne %{_ne_log_path}/%{_ne_log_file}
chmod 766 %{_ne_log_path}/%{_ne_log_file}

# Configure setup steps for the Nitro Enclaves driver (groups & udev rule)
# Configure NE driver configuration file in order to auto load it
echo "install nitro_enclaves insmod nitro_enclaves.ko" > /usr/lib/modules-load.d/nitro_enclaves.conf
/etc/install /usr/share/nitro_enclaves/

# Configure vsock-proxy & config-enclave-resources services
systemctl --system daemon-reload
%systemd_post %{_vsock_proxy_bin}.service
%systemd_postun_with_restart %{_vsock_proxy_bin}.service

%systemd_post %{_config_enclave_resources}.service

systemctl enable %{_vsock_proxy_bin}.service
systemctl start %{_vsock_proxy_bin}.service
systemctl enable %{_config_enclave_resources}.service
systemctl start %{_config_enclave_resources}.service

%post devel
chown root:ne /usr/share/nitro_enclaves/blobs

%preun
# Uninstall services
%systemd_preun %{_vsock_proxy_bin}.service

%systemd_preun %{_config_enclave_resources}.service


%postun
# Remove any directory which was created by the driver as well as unload the driver
rm /usr/lib/modules-load.d/nitro_enclaves.conf
rm -rf /var/run/nitro_enclaves/
rm -rf /var/log/nitro_enclaves/


%files
%defattr(0755,root,root,0755)

%{_sbindir}/%{_nitro_cli_bin}
%{_sbindir}/%{_vsock_proxy_bin}
%config(noreplace) %{_sysconfdir}/vsock_proxy/config.yaml

%attr(0644,root,root) %{_unitdir}/%{_vsock_proxy_bin}.service

%attr(0755,root,root) %{_sbindir}/%{_config_enclave_resources}
%attr(0644,root,root) %{_unitdir}/%{_config_enclave_resources}.service
%attr(0755,root,root) %{_sysconfdir}/install
%attr(0766,root,ne) %{_sysconfdir}/ne_conf

%files integration-tests
%defattr(0755,root,root,0755)

%{_sbindir}/run-nitro-cli-integration-tests
%{_sbindir}/nitro-cli-config
%{_datadir}/nitro_enclaves/*


%files devel
%attr(0755,root,ne) %{_datadir}/nitro_enclaves/blobs/init
%attr(0755,root,ne) %{_datadir}/nitro_enclaves/blobs/linuxkit
%attr(0644,root,ne) %{_datadir}/nitro_enclaves/blobs/bzImage
%attr(0644,root,ne) %{_datadir}/nitro_enclaves/blobs/cmdline
%attr(0644,root,ne) %{_datadir}/nitro_enclaves/blobs/nsm.ko

%changelog
* Wed Mar 25 2020 Alexandru Gheorghe <aggh@amazon.com> - 0.1-0
- Initial draft
