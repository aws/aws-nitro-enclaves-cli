# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

%define ne_name nitro_enclaves
%define ne_group ne
%define ne_data_dir %{_datadir}/%{ne_name}
%define ne_include_dir %{_includedir}/%{ne_name}
%define ne_sysconf_dir %{_sysconfdir}/%{ne_name}
%define ne_log_dir /var/log/%{ne_name}
%define ne_log_file %{ne_name}.log
%define ne_run_dir /run/%{ne_name}

Summary:    AWS Nitro Enclaves tools for managing enclaves
Name:       aws-nitro-enclaves-cli
Version:    1.0
Release:    3%{?dist}

License:    Apache 2.0

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
make NITRO_CLI_INSTALL_DIR=%{buildroot} BIN_DIR=%{_bindir} UNIT_DIR=%{_unitdir} VAR_DIR=%{_var} install-tools

# -devel package: sources and include headers
mkdir -p %{buildroot}%{ne_include_dir}
cp -r include/* %{buildroot}%{ne_include_dir}/

# -integration-tests package
install -D -m 0755 run-nitro-cli-integration-tests %{buildroot}%{_bindir}/run-nitro-cli-integration-tests
mkdir -p %{buildroot}%{ne_data_dir}/tests/integration
cp -r tests/integration/* %{buildroot}%{ne_data_dir}/tests/integration/


%pre
groupadd -f %{ne_group}

%post
# Manually perform log file initialization steps
mkdir -p %{ne_log_dir}
chmod 775 %{ne_log_dir}
touch %{ne_log_dir}/%{ne_log_file}
chmod 664 %{ne_log_dir}/%{ne_log_file}
chown -R root:%{ne_group} %{ne_log_dir}

# Create tmpfs directory
echo "d " %{ne_run_dir} " 0775 root "%{ne_group} > /usr/lib/tmpfiles.d/%{ne_name}.conf
# Make directory available even without rebooting the system
systemd-tmpfiles --create /usr/lib/tmpfiles.d/%{ne_name}.conf

# Configure setup steps for the Nitro Enclaves driver (groups & udev rule)
echo "KERNEL==\"nitro_enclaves\", SUBSYSTEM==\"misc\", OWNER=\"root\", GROUP=\""%{ne_group}"\", \
    MODE=\"0660\", TAG+=\"systemd\"" > /usr/lib/udev/rules.d/99-nitro_enclaves.rules
udevadm trigger -y nitro_enclaves

echo -e "
    * In order to successfully run Nitro Enclaves, please add your user to group '"%{ne_group}"'"
echo -e "
    * Before being able to run enclaves, the system administrator must reserve the required
      resources (i.e. CPUs and memory). Edit the allocator configuration file at
      "%{ne_sysconf_dir}/allocator.yaml" and then start the allocator oneshot service:
      
        sudo systemctl start nitro-enclaves-allocator.service

      Resource allocation can be performed at system boot (recommended), by enabling
      the allocator service:

        sudo systemctl enable nitro-enclaves-allocator.service
"

%preun
# Uninstall services
%systemd_preun nitro-enclaves-vsock-proxy.service
%systemd_preun nitro-enclaves-allocator.service


%postun
# Remove any directory which was created by the driver as well as unload the driver
rm -f /usr/lib/modules-load.d/nitro_enclaves.conf
rm -f /usr/lib/udev/rules.d/99-nitro_enclaves.rules
rm -f /usr/lib/tmpfiles.d/nitro_enclaves.conf
rm -rf %{ne_run_dir}
rm -rf %{ne_log_dir}


%files
%{_bindir}/nitro-cli
%{_bindir}/vsock-proxy
%{_bindir}/nitro-enclaves-allocator
%{_unitdir}/nitro-enclaves-vsock-proxy.service
%{_unitdir}/nitro-enclaves-allocator.service
%config(noreplace) %{ne_sysconf_dir}/vsock-proxy.yaml
%config(noreplace) %{ne_sysconf_dir}/allocator.yaml


%files integration-tests
%{_bindir}/run-nitro-cli-integration-tests
%{ne_data_dir}/tests/*


%files devel
%{ne_data_dir}/blobs/*
%{ne_data_dir}/examples/*
%{ne_include_dir}/*

%changelog
* Mon Oct 19 2020 Gabriel Bercaru <dhr@amazon.com> - 1.0.3
- Changed license to Apache 2.0

* Sat Oct 17 2020 Dan Horobeanu <dhr@amazon.com> - 1.0-1
- Updated license to Apache-2.0
- General cleanup and resync with `make install` output

* Wed Oct 14 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0-0
- Include resources reservation service

* Wed Mar 25 2020 Alexandru Gheorghe <aggh@amazon.com> - 0.1-0
- Initial draft
