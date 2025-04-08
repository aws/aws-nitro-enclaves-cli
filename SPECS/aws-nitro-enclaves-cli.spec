# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

%define ne_name nitro_enclaves
%define ne_group ne
%define ne_data_dir %{_datadir}/%{ne_name}
%define ne_include_dir %{_includedir}/%{ne_name}
%define ne_sysconf_dir %{_sysconfdir}/%{ne_name}
%define ne_log_dir %{_localstatedir}/log/%{ne_name}
%define ne_log_file %{ne_name}.log
%define ne_run_dir %{_rundir}/%{ne_name}

%define _src_dir %{_builddir}/%{name}-%{version}
%define _licenses_filename THIRD_PARTY_LICENSES
%define _third_party_licenses_file %{_datadir}/licenses/%{name}-%{version}/%{_licenses_filename}
%define _pkg_licenses_file %{_src_dir}/%{_licenses_filename}

# Stop mangling shebangs for scripts from examples
%global __brp_mangle_shebangs_exclude_from %{ne_data_dir}/examples/

Summary:    AWS Nitro Enclaves tools for managing enclaves
Name:       aws-nitro-enclaves-cli
Version:    1.4.2
Release:    0%{?dist}

License:    Apache 2.0

ExclusiveArch: x86_64 aarch64

Source0: aws-nitro-enclaves-cli.tar.gz
Source1: nitro-cli-dependencies.tar.gz

BuildRequires: openssl-devel
BuildRequires: rust >= 1.71
BuildRequires: cargo >= 1.71
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
install -D -m0644 %{_pkg_licenses_file} %{buildroot}%{_third_party_licenses_file}

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
chgrp %{ne_group} /dev/%{ne_name}

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
if [ $1 -ne 1 ]; then
    # Any operation except for package upgrade
    # Remove any directory which was created by the driver as well as unload the driver
    rm -f /usr/lib/modules-load.d/nitro_enclaves.conf
    rm -f /usr/lib/udev/rules.d/99-nitro_enclaves.rules
    rm -f /usr/lib/tmpfiles.d/nitro_enclaves.conf
    rm -rf %{ne_run_dir}
    rm -rf %{ne_log_dir}
fi


%triggerpostun -- aws-nitro-enclaves-cli = 1.0
# When uninstalling v1.0-5 of aws-nitro-enclaves-cli (during an update),
# make sure to bring in again files removed by the buggy version
if [ $1 -eq 2 ]; then
    mkdir -p %{ne_log_dir}
    chmod 775 %{ne_log_dir}
    touch %{ne_log_dir}/%{ne_log_file}
    chmod 664 %{ne_log_dir}/%{ne_log_file}
    chown -R root:%{ne_group} %{ne_log_dir}

    # (Re)create tmpfs directory
    echo "d " %{ne_run_dir} " 0775 root "%{ne_group} > /usr/lib/tmpfiles.d/%{ne_name}.conf
    # Make directory available even without rebooting the system
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/%{ne_name}.conf

    # (Re)configure setup steps for the Nitro Enclaves driver (groups & udev rule)
    echo "KERNEL==\"nitro_enclaves\", SUBSYSTEM==\"misc\", OWNER=\"root\", GROUP=\""%{ne_group}"\", \
        MODE=\"0660\", TAG+=\"systemd\"" > /usr/lib/udev/rules.d/99-nitro_enclaves.rules
    udevadm trigger -y nitro_enclaves
    chgrp %{ne_group} /dev/%{ne_name}
fi


%files
%{_bindir}/nitro-cli
%{_bindir}/vsock-proxy
%{_bindir}/nitro-enclaves-allocator
%{_third_party_licenses_file}
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
* Wed Mar 19 2025 Costin Lupu <lvpv@amazon.com> - 1.4.2-0
- bump ring from 0.17.13 to 0.17.14

* Tue Mar 18 2025 Costin Lupu <lvpv@amazon.com> - 1.4.1-0
- build(deps): bump hickory-resolver from 0.24.2 to 0.24.4
- build(deps): bump ring from 0.17.8 to 0.17.13
- Update env.sh
- Update Makefile
- command_executer - recv infinite loop
- build(deps): bump vsock from 0.3.0 to 0.5.1
- build(deps): bump hickory-proto from 0.24.2 to 0.24.3
- build(deps): bump tempfile from 3.15.0 to 3.16.0
- Bump openssl

* Fri Jan 31 2025 Mark Kirichenko <mkirich@amazon.de> - 1.4.0-0
- nitro-cli: allow to use KMS keys to sign EIFs during build
- nitro-cli: add command to sign pre-built EIFs
- rust: bump MSRV to 1.71
- build(deps): bump idna to 1.0.3
- build(deps): replace yaml-rust with yaml-rust2
- build(deps): replace serde_cbor with ciborium
- build(deps): bump Clap to 4.4
- ci: unpin version for cargo-audit
- ci: add Unicode-3.0 and OpenSSL to allowed licenses

* Mon Oct 21 2024 Leonard Foerster <foersleo@amazon.com> - 1.3.4-0
- blobs: Update linuxkit to version 1.5.2

* Thu Sep 5 2024 Leonard Foerster <foersleo@amazon.com> - 1.3.3-0
- blobs: Update linuxkit to version 1.5.0
- Update sources for 1.3.2 release

* Wed Jul 24 2024 Eugene Koira <eugkoira@amazon.com> - 1.3.2-0
- nitro-cli: Update enclave boot timeout based on allocated memory
- clippy: resolve build errors for Rust 1.79
- blobs: Update linuxkit binaries to version based on v1.2.0
- scripts/run_tests.sh: Add check dependencies

* Mon Jun 3 2024 Erdem Meydanli <meydanli@amazon.com> - 1.3.1-0
- vsock-proxy: Bump version to 1.0.1
- vsock_proxy: Use system-configured nameservers for DNS resolution
- Update init blob to support user namespaces
- clippy: resolve build errors for Rust 1.78

* Tue Apr 16 2024 Erdem Meydanli <meydanli@amazon.com> - 1.3.0-0
+ This release focuses on resolving two critical issues:
the vsock-proxy DNS lookup limitation (#553) and the compatibility
problem with Docker versions 25 and later (#591). Furthermore, it
updates several important crate dependencies to their latest versions.
- cargo: Update cargo.lock to eliminate build failures
- build(deps): bump base64 from 0.21.4 to 0.22.0
- build(deps): bump tokio from 1.28.2 to 1.32.0
- fix(deps): downgrade crate versions due to compatibility issues
- version: Release vsock_proxy v1.0.0
- vsock_proxy: Introduce DnsResolutionInfo type
- vsock_proxy: add tests
- vsock_proxy: change function's signature
- clippy/cargo: resolve build errors and warnings
- vsock_proxy: Perform DNS resolution after the expiration of the TTL
- vsock_proxy: Handle allowlisting out of Proxy
- vsock_proxy: rename starter.rs
- vsock_proxy: Refactor DNS-related functionality
- vsock_proxy: refactor
- cargo: Upgrade num-derive to v0.4
- enclave_build: Extract stream output handling
- enclave_build: Refactor docker.rs for consistent Runtime creation
- enclave_build: Extract build_tarball method
- enclave_build: Extract parse_docker_host method
- enclave_build: Extract inspect method
- enclave_build: Add more tests
- fix: Switch to bollard for docker API interaction
- ci: use cargo-about v0.5.0
- ci: disable automatic license file generation
- enclave_build: fix clippy failure
- build(deps): bump inotify from 0.10.0 to 0.10.2
- build(deps): bump dns-lookup from 1.0.8 to 2.0.3
- vsock_proxy: set log level to warn
- github: update the action version
- clippy: eliminate warnings & errors
- rust: msrv version bump
- build(deps): bump mio from 0.8.6 to 0.8.11
- docs: Correct image signing manual

* Wed Jan 31 2024 Costin Lupu <lvpv@amazon.com> - 1.2.3-0
- Dependencies updates: base64 bindgen chrono env_logger flexi_logger futures
  idna inotify libc log nix num-traits openssl page_size rand rustix serde
  serde_json serde_yaml shlex signal-hook tempfile tokio url vmm-sys-util vsock
- Fix clippy errors and warnings after updates
- Added dependabot support
- Improve help text of the memory argument
- Use public containers in tests
- Update and refactor run_tests.sh

* Tue Mar 07 2023 Petre Eftime <epetre@amazon.com> - 1.2.2-0
- update third party crates license file
- update clap
- update bindgen
- update cpufeatures
- update chrono
- update tempfile
- update hyper
- Fix fmt issues
- Fix clippy issues after tokio update.
- build(deps): bump tokio from 1.18.4 to 1.18.5
- ci: reserve 2 cpus, not specific cpus
- ci: mark logs as plaintext
- CI: prevent tests from getting stuck
- CI: use get-login-password instead of get-login
- build(deps): bump tokio from 1.17.0 to 1.18.4
- clippy: fix minor issue
- cli/enclave_proc: handle EINTR for epoll_wait()
- use ubuntu from the public ECR gallery
- Update THIRD_PARTY_LICENSES_RUST_CRATES.html
- nitro-enclaves-allocator: Set local language to English
- do not re-run Actions checks during tests
- add license checks
- add audit step
- ci: add workflows build, clippy and format workflows
- fix clippy::explicit_auto_deref
- fix clippy::partialeq_to_none
- regenerate driver-bindings with Default
- enclave_build: Fix clippy warning (clippy::needless_borrow)
- vsock-proxy: Add "ap-southeast-3" endpoints to config

* Tue Oct 25 2022 Andra Paraschiv <andraprs@amazon.com> - 1.2.1-0
- Fix nitro-cli debug mode, when using attach_console and debug_mode options.
- Refactor Dockerfiles for faster builds and remove duplication.
- Mock input in nitro-cli unit tests to allow running them on systems without
  Nitro Enclaves support or having various CPU configurations.
- Refactor console disconnect timeout feature.
- Fix race condition in nitro-cli on command dispatch.
- Allow NITRO_CLI_INSTALL_DIR to be overriden in nitro-cli-env.sh.
- Use aws-nitro-enclaves-image-format crate.
- Allow NITRO_CLI_INSTALL_DIR be set for path to allocator.yaml.
- Use DOCKER_HOST env variable properly when interacting with the shiplift
  library.
- Update linuxkit blobs to v0.8+.
- Create driver-bindings crate with static bindings for the Nitro Enclaves
  kernel driver.
- Remove custom metadata structure restriction for EIF images.
- Add symlinks for the blobs used by the command executer sample.
- Fix clippy warnings.
- Bump Rust version to 1.58.1.
- Bump socket2 from 0.3.11 to 0.3.19 in vsock_proxy.
- Bump smallvec from 0.6.13 to 0.6.14 in vsock_proxy.
- Update clap crate to 3.2.
- Update nitro-cli crates dependencies to the latest version.
- Fix broken nitro-cli enclave proc doctest.
- Fix typos in the nitro-cli documentation.

* Tue Feb 22 2022 Eugene Koira <eugkoira@amazon.com> - 1.2.0-0
- Add support of building EIF with custom name, version and metadata.
- Add support of checking EIF metadata within describe-eif and describe-enclave commands.
- Upgrade EIF to v4 containing metadata section.
- Update enclave image blobs to latest v4.14 kernel version.
- Add option to attach the enclave console immediately after starting the enclave.
- Update dependencies to fix cargo audit warnings.
- Update README to include references to official documentation.
- Update init blob based on the latest codebase version.
- Use latest cargo-about and cargo-audit 
- Update cargo dependencies.
- Fix CI tests for ARM.

* Thu Oct 28 2021 Andra Paraschiv <andraprs@amazon.com> - 1.1.0-0
- Update the enclave image blobs e.g. enclave kernel and NSM driver, to include
  the hwrng functionality from the NSM driver for entropy seeding.
- Exit if the hugepages configuration fails in the nitro-enclaves-allocator
  service.
- Update the enclave boot timeout logic to consider the enclave image size.
- Verify the signing certificate of the enclave image and add explicit error
  handling.
- Add pcr command in the nitro-cli.
- Add support for enclave name in the nitro-cli commands.
- Add describe-eif command in the nitro-cli.
- Set correct group ownership for /dev/nitro_enclaves in the nitro-cli spec.
- Add --disconnect-timeout option to console command.
- Add pylint fixes to the nitro-cli tests.
- Update cargo-about and cargo-audit in the nitro-cli CI.
- Update tar and hyper crates in the nitro-cli.
- Fix remote server's matching against allowlist for vsock proxy.
- Add refs for Nitro CLI install from sources on a set of Linux distros in the
  nitro-cli docs.
- Update references to the AWS Nitro Enclaves COSE crate in the nitro-cli docs.
- Update vsock proxy configuration file location in the vsock proxy README.
- Update command executer sample README to reflect current state.
- Update Nitro CLI README to include information about enclave disk space.

* Thu Jul 15 2021 Alexandru Gheorghe <aggh@amazon.com> - 1.0.12-0
- Fix build-enclave when docker contains ENTRYPOINT command.

* Wed May 19 2021 Alexandru Gheorghe <aggh@amazon.com> - 1.0.11-0
- Updated documentation.
- Updated dependencies to exclude deprecated crates and unused ones.
- Switch vsock proxy to using IMDSv2.
- Minor bug fixes.

* Sat Feb 06 2021 Gabriel Bercaru <bercarug@amazon.com> - 1.0.10-1
- Changed release from 0 to 1

* Tue Feb 02 2021 Gabriel Bercaru <bercarug@amazon.com> - 1.0.10-0
- Removed the %posttrans scriptlet and delegated the task of
  re-performing resources initialization to a trigger script
  which runs only when uninstalling v1.0 or the package (during an update)
* Fri Nov 27 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0.9-0
- Added checks for the pre & post uninstallation hooks to check
  whether an upgrade or an uninstallation is being performed

* Tue Nov 24 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0-8
- Added third_party directory with linuxkit credit
- Improved 'insufficient resources' error messages
- Updated the allocator service
- Enforce an enclave memory lower limit of 4x the size of the EIF file
- Added a check wrt the enclave flags, when issuing a `console` command

* Thu Nov 05 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0-7
- Updated init blob file to reflect recent init code changes

* Wed Nov 04 2020 Gabriel Bercaru <bercarug@amzon.com> - 1.0-6
- Improved the error messages related to file operation failures
- Updated the documentation landing page reported in error logs

* Sun Oct 25 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0-5
- Refactored integration tests main scripts in order to use the allocator service

* Tue Oct 20 2020 Dan Horobeanu <dhr@amazon.com> - 1.0-4
- Removed dependency on `nitro_enclaves.device` for the allocator service
- Removed timeout from the allocator oneshot service

* Mon Oct 19 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0-3
- Updated license string to 'Apache 2.0'

* Sat Oct 17 2020 Dan Horobeanu <dhr@amazon.com> - 1.0-1
- Updated license to Apache-2.0
- General cleanup and resync with `make install` output

* Wed Oct 14 2020 Gabriel Bercaru <bercarug@amazon.com> - 1.0-0
- Include resources reservation service

* Wed Mar 25 2020 Alexandru Gheorghe <aggh@amazon.com> - 0.1-0
- Initial draft
