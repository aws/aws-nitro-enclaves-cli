![msrv]

[msrv]: https://img.shields.io/badge/MSRV-1.68.2-blue

## Nitro Enclaves Command Line Interface (Nitro CLI)

This repository contains a collection of tools and commands used for managing the lifecycle of enclaves. The Nitro CLI needs to be installed on the parent instance, and it can be used to start, manage, and terminate enclaves.  

### Prerequisites
  1. A working docker setup, follow https://docs.docker.com/install/overview/ for details of how to install docker on your host, including how to run it as non-root.
  2. Install gcc, make, git, llvm-dev, libclang-dev, clang.

### Driver information
  The Nitro Enclaves kernel driver is available in the upstream Linux kernel starting with the v5.10 kernel for x86_64 and starting with the v5.16 kernel for arm64. The codebase from the 'drivers/virt/nitro_enclaves' directory in this GitHub repository is similar to the one merged into the upstream Linux kernel.

  The Nitro Enclaves kernel driver is currently available in the following distro kernels:

  - x86_64
      - Amazon Linux 2 v4.14 kernel starting with kernel-4.14.198-152.320.amzn2.x86_64
      - Amazon Linux 2 v5.4 kernel starting with kernel-5.4.68-34.125.amzn2.x86_64
      - Amazon Linux 2 v5.10+ kernels (e.g. kernel-5.10.29-27.128.amzn2.x86_64)
      - Amazon Linux 2022 v5.10+ kernels (e.g. kernel-5.10.75-82.359.amzn2022.x86_64)
      - CentOS Stream v4.18+ kernels starting with kernel-4.18.0-257.el8.x86_64
      - Fedora v5.10+ kernels (e.g. kernel-5.10.12-200.fc33.x86_64)
      - openSUSE Tumbleweed v5.10+ kernels (e.g. kernel-default-5.10.1-1.1.x86_64)
      - Red Hat Enterprise Linux v4.18+ kernels starting with kernel-4.18.0-305.el8.x86_64
      - SUSE Linux Enterprise Server v5.14+ kernels starting with kernel-default-5.14.21-150400.22.1.x86_64
      - Ubuntu v5.4 kernel starting with linux-aws 5.4.0-1030-aws x86_64
      - Ubuntu v5.8 kernel starting with linux-aws 5.8.0-1017-aws x86_64
      - Ubuntu v5.11+ kernels (e.g. linux-aws 5.11.0-1006-aws x86_64)

  - aarch64
      - Amazon Linux 2 v4.14 kernel starting with kernel-4.14.252-195.483.amzn2.aarch64
      - Amazon Linux 2 v5.4 kernel starting with kernel-5.4.156-83.273.amzn2.aarch64
      - Amazon Linux 2 v5.10+ kernels starting with kernel-5.10.75-79.358.amzn2.aarch64
      - Amazon Linux 2022 v5.10+ kernels starting with kernel-5.10.75-82.359.amzn2022.aarch64
      - CentOS Stream v4.18 kernel starting with kernel-4.18.0-358.el8.aarch64
      - CentOS Stream v5.14+ kernels starting with kernel-5.14.0-24.el9.aarch64
      - Fedora v5.16+ kernels (e.g. kernel-5.16.5-200.fc35.aarch64)
      - Red Hat Enterprise Linux v4.18+ kernels starting with kernel-4.18.0-372.9.1.el8.aarch64
      - Ubuntu v5.4 kernel starting with linux-aws 5.4.0-1064-aws aarch64
      - Ubuntu v5.13+ kernels starting with linux-aws 5.13.0-1012-aws aarch64

  The following packages need to be installed or updated to have the Nitro Enclaves kernel driver available in the mentioned distros:

  - Amazon Linux 2 - "kernel" (amzn2-core) for the v4.14 kernel, "kernel" (amzn2extra-kernel-5.4) for the v5.4 kernel, "kernel" (amzn2extra-kernel-5.10) for the v5.10 kernel
  - Amazon Linux 2022 - "kernel" for the v5.10+ kernels
  - CentOS Stream - "kernel" for the v4.18+ kernels
  - Fedora - "kernel" for the v5.10+ kernels
  - openSUSE Tumbleweed - "kernel-default" for the v5.10+ kernels
  - Red Hat Enterprise Linux - "kernel" for the v4.18+ kernels
  - SUSE Linux Enterprise Server - "kernel-default" for the v5.14+ kernels
  - Ubuntu - "linux-aws" and "linux-modules-extra-aws" for the v5.4, v5.8 and v5.11+ kernels

  Out-of-tree driver build can be done using the Makefile in the 'drivers/virt/nitro_enclaves' directory.

### How to install (GitHub sources):
  1. Clone the repository.
  2. Set NITRO_CLI_INSTALL_DIR to the desired location, by default everything will be installed in build/install
  3. Run 'make nitro-cli && make vsock-proxy && make install'.
  4. [Rerun after reboot] Source the script ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.sh.
  5. [Rerun after reboot] Preallocate resources for the enclaves(s). 
     For example, to configure 2 vCPUs and 256 Mib for enclave use:
     `nitro-cli-config -i -m 256 -t 2`
  6. [Optional] You could add ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.sh in your local shell configuration.
  7. You are now ready to go.

  A set of steps options to install on distros the Nitro CLI from GitHub sources can be found in the [docs](docs) directory:
  - [CentOS Stream 8](docs/centos_stream_8_how_to_install_nitro_cli_from_github_sources.md)
  - [Fedora 34](docs/fedora_34_how_to_install_nitro_cli_from_github_sources.md)
  - [RHEL 8.4](docs/rhel_8.4_how_to_install_nitro_cli_from_github_sources.md)
  - [Ubuntu 20.04](docs/ubuntu_20.04_how_to_install_nitro_cli_from_github_sources.md)

### How to use Nitro Enclaves CLI
  The user guide for the Nitro Enclaves CLI can be found at https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli.html.

  Ensure that your EC2 instance was created with enclave support enabled and that your system (*and container if applicable*) has read/write access to `/dev/nitro_enclaves`.

  Ensure that your Linux system (*and container if applicable*) has Linux hugepages available.

  The AWS Nitro Enclaves CLI package is currently available for:
  - Amazon Linux 2 - https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html
  - openSUSE and SUSE Linux Enterprise Server - https://build.opensuse.org/package/show/Cloud:Tools/aws-nitro-enclaves-cli
  - Windows - https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install-win.html

#### Enclave disk size
  The enclaves do not have access to a physical disk, just a RAM filesystem.
  One can configure the disk space by changing memory size or by using kernel command line arguments.

  The [`init.c`](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/tree/main/init/init.c) file keeps the default configuration for each volume. The below example shows
  the default options for `/tmp`.
  ```
  { OpMount, .mount = { "tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC } },
  ```
  To modify the memory allocated to this volume, another parameter is needed
  ```
  { OpMount, .mount = { "tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "size=100%" } },
  ```
  Note that the parameter `size` specifies only the maximum allocated size.
  After modifying the configuration, the file needs to be recompiled using `make init` and moved to
  `/usr/share/nitro_enclaves/blobs/init`.

## License
  This library is licensed under the Apache 2.0 License.

## Source-code components
  The components of the Nitro Enclaves CLI are organized as follows (all paths are relative to the Nitro Enclaves CLI's root directory):

  - 'blobs': Binary blobs providing pre-compiled components needed for the building of enclave images:
      - 'blobs/aarch64/Image': Kernel image
      - 'blobs/aarch64/Image.config': Kernel config
      - 'blobs/aarch64/cmdline': Kernel boot command line
      - 'blobs/aarch64/init': Init process executable
      - 'blobs/aarch64/linuxkit': LinuxKit-based user-space environment
      - 'blobs/aarch64/nsm.ko': The driver which enables the Nitro Secure Module (NSM) component inside the enclave
      - 'blobs/x86_64/bzImage': Kernel image
      - 'blobs/x86_64/bzImage.config': Kernel config
      - 'blobs/x86_64/cmdline': Kernel boot command line
      - 'blobs/x86_64/init': Init process executable
      - 'blobs/x86_64/linuxkit': LinuxKit-based user-space environment
      - 'blobs/x86_64/nsm.ko': The driver which enables the Nitro Secure Module (NSM) component inside the enclave
      - The enclave kernel is based on the v4.14 Amazon Linux kernel - https://github.com/amazonlinux/linux/tree/amazon-4.14.y/master
      - The source code for the init process and the NSM kernel driver can be found in the following GitHub repository - https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap

  - 'build': An automatically-generated directory which stores the build output for various components (the CLI, the command executer etc.)

  - 'bootstrap': Various useful scripts for CLI environment configuration, namely:
      - 'allocator.yaml': Configuration file for enclave memory and CPUs reservation
      - 'env.sh': A script which inserts the pre-built Nitro Enclaves kernel module, adds the CLI binary directory to $PATH and sets the blobs directory
      - 'nitro-cli-config': A script which can build, configure and install the Nitro Enclaves kernel module, as well as configure the memory and CPUs available for enclave launches (depending on the operation, root privileges may be required)
      - 'nitro-enclaves-allocator': Configuration script for enclave memory and CPUs reservation
      - 'nitro-enclaves-allocator.service': Configuration service for enclave memory and CPUs reservation

  - 'docs': Useful documentation

  - 'drivers': The source code of the kernel modules used by the CLI in order to control enclave behavior, containing:
      - 'drivers/virt/nitro_enclaves': The Nitro Enclaves driver used by the Nitro CLI

  - 'eif_loader': The source code for the EIF loader, a module which ensures that an enclave has booted successfully

  - 'enclave_build': A tool which builds EIF files starting from a Docker image and pre-existing binary blobs (such as those from 'blobs')

  - 'examples': Basic examples of enclaves. One example is the hello world enclave.

  - 'include': The header files exposed by the Nitro Enclaves kernel module used by the Nitro CLI

  - 'samples': A collection of CLI-related sample applications. One sample is the command executer - an application that enables a parent instance to issue commands to an enclave (such as transferring a file, executing an application on the enclave etc.)

  - 'src': The Nitro CLI implementation, divided into 3 components:
      - The implementation of the background enclave process: 'src/enclave_proc'
      - The implementation of the CLI, which takes user commands and communicates with enclave processes: 'src/*.rs'
      - A common module used by both the CLI and the enclave process: 'src/common'

  - 'tests': Various unit and integration tests for the CLI

  - 'tools': Various useful configuration files used for CLI and EIF builds

  - 'vsock_proxy': The implementation of the Vsock - TCP proxy application, which is used to allow an enclave to communicate with an external service through the parent instance

  - 'ci_entrypoint.sh': The script which launches the CLI continuous integration tests

  - 'scripts/run_tests.sh': The continuous integration test suite for the CLI across all supported platforms

## Security issue notifications

If you discover a potential security issue in nitro-cli, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.
