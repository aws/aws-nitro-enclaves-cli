## Nitro Enclaves Command Line Interface (Nitro CLI)

This repository contains a collection of tools and commands used for managing the lifecycle of enclaves. The Nitro CLI needs to be installed on the parent instance, and it can be used to start, manage, and terminate enclaves.  

### Prerequisites
  1. A working docker setup, follow https://docs.docker.com/install/overview/ for details of how to install docker on your host, including how to run it as non-root.
  2. Install gcc, make, git, llvm-dev, libclang-dev, clang.

### Driver information
  The Nitro Enclaves kernel driver is currently at version 0.10. Out-of-tree driver build is supported.

### How to install (Git):
  1. Clone the repository.
  2. Set NITRO_CLI_INSTALL_DIR to the desired location, by default everything will be installed in build/install
  3. Run 'make nitro-cli && make vsock-proxy && make install'.
  4. Source the script ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.sh.
  5. [Optional] You could add ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.shenv.sh in you local shell configuration.
  6. You are now ready to go.

### How to install (Repository):
  1. Install the main Nitro CLI package from the AL2 repository: `sudo yum install -y aws-nitro-enclaves-cli`.
  2. [Optional] In case you want to build EIF images, install additional Nitro Enclaves resources: `sudo yum install -y aws-nitro-enclaves-cli-devel`.
  3. Reserve resources (memory and CPUs) for future enclaves, by editing '/etc/ne_conf' (or use the default configuration - 512MB and 2 CPUs) and then starting the resource reservation service: `sudo systemctl start config-enclave-resources.service`.
  4. [Optional] If you want your resources configuration to persist across reboots, enable the service: `sudo systemctl enable config-enclave-resources.service`.
  5. You are now ready to go.

### How to use nitro-cli
 TODO: link to official AWS documentation

## License
  This library is licensed under the Apache 2.0 License.

## Source-code components
  The components of the CLI are organized as follows (all paths are relative to the CLI's root directory):

  - 'blobs': binary blobs providing pre-compiled components needed for the building of enclave images:
      - a kernel image: 'blobs/bzImage'
      - a kernel boot command line: 'blobs/cmdline'
      - an init process executable: 'blobs/init'
      - a LinuxKit-based user-space environment: 'blobs/linuxkit'
      - the driver which enables the Nitro Secure Module component inside the enclave: 'blobs/nsm.ko'

  - 'build': an automatically-generated directory which stores the build output for various components (the CLI, the command executer etc.)

  - 'cli_poweruser': A power-user version of the CLI, used for direct communication with the enclave-enabling PCI device.

- 'config': Various useful scripts for CLI environment configuration, namely:
      - 'env.sh': A script which inserts the pre-built Nitro Enclaves kernel module, ads the CLI binary directory to $PATH and sets the blobs directory
      - 'nitro-cli-config': A scripts which can build, configure and install the Nitro Enclaves kernel module, as well as configure the memory
          and CPUs available for enclave launches (depending on the operation, root privileges may be required)

  - 'docs': Useful documentation

  - 'drivers': The source code of the kernel modules used by the CLI in order to control enclave behavior, containing:
      - The resource allocator driver used by the power-user CLI for memory and CPU management: 'drivers/nitro_cli_resource_allocator_driver'
      - The Nitro Enclaves driver used by the normal CLI: 'drivers/virt/nitro_enclaves'

  - 'eif_defs': The definition of the enclave image format (EIF) file

  - 'eif_loader': The source code for the EIF loader, a module which ensures that an enclave has booted successfully

  - 'eif_utils': Utilities for the EIF files, focused mostly on building EIFs

  - 'enclave_build': A tool which builds EIF files starting from a Docker image and pre-existing binary blobs (such as those from 'blobs')

  - 'include': The header files exposed by the Nitro Enclaves kernel module used by the normal CLI

  - rust-cose': A Rust-based COSE implementation, needed by the EIF utilities module ('eif_utils')

  - 'samples': A collection of CLI-related sample applications. One sample is the command executer - an application that enables a parent
      instance to issue commands to an enclave (such as transferring a file, executing an application on the enclave etc.)

  - 'src': The Nitro CLI implementation, divided into 3 components:
      - The implementation of the background enclave process: 'src/enclave_proc'
      - The implementation of the CLI, which takes user commands and communicates with enclave processes: 'src/*.rs'
      - A common module used by both the CLI and the enclave process: 'src/common'

  - 'tests': Various unit and integration tests for the CLI, both normal and power-user.

  - 'tools': Various useful configuration files used for CLI and EIF builds.

  - 'vsock_proxy': The implementation of the Vsock - TCP proxy application, which is used to allow an enclave to communicate with an external service
          through the parent instance.

  - 'ci_entrypoint.sh': The script which launches the CLI continuous integration tests

  - 'init.c': The implementation of the default init process used by an enclave's user-space

  - 'run_tests.sh': The continuous integration test suite for the CLI
