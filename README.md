## AWS CLI for Nitro Enclaves

This repository contains a collection of tools and commands used for managing
the lifecycle of Nitro Enclaves.

### Prerequisites
  1. A working docker setup, follow https://docs.docker.com/install/overview/
     for details of how to install docker on your host, including how to run it
     as non-root.
  2. Install gcc, make, git.

### Driver information
  The Nitro Enclaves kernel driver is currently at version 0.7. Out-of-tree
  driver build is supported.

### How to install:
  1. Clone the repository.
  2. Set NITRO_CLI_INSTALL_DIR to the desired location, by default everything will be
     installed in build/install
  3. Run 'make nitro-cli && make vsock-proxy && make install'.
  4. Source the script ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.sh.
  5. [Optional] You could add ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.shenv.sh in you local shell configuration.
  6. You are now ready to go.

### How to use nitro-cli
 TODO: link to official AWS documentation

## License
  This library is licensed under the Apache 2.0 License.
