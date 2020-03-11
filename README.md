Nitro-cli

It contains a collection of tools and commands used for managing the lifecycle
of Nitro Enclaves.

Prerequisites:
  1. A working docker setup, follow https://docs.docker.com/install/overview/
     for details of how to install docker on your host.
  2. Install gcc, make, git.

How to install:
  1. Clone the repository.
  2. Set NITRO_CLI_INSTALL_DIR to the desired location, by default everything will be
     installed in build/install
  3. Run 'make install'.
  4. Source the script ${NITRO_CLI_INSTALL_DIR}/env.sh.
  5. [Optional] You could add ${NITRO_CLI_INSTALL_DIR}/env.sh in you local shell configuration.
  6. You are now ready to go.

How to use nitro-cli:
 TODO: link to official AWS documentation
