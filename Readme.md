Nitro-cli

It contains a collection of tools and commands used for managing the lifecycle
of Nitro Enclaves.

Prerequisites:
  1. A working docker setup, follow https://docs.docker.com/install/overview/
     for details of how to install docker on your host.
  2. Install gcc, make, git.

Driver information:
  The Nitro Enclaves device driver is currently at version 0.2. It is based on the
  kernel tree head commit b335e6094dff (tag: v0.2, origin/ne-driver-mainline-kernel,
  "nitro_enclaves: Add hrtimer support for polling") and supports out-of-tree driver builds.

How to install:
  1. Clone the repository.
  2. Set NITRO_CLI_INSTALL_DIR to the desired location, by default everything will be
     installed in build/install
  3. Run 'make nitro-cli && make vsock-proxy && make install'.
  4. Source the script ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.sh.
  5. [Optional] You could add ${NITRO_CLI_INSTALL_DIR}/etc/profile.d/nitro-cli-env.shenv.sh in you local shell configuration.
  6. You are now ready to go.

How to use nitro-cli:
 TODO: link to official AWS documentation
