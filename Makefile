# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

##############################
#                            #
#    Variables for build     #
#                            #
##############################


CARGO   = cargo
CC      = gcc
INSTALL = install
MKDIR   = mkdir
RM      = rm
DOCKER  = docker

SRC_PATH = .
BASE_PATH ?= $(SRC_PATH)
OBJ_PATH = $(BASE_PATH)/build
NITRO_CLI_INSTALL_DIR ?= $(OBJ_PATH)/install

CONTAINER_TAG="nitro_cli:1.0"

##############################
#                            #
#      Makefile rules        #
#                            #
##############################


.PHONY: all
all: build-setup init nc-vsock nitro-cli nitro-cli-poweruser vsock-proxy


.PHONY: driver-deps
driver-deps:
	((cat /etc/os-release | grep -qni  "Ubuntu"  \
		&& sudo apt-get install linux-headers-$$(uname -r)) || \
	(cat /etc/os-release | grep -qni  "Amazon Linux\|CentOS\|RedHat" \
		&& sudo yum install kernel-headers-$$(uname -r) \
		&& sudo yum install kernel-devel-$$(uname -r)) || \
	echo "Warning: kernel-header were not installed") \
	&& echo "Successfully installed the nitro_cli_resource_allocator deps"

build-container: tools/Dockerfile1804
	docker image build -t $(CONTAINER_TAG) -f tools/Dockerfile1804 $(OBJ_PATH)/ \
		> $(OBJ_PATH)/build_container_output.log

.PHONY: build-setup
build-setup:
	$(MKDIR) -p $(OBJ_PATH)

nitro_cli_resource_allocator: drivers/nitro_cli_resource_allocator/nitro_cli_resource_allocator.c driver-deps
	PREV_DIR=$$PWD && cd drivers/nitro_cli_resource_allocator/ && make && cd $$PREV_DIR

.PHONY: driver-clean
driver-clean:
	PREV_DIR=$$PWD && cd drivers/nitro_cli_resource_allocator/ && make clean && cd $$PREV_DIR

.PHONY: nc-vsock
nc-vsock: nc-vsock.c build-setup
	$(CC) -o $(OBJ_PATH)/nc-vsock nc-vsock.c

.PHONY: init
init: init.c build-setup
	$(CC) -o $(OBJ_PATH)/init $< -static -static-libgcc -flto

.PHONY: nitro-cli
nitro-cli: $(BASE_PATH)/src/main.rs build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			OPENSSL_STATIC=yes OPENSSL_DIR=/musl_openssl/ cargo build \
				--release \
				--manifest-path=/nitro_src/Cargo.toml \
				--target=x86_64-unknown-linux-musl \
				--target-dir=/nitro_build/nitro_cli  && \
			chmod -R 777 nitro_build '

.PHONY: command-executer
command-executer: $(BASE_PATH)/samples/command_executer/src/main.rs build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			OPENSSL_STATIC=yes OPENSSL_DIR=/musl_openssl/ cargo build \
				--release \
				--manifest-path=/nitro_src/samples/command_executer/Cargo.toml \
				--target=x86_64-unknown-linux-musl \
				--target-dir=/nitro_build/command-executer  && \
			chmod -R 777 nitro_build '

.PHONY: nitro-tests
nitro-tests: $(BASE_PATH)/src/main.rs build-setup  build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			OPENSSL_STATIC=yes OPENSSL_DIR=/musl_openssl/ cargo test \
				--release \
				--no-run \
				--all \
				--manifest-path=/nitro_src/Cargo.toml \
				--target=x86_64-unknown-linux-musl \
				--target-dir=/nitro_build/nitro_cli \
				--message-format json | \
				jq -r "select(.profile.test == true) | .filenames[]" \
					 > /nitro_build/test_executables.txt && \
			chmod -R 777 nitro_build '

.PHONY: nitro-cli-poweruser
nitro-cli-poweruser: $(BASE_PATH)/src/main.rs build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			OPENSSL_STATIC=yes OPENSSL_DIR=/musl_openssl/ cargo build \
				--release \
				--manifest-path=/nitro_src/Cargo.toml \
				--target=x86_64-unknown-linux-musl \
				--features=power_user \
				--target-dir=/nitro_build/nitro_cli_poweruser  && \
			chmod -R 777 nitro_build '

.PHONY: vsock-proxy
vsock-proxy: $(BASE_PATH)/vsock_proxy/src/main.rs build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			cargo build \
				--release \
				--target-dir=/nitro_build/vsock_proxy \
				--target=x86_64-unknown-linux-musl \
				--manifest-path=/nitro_src/vsock_proxy/Cargo.toml && \
			chmod -R 777 nitro_build '

.PHONY: install
install: vsock-proxy nitro-cli nitro_cli_resource_allocator
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/usr/sbin
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/var/nitro_cli
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/var/vsock_proxy
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/nitro_cli_resource_allocator
	$(INSTALL) -D -m 0700 $(OBJ_PATH)/nitro_cli/x86_64-unknown-linux-musl/release/nitro-cli ${NITRO_CLI_INSTALL_DIR}/usr/sbin/nitro-cli
	$(INSTALL) -D -m 0700 $(OBJ_PATH)/vsock_proxy/x86_64-unknown-linux-musl/release/vsock-proxy ${NITRO_CLI_INSTALL_DIR}/usr/sbin/vsock-proxy
	$(INSTALL) -D -m 0700 blobs/bzImage ${NITRO_CLI_INSTALL_DIR}/var/nitro_cli/bzImage
	$(INSTALL) -D -m 0700 blobs/cmdline ${NITRO_CLI_INSTALL_DIR}/var/nitro_cli/cmdline
	$(INSTALL) -D -m 0700 blobs/init ${NITRO_CLI_INSTALL_DIR}/var/nitro_cli/init
	$(INSTALL) -D -m 0700 blobs/linuxkit ${NITRO_CLI_INSTALL_DIR}/var/nitro_cli/linuxkit
	if [ -d ${NITRO_CLI_INSTALL_DIR}/lib/systemd/system ] ; then \
		$(INSTALL) -D -m 0644 vsock_proxy/service/vsock-proxy.service ${NITRO_CLI_INSTALL_DIR}/lib/systemd/system/vsock-proxy.service ; \
	else \
		$(INSTALL) -D -m 0755 vsock_proxy/service/vsock-proxy ${NITRO_CLI_INSTALL_DIR}/etc/rc.d/init.d/vsock-proxy ; \
	fi
	$(INSTALL) -D -m 0644 vsock_proxy/service/vsock-proxy.logrotate.conf ${NITRO_CLI_INSTALL_DIR}/etc/logrotate.d/vsock-proxy
	$(INSTALL) -D -m 0644 vsock_proxy/configs/config.yaml ${NITRO_CLI_INSTALL_DIR}/var/vsock_proxy/config.yaml
	$(INSTALL) -D -m 0755 drivers/nitro_cli_resource_allocator/nitro_cli_resource_allocator.ko \
		${NITRO_CLI_INSTALL_DIR}/nitro_cli_resource_allocator/nitro_cli_resource_allocator.ko
	$(INSTALL) -m 0644 tools/env.sh ${NITRO_CLI_INSTALL_DIR}/env.sh
	sed -i "2 a NITRO_CLI_INSTALL_DIR=$$(readlink -f ${NITRO_CLI_INSTALL_DIR})" ${NITRO_CLI_INSTALL_DIR}/env.sh
	echo "Installation finished"
	echo "Please run \"source ${NITRO_CLI_INSTALL_DIR}/env.sh\" to setup the environment or add it your local shell configuration"

.PHONY: uninstall
uninstall:
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/usr/sbin/nitro-cli
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/usr/sbin/vsock-proxy
	$(RM) -rf ${NITRO_CLI_INSTALL_DIR}/var/nitro_cli
	$(RM) -rf ${NITRO_CLI_INSTALL_DIR}/var/vsock_proxy
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/lib/systemd/system/vsock-proxy.service
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/etc/rc.d/init.d/vsock-proxy
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/etc/logrotate.d/vsock-proxy

.PHONY: clean
clean: driver-clean
	$(RM) -rf $(OBJ_PATH)
	$(CARGO) clean
