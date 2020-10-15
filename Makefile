# Copyright 2019-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.

##############################
#                            #
#    Variables for build     #
#                            #
##############################

.DEFAULT_GOAL := nitro-cli

CARGO   = cargo
CC      = gcc
INSTALL = install
MKDIR   = mkdir
RM      = rm
DOCKER  = docker
GIT     = git
TAR     = tar
MV      = mv
CP      = cp
AWS     = aws
SHA1    = sha1sum

SRC_PATH              = .
BASE_PATH             ?= $(SRC_PATH)
OBJ_PATH              ?= $(BASE_PATH)/build
NITRO_CLI_TOOLS_DIR   ?= $(BASE_PATH)/tools
NITRO_CLI_INSTALL_DIR ?= $(OBJ_PATH)/install
SBIN_DIR              ?= /usr/sbin/
UNIT_DIR              ?= /usr/lib/systemd/system/
CONF_DIR              ?= /etc
ENV_SETUP_DIR         ?= /etc/profile.d/
OPT_DIR               ?= /opt

CONTAINER_TAG = "nitro_cli:1.0"

# Flags common to C
C_FLAGS := -Wall -Wextra -Werror -O2
##############################
#                            #
#      Makefile rules        #
#                            #
##############################

# Target for generating a tarball with all the dependencies
# needed by the nitro-cli, this is then uploaded to s3, and
# used when building the package for Amazon linux.
# Use account: 283220266793
.PHONY: update-crates-dependencies
update-crates-dependencies:
	$(CARGO) vendor ./crates-dependencies 2>&1 | tee cargo_vendor.log
	$(MV) cargo_vendor.log crates-dependencies/
	$(GIT) log --oneline -n1 > crates-dependencies/git_revision
	$(CP) Cargo.lock crates-dependencies/
	$(TAR) -czf nitro-cli-dependencies.tar.gz crates-dependencies/
	$(SHA1) nitro-cli-dependencies.tar.gz > sources
	TAR_SHA=$$(sha1sum nitro-cli-dependencies.tar.gz | cut -f1 -d' ') && \
		$(AWS) s3 cp nitro-cli-dependencies.tar.gz \
		s3://crates-dependencies/StrongholdCLI/$${TAR_SHA}/nitro-cli-dependencies.tar.gz
	echo "All dependencies have been uploaded to S3, now commit sources file"

.PHONY: crates-dependencies
crates-dependencies:
	ccgit sources --blob_acct=283220266793 --blob_bucket=crates-dependencies

.PHONY: aws-nitro-enclaves-cli.tar.gz
aws-nitro-enclaves-cli.tar.gz:
	$(GIT) archive --format=tar -o SPECS/aws-nitro-enclaves-cli.tar.gz HEAD

.PHONY: sources
sources: aws-nitro-enclaves-cli.tar.gz crates-dependencies

.PHONY: all
all: build-setup init nitro-cli nitro-cli-poweruser vsock-proxy

.PHONY: driver-deps
driver-deps:
	((cat /etc/os-release | grep -qni  "Ubuntu"  \
		&& sudo apt-get install -y linux-headers-$$(uname -r)) || \
	(cat /etc/os-release | grep -qni  "Amazon Linux\|CentOS\|RedHat" \
		&& sudo yum install -y kernel-headers-$$(uname -r) \
		&& sudo yum install -y kernel-devel-$$(uname -r)) || \
	echo "Warning: kernel-header were not installed") \
	&& echo "Successfully installed the nitro_cli_resource_allocator deps"

# In order to avoid executing the same rule everytime,
# the build rules are prefixed by dot and are generating
# a file with the same name via the touch command. This
# change is required in order to capture the timestamp
# of the rule.
.build-container: tools/Dockerfile1804
	docker image build -t $(CONTAINER_TAG) -f tools/Dockerfile1804 tools/
	touch $@

build-container: .build-container

$(OBJ_PATH):
	$(MKDIR) -p $(OBJ_PATH)

# Build the $(OBJ_PATH) directory only if it does not exist.
build-setup: | $(OBJ_PATH);

nitro_cli_resource_allocator: drivers/nitro_cli_resource_allocator/nitro_cli_resource_allocator.c driver-deps
	PREV_DIR=$$PWD && cd drivers/nitro_cli_resource_allocator/ && make && cd $$PREV_DIR

.PHONY: nitro_cli_resource_allocator-clean
nitro_cli_resource_allocator-clean:
	PREV_DIR=$$PWD && cd drivers/nitro_cli_resource_allocator/ && make clean && cd $$PREV_DIR \

nitro_enclaves: drivers/virt/nitro_enclaves/ne_misc_dev.c drivers/virt/nitro_enclaves/ne_pci_dev.c driver-deps
	PREV_DIR=$$PWD && cd drivers/virt/nitro_enclaves/ && make && cd $$PREV_DIR

.PHONY: nitro_enclaves-clean
nitro_enclaves-clean:
	PREV_DIR=$$PWD && cd drivers/virt/nitro_enclaves/ && make clean && cd $$PREV_DIR

.PHONY: driver-clean
driver-clean: nitro_enclaves-clean nitro_cli_resource_allocator-clean

.PHONY: init
init: init.c build-setup
	$(CC) $(C_FLAGS) -o $(OBJ_PATH)/init $< -static -static-libgcc -flto
	strip --strip-all $(OBJ_PATH)/init

# See .build-container rule for explanation.
.build-nitro-cli: $(shell find $(BASE_PATH)/src -name "*.rs")
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
	ln -sf ../x86_64-unknown-linux-musl/release/nitro-cli \
		${OBJ_PATH}/nitro_cli/release/nitro-cli
	touch $@

nitro-cli: build-setup build-container .build-nitro-cli

.PHONY: nitro-cli-native
nitro-cli-native:
	cargo build \
		--release \
		--manifest-path=${BASE_PATH}/Cargo.toml \
		--target-dir=${OBJ_PATH}/nitro_cli

# See .build-container rule for explanation.
.build-command-executer: $(shell find $(BASE_PATH)/samples/command_executer/src -name "*.rs")
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
	ln -sf ../x86_64-unknown-linux-musl/release/command-executer \
		${OBJ_PATH}/command-executer/release/command-executer
	touch $@

.build-command-executer-eif: .build-nitro-cli .build-command-executer \
	$(BASE_PATH)/samples/command_executer/resources/blobs/* \
	$(BASE_PATH)/samples/command_executer/resources/Dockerfile.alpine

	$(MKDIR) -p $(OBJ_PATH)/command-executer/command_executer_docker_dir
	$(CP) \
		$(OBJ_PATH)/command-executer/x86_64-unknown-linux-musl/release/command-executer \
		$(OBJ_PATH)/command-executer/command_executer_docker_dir
	$(CP) \
		$(BASE_PATH)/samples/command_executer/resources/Dockerfile.alpine \
		$(OBJ_PATH)/command-executer/command_executer_docker_dir/Dockerfile
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		-v /var/run/docker.sock:/var/run/docker.sock \
		$(CONTAINER_TAG) bin/bash -c \
			'NITRO_CLI_BLOBS=/nitro_src/samples/command_executer/resources/blobs \
				/nitro_build/nitro_cli/x86_64-unknown-linux-musl/release/nitro-cli \
					build-enclave \
					--docker-uri command_executer:eif \
					--docker-dir /nitro_build/command-executer/command_executer_docker_dir \
					--output-file /nitro_build/command-executer/command_executer.eif'
	touch $@

command-executer: build-setup build-container .build-command-executer-eif

# See .build-container rule for explanation.
.build-nitro-tests: $(BASE_PATH)/tests
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && set -o pipefail && \
			OPENSSL_STATIC=yes OPENSSL_DIR=/musl_openssl/ cargo test \
				--release \
				--no-run \
				--all \
				--manifest-path=/nitro_src/Cargo.toml \
				--target=x86_64-unknown-linux-musl \
				--target-dir=/nitro_build/nitro_cli \
				--message-format json \
				| tee /nitro_build/nitro-tests-build.log | \
				jq -r "select(.profile.test == true) | .filenames[], .package_id" | \
				paste -d " " - - | cut -d " " -f 1,2 \
					> /nitro_build/test_executables.txt && \
			chmod -R 777 nitro_build '
	touch $@

nitro-tests: build-setup build-container .build-nitro-tests

nitro-format: build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			cargo fmt --manifest-path=/nitro_src/Cargo.toml -q --all -- --check'

nitro-clippy: build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			cargo clippy --manifest-path=/nitro_src/Cargo.toml --all'

nitro-audit: build-setup build-container
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			cargo audit -f /nitro_src/Cargo.lock'

# See .build-container rule for explanation.
.build-nitro-cli-poweruser: $(shell find $(BASE_PATH)/cli_poweruser/src -name "*.rs")
	$(DOCKER) run \
		-v "$$(readlink -f ${BASE_PATH})":/nitro_src \
		-v "$$(readlink -f ${OBJ_PATH})":/nitro_build \
		$(CONTAINER_TAG) bin/bash -c \
			'source /root/.cargo/env && \
			OPENSSL_STATIC=yes OPENSSL_DIR=/musl_openssl/ cargo build \
				--release \
				--manifest-path=/nitro_src/cli_poweruser/Cargo.toml \
				--target=x86_64-unknown-linux-musl \
				--target-dir=/nitro_build/cli_poweruser  && \
			chmod -R 777 nitro_build '
	touch $@

nitro-cli-poweruser: build-setup build-container .build-nitro-cli-poweruser

# See .build-container rule for explanation.
.build-vsock-proxy: $(shell find $(BASE_PATH)/vsock_proxy/src -name "*.rs")
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
	ln -sf ../x86_64-unknown-linux-musl/release/vsock-proxy \
		${OBJ_PATH}/vsock_proxy/release/vsock-proxy
	touch $@

vsock-proxy: build-setup build-container .build-vsock-proxy

.PHONY: vsock-proxy-native
vsock-proxy-native:
	cargo build \
		--release \
		--manifest-path=${BASE_PATH}/vsock_proxy/Cargo.toml \
		--target-dir=${OBJ_PATH}/vsock_proxy

.PHONY: install-command-executer
install-command-executer:
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}
	$(INSTALL) -D -m 0755 $(OBJ_PATH)/command-executer/release/command-executer ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}/command-executer

.PHONY: install-nitro-cli-poweruser
install-nitro-cli-poweruser:
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}
	$(INSTALL) -D -m 0755 $(OBJ_PATH)/cli_poweruser/x86_64-unknown-linux-musl/release/nitro-cli-poweruser ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}/nitro-cli-poweruser

# Target for installing only the binaries available to the end-user
.PHONY: install-tools
install-tools:
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/${CONF_DIR}/vsock_proxy
	$(INSTALL) -D -m 0755 $(OBJ_PATH)/nitro_cli/release/nitro-cli ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}/nitro-cli
	$(INSTALL) -D -m 0755 $(OBJ_PATH)/vsock_proxy/release/vsock-proxy ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}/vsock-proxy
	$(INSTALL) -D -m 0644 vsock_proxy/service/vsock-proxy.service ${NITRO_CLI_INSTALL_DIR}/${UNIT_DIR}/vsock-proxy.service
	$(INSTALL) -D -m 0644 vsock_proxy/configs/config.yaml ${NITRO_CLI_INSTALL_DIR}/${CONF_DIR}/vsock_proxy/config.yaml

.PHONY: install
install: install-tools nitro_enclaves
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli
	${MKDIR} -p ${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/
	$(INSTALL) -D -m 0755 blobs/bzImage ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli/bzImage
	$(INSTALL) -D -m 0755 blobs/cmdline ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli/cmdline
	$(INSTALL) -D -m 0755 blobs/init ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli/init
	$(INSTALL) -D -m 0755 blobs/nsm.ko ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli/nsm.ko
	$(INSTALL) -D -m 0755 blobs/linuxkit ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli/linuxkit
	$(MKDIR) -p ${NITRO_CLI_INSTALL_DIR}/lib/modules/$(uname -r)/extra/nitro_enclaves
	$(INSTALL) -D -m 0755 drivers/virt/nitro_enclaves/nitro_enclaves.ko \
               ${NITRO_CLI_INSTALL_DIR}/lib/modules/$(uname -r)/extra/nitro_enclaves/nitro_enclaves.ko
	$(INSTALL) -m 0644 config/env.sh ${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/nitro-cli-env.sh
	$(INSTALL) -m 0755 config/nitro-cli-config ${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/nitro-cli-config
	sed -i "2 a NITRO_CLI_INSTALL_DIR=$$(readlink -f ${NITRO_CLI_INSTALL_DIR})" \
		${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/nitro-cli-env.sh
	echo "Installation finished"
	echo "Please run \"source ${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/nitro-cli-env.sh\" to setup the environment or add it your local shell configuration"

.PHONY: uninstall
uninstall:
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}/nitro-cli
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/${SBIN_DIR}/vsock-proxy
	$(RM) -rf ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/nitro_cli
	$(RM) -rf ${NITRO_CLI_INSTALL_DIR}/${OPT_DIR}/vsock_proxy
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/${UNIT_DIR}/vsock-proxy.service
	$(RM) -rf ${NITRO_CLI_INSTALL_DIR}/lib/modules/$(uname -r)/extra/nitro_enclaves
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/${CONF_DIR}/vsock_proxy/config.yaml
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/nitro-cli-env.sh
	$(RM) -f ${NITRO_CLI_INSTALL_DIR}/${ENV_SETUP_DIR}/nitro-cli-config

.PHONY: clean
clean:
	$(DOCKER) rmi command_executer:eif 2> /dev/null || true
	$(RM) -rf $(OBJ_PATH)
	$(RM) -f .build*
