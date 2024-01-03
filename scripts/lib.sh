#!/bin/bash -x
#
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
TEST_SUITES_FAILED=0
TEST_SUITES_TOTAL=0

SCRIPT_DIR="$(realpath $(dirname ${BASH_SOURCE[0]}))"
export NITRO_CLI_BLOBS="$SCRIPT_DIR/../blobs"
export NITRO_CLI_ARTIFACTS="$SCRIPT_DIR/../build"

ARCH="$(uname -m)"
AWS_ACCOUNT_ID=667861386598

test_start() {
	TEST_SUITES_TOTAL=$(($TEST_SUITES_TOTAL + 1))
}

# Indicate that the test suite has failed
register_test_fail() {
	TEST_SUITES_FAILED=$(($TEST_SUITES_FAILED + 1))
}

# Force the test suite to end in failure
test_failed() {
	register_test_fail
	clean_up_and_exit
}

# Clean up and exit with the current test suite's status
clean_up_and_exit() {
	driver_unload nitro_enclaves || register_test_fail

	make clean

	enclaves_images_clean

	exit $TEST_SUITES_FAILED
}

driver_is_not_loaded() {
	local driver_name="$1"
	[ "$(lsmod | grep -cw $driver_name)" -eq 0 ]
}

driver_unload() {
	local driver_name="$1"
	driver_is_not_loaded $driver_name || rmmod $driver_name
}

ne_driver_is_not_loaded() {
	driver_is_not_loaded nitro_enclaves
}

# Remove the Nitro Enclaves driver
ne_driver_remove() {
	ne_driver_is_not_loaded || rmmod nitro_enclaves
}

# Configure and insert the Nitro Enclaves driver
ne_driver_configure() {
	if ne_driver_is_not_loaded; then
		# Preallocate 2046 Mb, that should be enough for all the tests. We explicitly
		# pick this value to have both 1 GB and 2 MB pages if the system allows it.
		source build/install/etc/profile.d/nitro-cli-env.sh
		./build/install/etc/profile.d/nitro-cli-config -m 2046 -t 2
	fi
}

build_and_install() {
	# First run the instalation test, before we change the environement
	pytest-3 tests/integration/test_installation.py

	# Clean up build artifacts
	make clean

	# Setup the environment with everything needed to run the integration tests
	make command-executer
	make nitro-tests
	make nitro_enclaves
	make nitro-cli
	make vsock-proxy
	make install
}

prepare_env() {
	# Ensure the Nitro Enclaves driver is inserted
	ne_driver_configure

	# Load vsock_loopback module for connection_test test of vsock-proxy
	if driver_is_not_loaded vsock_loopback; then
		modprobe vsock_loopback || echo "Module vsock_loopback not available."
	fi

	# Create directories for enclave process sockets and logs
	mkdir -p /run/nitro_enclaves
	mkdir -p /var/log/nitro_enclaves
}

IMAGES_DIR="test_images"
EXAMPLES_DIR="examples/$ARCH"
HELLO_ENTRYPOINT_DIR="$EXAMPLES_DIR/hello-entrypoint"
HELLO_ENTRYPOINT_URI="hello-entrypoint-usage"

# Build EIFS for testing
enclaves_images_build() {
	mkdir -p "$IMAGES_DIR"

	# (1) Simple EIF
	nitro-cli build-enclave \
		--docker-uri public.ecr.aws/aws-nitro-enclaves/hello:v1 \
		--output-file "$IMAGES_DIR"/hello.eif

	# Generate signing certificate
	openssl ecparam -name secp384r1 -genkey -out "$IMAGES_DIR"/key.pem
	openssl req -new -key "$IMAGES_DIR"/key.pem -sha384 -nodes \
		-subj "/CN=AWS/C=US/ST=WA/L=Seattle/O=Amazon/OU=AWS" -out "$IMAGES_DIR"/csr.pem
	openssl x509 -req -days 20  -in "$IMAGES_DIR"/csr.pem -out "$IMAGES_DIR"/cert.pem \
		-sha384 -signkey "$IMAGES_DIR"/key.pem

	# (2) Signed EIF
	nitro-cli build-enclave \
		--docker-uri public.ecr.aws/aws-nitro-enclaves/hello:v1 \
		--output-file "$IMAGES_DIR"/hello-signed.eif \
		--private-key "$IMAGES_DIR"/key.pem \
		--signing-certificate "$IMAGES_DIR"/cert.pem

	# (3) Build enclave image using Docker ENTRYPOINT instruction
	mkdir -p "$HELLO_ENTRYPOINT_DIR"
	cp -r "$EXAMPLES_DIR"/hello/* "$HELLO_ENTRYPOINT_DIR"

	sed -i 's/CMD/ENTRYPOINT/g' "$HELLO_ENTRYPOINT_DIR/Dockerfile"

	nitro-cli build-enclave \
		--docker-dir "$HELLO_ENTRYPOINT_DIR" \
		--docker-uri $HELLO_ENTRYPOINT_URI \
		--output-file "$IMAGES_DIR"/$HELLO_ENTRYPOINT_URI.eif
}

enclaves_images_clean() {
	rm -rf "$IMAGES_DIR"

	# Cleanup pulled images during testing
	docker rmi public.ecr.aws/aws-nitro-enclaves/hello:v1 2> /dev/null || true
	docker rmi hello-world:latest 2> /dev/null || true

	rm -rf "$HELLO_ENTRYPOINT_DIR"
	docker rmi $HELLO_ENTRYPOINT_URI:latest 2> /dev/null || true
}

run_integration_tests() {
	# Ensure the Nitro Enclaves driver is inserted for the remaining integration tests.
	ne_driver_configure

	# Run integration tests except the installation test
	pytest-3 tests/integration/ --ignore tests/integration/test_installation.py
}

