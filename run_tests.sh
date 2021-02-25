#!/bin/bash -x
#
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Script used for running all the tests we have on a EC2 instance that has
# --enclave-options set to true
#
TEST_SUITES_FAILED=0
TEST_SUITES_TOTAL=0

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export NITRO_CLI_BLOBS="${SCRIPTDIR}/blobs"
export NITRO_CLI_ARTIFACTS="${SCRIPTDIR}/build"

$(aws ecr get-login --no-include-email --region us-east-1)

# Indicate that the test suite has failed
function register_test_fail() {
	TEST_SUITES_FAILED=$((TEST_SUITES_FAILED + 1))
}

# Clean up and exit with the current test suite's status
function clean_up_and_exit() {
	[ "$(lsmod | grep -cw nitro_enclaves)" -eq 0 ] || rmmod nitro_enclaves || register_test_fail
	make clean
	rm -rf test_images

	exit $TEST_SUITES_FAILED
}

# Force the test suite to end in failure
function test_failed() {
	register_test_fail
	clean_up_and_exit
}

# Remove the Nitro Enclaves driver
function remove_ne_driver() {
	[ "$(lsmod | grep -cw nitro_enclaves)" -eq 0 ] || rmmod nitro_enclaves || test_failed
}

# Configure and insert the Nitro Enclaves driver
function configure_ne_driver() {
	if [ "$(lsmod | grep -cw nitro_enclaves)" -eq 0 ]
	then
		# Preallocate 2046 Mb, that should be enough for all the tests. We explicitly
		# pick this value to have both 1 GB and 2 MB pages if the system allows it.
		source build/install/etc/profile.d/nitro-cli-env.sh || test_failed
		./build/install/etc/profile.d/nitro-cli-config -m 2046 -p 1,3 || test_failed
	fi
}

# First run the instalation test, before we change the environement
pytest-3 tests/integration/test_installation.py || test_failed

# Clean up build artefacts
make clean

# Run cargo fmt
echo "=================== cargo fmt ========================="
make nitro-format || test_failed

# Run cargo clippy
echo "=================== cargo clippy ==========================="
make nitro-clippy || test_failed

# Run cargo audit
echo "=================== cargo audit ==========================="
make nitro-audit || test_failed

# Check Rust licenses
echo "=================== cargo about ==========================="
make nitro-about || test_failed

# Setup the environement with everything needed to run the integration tests
make command-executer || test_failed
make nitro-tests || test_failed
make nitro_enclaves || test_failed
make nitro-cli || test_failed
make vsock-proxy || test_failed
make install || test_failed

# Ensure the Nitro Enclaves driver is inserted at the beginning.
configure_ne_driver

# Create directories for enclave process sockets and logs
mkdir -p /run/nitro_enclaves || test_failed
mkdir -p /var/log/nitro_enclaves || test_failed

# Build EIFS for testing
mkdir -p test_images
export HOME="/root"
nitro-cli build-enclave --docker-uri 667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample \
	--output-file test_images/vsock-sample.eif || test_failed

# Run all unit tests
while IFS= read -r test_line
do
	TEST_SUITES_TOTAL=$((TEST_SUITES_TOTAL + 1))
	test_module="$(echo ${test_line} | cut -d' ' -f2)"
	test_exec_name="$(basename $(echo ${test_line} | cut -d' ' -f1))"

	configure_ne_driver

	./build/nitro_cli/x86_64-unknown-linux-musl/release/deps/"${test_exec_name}" \
		--test-threads=1 --nocapture || test_failed
done < <(grep -v '^ *#' < build/test_executables.txt)

# Ensure the Nitro Enclaves driver is inserted for the remaining integration tests.
configure_ne_driver

# Run integration tests except the instalation test
pytest-3 tests/integration/ --ignore tests/integration/test_installation.py || test_failed

clean_up_and_exit
