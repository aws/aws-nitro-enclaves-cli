#!/bin/bash -x
#
# Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
ARCH="$(uname -m)"

AWS_ACCOUNT_ID=667861386598

# Indicate that the test suite has failed
function register_test_fail() {
	TEST_SUITES_FAILED=$((TEST_SUITES_FAILED + 1))
}

# Clean up and exit with the current test suite's status
function clean_up_and_exit() {
	[ "$(lsmod | grep -cw nitro_enclaves)" -eq 0 ] || rmmod nitro_enclaves || register_test_fail
	make clean
	rm -rf test_images

	# Cleanup pulled images during testing
	docker rmi public.ecr.aws/aws-nitro-enclaves/hello:v1 2> /dev/null || true
	docker rmi hello-world:latest 2> /dev/null || true

	rm -rf examples/"${ARCH}"/hello-entrypoint
	docker rmi hello-entrypoint-usage:latest 2> /dev/null || true

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
		./build/install/etc/profile.d/nitro-cli-config -m 2046 -t 2 || test_failed
	fi
}

# First run the instalation test, before we change the environement
pytest-3 tests/integration/test_installation.py || test_failed

# Clean up build artefacts
make clean

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
mkdir -p test_images || test_failed
export HOME="/root"

# Simple EIF
nitro-cli build-enclave --docker-uri public.ecr.aws/aws-nitro-enclaves/hello:v1 \
	--output-file test_images/hello.eif || test_failed

# Generate signing certificate
openssl ecparam -name secp384r1 -genkey -out test_images/key.pem || test_failed
openssl req -new -key test_images/key.pem -sha384 -nodes \
	-subj "/CN=AWS/C=US/ST=WA/L=Seattle/O=Amazon/OU=AWS" -out test_images/csr.pem || test_failed
openssl x509 -req -days 20  -in test_images/csr.pem -out test_images/cert.pem \
	-sha384 -signkey test_images/key.pem || test_failed
# Signed EIF
nitro-cli build-enclave --docker-uri public.ecr.aws/aws-nitro-enclaves/hello:v1 \
	--output-file test_images/hello-signed.eif \
	--private-key test_images/key.pem --signing-certificate test_images/cert.pem || test_failed


# Build enclave image using Docker ENTRYPOINT instruction
mkdir -p examples/"${ARCH}"/hello-entrypoint || test_failed
cp -r examples/"${ARCH}"/hello/* examples/"${ARCH}"/hello-entrypoint || test_failed

sed -i 's/CMD/ENTRYPOINT/g' examples/"${ARCH}"/hello-entrypoint/Dockerfile || test_failed

nitro-cli build-enclave --docker-dir examples/"${ARCH}"/hello-entrypoint --docker-uri hello-entrypoint-usage \
	--output-file test_images/hello-entrypoint-usage.eif || test_failed

# Run all unit tests
while IFS= read -r test_line
do
	TEST_SUITES_TOTAL=$((TEST_SUITES_TOTAL + 1))
	test_module="$(echo ${test_line} | cut -d' ' -f2)"
	test_exec_name="$(basename $(echo ${test_line} | cut -d' ' -f1))"

	configure_ne_driver

	timeout 5m \
	./build/nitro_cli/"${ARCH}"-unknown-linux-musl/release/deps/"${test_exec_name}" \
		--test-threads=1 --nocapture || test_failed
done < <(grep -v '^ *#' < build/test_executables.txt)

# Ensure the Nitro Enclaves driver is inserted for the remaining integration tests.
configure_ne_driver

# Run integration tests except the instalation test
pytest-3 tests/integration/ --ignore tests/integration/test_installation.py || test_failed

clean_up_and_exit
