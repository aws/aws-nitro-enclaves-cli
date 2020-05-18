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

function test_failed() {
	TEST_SUITES_FAILED=$((TEST_SUITES_FAILED + 1))
}

# First run the instalation test, before we change the environement
pytest-3 tests/integration/test_installation.py \
	|| test_failed

# Setup the environement with everything needed to run the integration tests
make nitro-tests || test_failed
make nitro_enclaves || test_failed
make nitro-cli || test_failed
make vsock-proxy || test_failed
make install || test_failed
# Preallocate 2048Gb, that should be enough for all the tests
echo 1024 > /proc/sys/vm/nr_hugepages
source build/install/etc/profile.d//nitro-cli-env.sh

# Build EIFS for testing
nitro-cli build-enclave --docker-uri 667861386598.dkr.ecr.us-east-1.amazonaws.com/enclaves-samples:vsock-sample --output-file test_images/vsock-sample.eif


# Run all unittests
while IFS= read -r test_exec_path
do
	TEST_SUITES_TOTAL=$((TEST_SUITES_TOTAL + 1))
	test_exec_name=$(basename "${test_exec_path}")
	./build/nitro_cli/x86_64-unknown-linux-musl/release/"${test_exec_name}" \
		--test-threads=1 --nocapture \
		|| test_failed

done < <(grep -v '^ *#' < build/test_executables.txt)

# Run integration tests except the instalation test
pytest-3 tests/integration/ --ignore tests/integration/test_installation.py \
	|| test_failed

# Run rust-fmt
echo "=================== cargo fmt check ========================="
docker run -v "$(readlink -f .)":/nitro_src \
	   -v "$(readlink -f ./build)":/nitro_build \
		"nitro_cli:1.0" \
		bin/bash -c 'source /root/.cargo/env && \
		cargo fmt --manifest-path=/nitro_src/Cargo.toml -q --  --check' \
		|| test_failed

# Run cargo clippy
echo "=================== cargo clippy ==========================="
docker run -v "$(readlink -f .)":/nitro_src \
	   -v "$(readlink -f ./build)":/nitro_build \
		"nitro_cli:1.0" \
		bin/bash -c 'source /root/.cargo/env && \
		cargo clippy --manifest-path=/nitro_src/Cargo.toml' \
		|| test_failed
# Run cargo audit
echo "=================== cargo audit ==========================="
docker run -v "$(readlink -f .)":/nitro_src \
	   -v "$(readlink -f./build)":/nitro_build \
		"nitro_cli:1.0" \
		bin/bash -c 'source /root/.cargo/env && \
		cargo audit -f /nitro_src/Cargo.lock' \
		|| test_failed

rmmod nitro_enclaves
make clean
rm -rf test_images

exit $TEST_SUITES_FAILED
