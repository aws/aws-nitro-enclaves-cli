#!/bin/bash -x
#
# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Script used for running all the tests we have on a EC2 instance that has
# --enclave-options set to true
#

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source "$SCRIPTDIR/lib_tests.sh"

trap test_failed ERR

check_dependencies

# Build and install NE CLI
build_and_install

# Prepare environment
prepare_env

# Build EIFS for testing
enclaves_images_build

# Run all unit tests
while IFS= read -r test_line; do
	test_start
	test_module="$(echo $test_line | cut -d' ' -f2)"
	test_exec_name="$(basename $(echo $test_line | cut -d' ' -f1))"

	echo "Test module=$test_module executable=$test_exec_name"

	ne_driver_configure

	timeout 7m \
	./build/nitro_cli/$ARCH-unknown-linux-musl/release/deps/$test_exec_name \
		--test-threads=1 --nocapture
done < <(grep -v '^ *#' < build/test_executables.txt)

# Run integration tests
run_integration_tests

# Clean-up
clean_up_and_exit

