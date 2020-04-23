#!/bin/bash -xe

TEST_SUITES_FAILED=0
TEST_SUITES_TOTAL=0

export NITRO_CLI_BLOBS="${SCRIPTDIR}/blobs"
export NITRO_CLI_ARTIFACTS="${SCRIPTDIR}/build"
$(aws ecr get-login --no-include-email --region us-east-1)

make nitro-tests
make nitro_cli_resource_allocator
insmod drivers/nitro_cli_resource_allocator/nitro_cli_resource_allocator.ko

while IFS= read -r test_exec_path
do
	TEST_SUITES_TOTAL=$((TEST_SUITES_TOTAL + 1))
	test_exec_name=$(basename "${test_exec_path}")
	set +e
	./build/nitro_cli/x86_64-unknown-linux-musl/release/"${test_exec_name}" \
		--test-threads=1 --nocapture \
		|| TEST_SUITES_FAILED=$((TEST_SUITES_FAILED + 1))
	set -e

done < <(grep -v '^ *#' < build/test_executables.txt)

rmmod nitro_cli_resource_allocator
make clean

exit $TEST_SUITES_FAILED
