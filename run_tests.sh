#!/bin/bash -x

TEST_SUITES_FAILED=0
TEST_SUITES_TOTAL=0

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${SCRIPTDIR}"

export NITRO_CLI_BLOBS="${SCRIPTDIR}/blobs"
export NITRO_CLI_ARTIFACTS="${SCRIPTDIR}/build"
$(aws ecr get-login --no-include-email --region us-east-1)
source build_env.txt

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

ACCESS_TOKEN=$(aws ssm get-parameter --name GITHUB_TOKEN --region us-east-1 | \
		grep Value | cut -d':' -f2  | cut -d' ' -f2 | cut -d',' -f1 | cut -d'"' -f2)
if [[ $ACCESS_TOKEN == "" ]];
then
	echo "Invalid ACCESS_TOKEN"
	exit 1
fi

PR_NUMBER=$(echo "$CODEBUILD_SOURCE_VERSION" | cut -d"/" -f2)
curl -H "Authorization: token ${ACCESS_TOKEN}" \
 -X POST -d '{"body":"Commit: '"${CODEBUILD_RESOLVED_SOURCE_VERSION}"' ran test suites total: '${TEST_SUITES_TOTAL}', suites failed: '${TEST_SUITES_FAILED}'"}' \
  https://api.github.com/repos/aws/aws-nitro-enclaves-cli/issues/"${PR_NUMBER}"/comments

exit $TEST_SUITES_FAILED
