#!/bin/bash

IMAGE_ID="ami-02b4d79e47add7637"
INSTANCE_TYPE="c5.2xlarge"
KEY_NAME="stronghold-device-fuzzer"
ENCLAVE_OPTIONS="Enabled=true"
REGION="us-east-1"

FUZZER_CODE_PATH="s3://stronghold-device-fuzzing/stronghold_device_fuzzer.tar.gz"
DEPS_SETUP_PATH="s3://stronghold-device-fuzzing/install_deps.sh"
SAMPLE_EIF_PATH="s3://stronghold-device-fuzzing/command_executer.eif"

SLEEP_INTERVAL=60

function check_keypair {
    if [ ! -f "${KEY_NAME}.pem" ]; then
        echo "Error: ${KEY_NAME}.pem not found in current directory."
        exit -1
    fi
}

function check_envvars {
    if [ -z $AWS_ACCESS_KEY_ID ]; then
        echo "Error: AWS_ACCESS_KEY_ID env var not set."
        exit -2
    fi
    if [ -z $AWS_SECRET_ACCESS_KEY ]; then
        echo "Error: AWS_SECRET_ACCESS_KEY env var not set."
        exit -2
    fi
    if [ -z $AWS_SESSION_TOKEN ]; then
        echo "Error: AWS_SESSION_TOKEN env var not set."
        exit -2
    fi
}

check_keypair
check_envvars

echo "===== Starting Instance ====="

OUT=$(aws ec2 run-instances --image-id ${IMAGE_ID} --instance-type ${INSTANCE_TYPE} --key-name ${KEY_NAME} --enclave-options ${ENCLAVE_OPTIONS} --region ${REGION})
INSTANCE_ID=$(echo "${OUT}" | grep "InstanceId" | cut -d '"' -f4)
INSTANCE_INFO=$(aws ec2 describe-instances --instance-ids ${INSTANCE_ID} --region ${REGION})
PUBLIC_IP=$(echo "${INSTANCE_INFO}" | grep "PublicIpAddress" | cut -d '"' -f4)
echo "Public ip is ${PUBLIC_IP}"

echo "===== Waiting for Instance to Start (${SLEEP_INTERVAL}s) ====="
sleep ${SLEEP_INTERVAL}
echo "===== Done Waiting ===="

# Set required permissions for instance + download code + set rust version
ssh -i "${KEY_NAME}.pem" ubuntu@${PUBLIC_IP} "echo \"export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}\" >> ~/.bash_profile; echo \"export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}\" >> ~/.bash_profile; echo \"export AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}\" >> ~/.bash_profile; source ~/.bash_profile; aws s3 cp ${FUZZER_CODE_PATH} .; aws s3 cp ${DEPS_SETUP_PATH} .; source ~/.cargo/env; cargo install cargo-fuzz; rustup toolchain install nightly; rustup override set nightly; tar -zxvf stronghold_device_fuzzer.tar.gz; cd aws-nitro-enclaves-cli/cli_poweruser; aws s3 cp ${SAMPLE_EIF_PATH} ."

# Start fuzzer and redirect output to aws-nitro-enclaves-cli/cli_poweruser/nohup.out
ssh -i "${KEY_NAME}.pem" ubuntu@${PUBLIC_IP} "cd aws-nitro-enclaves-cli/cli_poweruser && nohup ~/.cargo/bin/cargo fuzz run fuzz_target_1 > nohup.out 2>&1 &"
