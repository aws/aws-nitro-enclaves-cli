#!/bin/bash

EIF_PATH="https://drive.corp.amazon.com/documents/bercarug@/command_executer.eif"
EIF_NAME="command_executer.eif"

# Setup nightly rust in order to run cargo-fuzz
rustup toolchain install nightly
rustup override set nightly

## Download sample EIF and place it at the specified location
#curl -L -u : --negotiate -o ./${EIF_NAME} ${EIF_PATH}

# Start fuzzer
nohup cargo fuzz run fuzz_target_1 &
