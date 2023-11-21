#!/bin/bash -xe

SCRIPT_DIR="$(realpath $(dirname $0))"

bash -x "$SCRIPT_DIR/ci_entrypoint.sh" 2>&1 | tee "$SCRIPT_DIR/myoutput"

