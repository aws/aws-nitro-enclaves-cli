# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
from subprocess import PIPE
from subprocess import check_output
import os
import signal

ROOT_DIR  = os.path.dirname(os.path.abspath(__file__)) + "/../../"
TEST_IMAGES = "test_images/"
SAMPLE_EIF = "vsock-sample.eif"

# Runs a system command and checks it returned success
def run_cmd_ok(cmd_string):
        print(cmd_string)
        ret = os.system(cmd_string)
        assert ret == 0

# Runs a system command and checks it returned error
def run_cmd_err(cmd_string):
        print(cmd_string)
        ret = os.system(cmd_string)
        assert ret != 0

# Checks dir_name and its children do not include any files
def check_no_files(dir_name):
        for root, dirs, files in os.walk(dir_name):
                print("Expected files to be empty found: ", files)
                assert len(files) == 0

# Builds the prefix for running a make command
def make_prefix(install_dir, build_dir):
        return "make " + "NITRO_CLI_INSTALL_DIR=" + install_dir + \
                        " OBJ_PATH=" + build_dir + \
                        " -C " + ROOT_DIR + " "

# Runs a process and dumps it outputs for debugging purpose
# Returns an instance of a CompletedProcess
def run_subprocess(args):
        try:
                result = subprocess.run(args, stdout=PIPE, stderr=PIPE)
        except:
                assert 0
        output = result.stdout.decode('UTF-8');
        error = result.stderr.decode('UTF-8');
        print("Running command: ", args);
        print("================= STDOUT =================")
        print(output);
        print("================= STDERR =================")
        print(error);

        # CLI should not panic in any circumstances
        assert output.lower().find("panic") == -1
        assert error.lower().find("panic") == -1
        return result

def get_pids(name):
        try:
                return check_output(["pidof",name]).decode('UTF-8')
        except:
                return ""

def kill_all_nitro_processes():
        pids = get_pids("nitro-cli")
        for pid in pids.split():
                try:
                        if pid:
                                os.kill(int(pid), signal.SIGTERM)
                except:
                        print("Caught exception while killing the process");

# Runs a process and checks it returned success
# Returns an instance of a CompletedProcess
def run_subprocess_ok(args):
        result = run_subprocess(args)
        assert result.returncode == 0
        return result

# Runs a process and checks it returned error
# Returns an instance of a CompletedProcess
def run_subprocess_err(args):
        result = run_subprocess(args)
        assert result.returncode != 0
        return result

# Builds an run_enclave command
def run_enclave_cmd(eif_name, memory, cpu_count, extra_flags = None):
        eif_path = TEST_IMAGES + eif_name
        args = [ "nitro-cli",
                 "run-enclave",
                 "--eif-path", eif_path,
                 "--memory", memory,
                 "--cpu-count", cpu_count
                ]
        if extra_flags is not None:
                args.extend(extra_flags)
        return args

# Runs an enclave and checks it returned success
# Returns an instance of a CompletedProcess
def run_enclave_ok(eif_name, memory, cpu_count, extra_flags = None):
        args = run_enclave_cmd(eif_name, memory, cpu_count, extra_flags)
        return run_subprocess_ok(args)

# Runs an enclave and checks it returned error
# Returns an instance of a CompletedProcess
def run_enclave_err(eif_name, memory, cpu_count, extra_flags = None):
        args = run_enclave_cmd(eif_name, memory, cpu_count, extra_flags)
        return run_subprocess_err(args)


# Terminates an enclave and checks the command was successful
# Returns an instance of a CompletedProcess
def terminate_enclave_ok(enclave_id):
        args = [ "nitro-cli",
                 "terminate-enclave",
                 "--enclave-id", enclave_id
        ]

        return run_subprocess_ok(args)

# Runs describe_enclaves command and checks the command was successful
# Returns an instance of a CompletedProcess
def describe_enclaves_ok():
        args = [ "nitro-cli",
                 "describe-enclaves"]

        return run_subprocess_ok(args)

# Connects to the enclave console defined by the enclave id
# Returns the handle to the running process.
def connect_console(enclave_id):
        args = ["nitro-cli",
                "console",
                "--enclave-id", enclave_id]

        return subprocess.Popen(args, stdout = PIPE, stderr = PIPE)

# Get the number of CPUs in the system, both on-line and off-line.
def get_cpu_count():
        run_lscpu = subprocess.Popen(["lscpu -a -p=cpu"], stdout=subprocess.PIPE, shell=True)
        (output, _) = run_lscpu.communicate()
        output = output.decode('UTF-8').splitlines()
        cpu_ids = [id for id in output if not id.startswith("#")]
        return len(cpu_ids)
