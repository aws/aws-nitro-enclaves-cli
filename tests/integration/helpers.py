# Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/python3
"""
This module provides helpers for managing enclaves testing.
"""

import subprocess
from subprocess import PIPE
from subprocess import check_output
import os
import signal

ROOT_DIR = os.path.dirname(os.path.abspath(__file__)) + "/../../"
TEST_IMAGES = "test_images/"
ARCH =  subprocess.run(["uname", "-m"], stdout=PIPE, stderr=PIPE,
        check=False).stdout.decode('UTF-8').rstrip("\n")
SAMPLE_EIF = "hello.eif"
SIGNED_EIF = "hello-signed.eif"
SIGN_CERT = "cert.pem"


def run_cmd_ok(cmd_string):
    """Runs a system command and checks it returned success"""
    print(cmd_string)
    ret = os.system(cmd_string)
    assert ret == 0


def run_cmd_err(cmd_string):
    """Runs a system command and checks it returned error"""
    print(cmd_string)
    ret = os.system(cmd_string)
    assert ret != 0


def check_no_files(dir_name):
    """Checks dir_name and its children do not include any files"""
    for _root, _dirs, files in os.walk(dir_name):
        print("Expected files to be empty found: ", files)
        assert len(files) == 0


def make_prefix(install_dir, build_dir):
    """Builds the prefix for running a make command"""
    return "make " + "NITRO_CLI_INSTALL_DIR=" + install_dir + \
           " OBJ_PATH=" + build_dir + \
           " -C " + ROOT_DIR + " "


def run_subprocess(args):
    """
    Runs a process and dumps it outputs for debugging purpose
    :return: An instance of a CompletedProcess
    """
    try:
        result = subprocess.run(args, stdout=PIPE, stderr=PIPE, check=False)
    except: # pylint: disable=bare-except
        assert 0
    output = result.stdout.decode('UTF-8')
    error = result.stderr.decode('UTF-8')
    print("Running command: ", args)
    print("================= STDOUT =================")
    print(output)
    print("================= STDERR =================")
    print(error)

    # CLI should not panic in any circumstances
    assert output.lower().find("panic") == -1
    assert error.lower().find("panic") == -1
    return result


def get_pids(name):
    """Find the process ID of a running program"""
    try:
        return check_output(["pidof", name]).decode('UTF-8')
    except: # pylint: disable=bare-except
        return ""


def kill_all_nitro_processes():
    """Kill al nitro-cli processes"""
    pids = get_pids("nitro-cli")
    for pid in pids.split():
        try:
            if pid:
                os.kill(int(pid), signal.SIGTERM)
        except: # pylint: disable=bare-except
            print("Caught exception while killing the process")


def run_subprocess_ok(args):
    """
    Runs a process and checks it returned success
    :return: An instance of a CompletedProcess
    """
    result = run_subprocess(args)
    assert result.returncode == 0
    return result


def run_subprocess_err(args):
    """
    Runs a process and checks it returned error
    :return: An instance of a CompletedProcess
    """
    result = run_subprocess(args)
    assert result.returncode != 0
    return result


def run_enclave_cmd(eif_name, memory, cpu_count, extra_flags=None):
    """Builds an run_enclave command"""
    eif_path = TEST_IMAGES + eif_name
    args = [
        "nitro-cli", "run-enclave", "--eif-path", eif_path, "--memory", memory,
        "--cpu-count", cpu_count
    ]
    if extra_flags is not None:
        args.extend(extra_flags)
    return args


def run_enclave_ok(eif_name, memory, cpu_count, extra_flags=None):
    """
    Runs an enclave and checks it returned success
    :return: An instance of a CompletedProcess
    """
    args = run_enclave_cmd(eif_name, memory, cpu_count, extra_flags)
    return run_subprocess_ok(args)


def run_enclave_err(eif_name, memory, cpu_count, extra_flags=None):
    """
    Runs an enclave and checks it returned error
    :return: An instance of a CompletedProcess
    """
    args = run_enclave_cmd(eif_name, memory, cpu_count, extra_flags)
    return run_subprocess_err(args)


def terminate_enclave_ok(enclave_id):
    """
    Terminates an enclave and checks the command was successful
    :return: An instance of a CompletedProcess
    """
    args = ["nitro-cli", "terminate-enclave", "--enclave-id", enclave_id]

    return run_subprocess_ok(args)


def terminate_enclave_by_name(enclave_name):
    """
    Terminates an enclave with the given name and checks the command was successful
    :return: An instance of a CompletedProcess
    """
    args = [
        "nitro-cli",
        "terminate-enclave",
        "--enclave-name", enclave_name
    ]

    return run_subprocess_ok(args)


def describe_enclaves_ok():
    """
    Runs describe_enclaves command and checks the command was successful
    :return: An instance of a CompletedProcess
    """
    args = ["nitro-cli", "describe-enclaves"]

    return run_subprocess_ok(args)


def describe_eif_ok(eif_name):
    """
    Runs describe_eif command, describing the EIF at the given path
    :return: Checks if command is successful and returns a CompletedProcess
    """
    eif_path = TEST_IMAGES + eif_name
    args = [
        "nitro-cli",
        "describe-eif",
        "--eif-path",
        eif_path,
    ]
    return run_subprocess_ok(args)


def connect_console(enclave_id, timeout=None):
    """
    Connects to the enclave console defined by the enclave id
    :return: The handle to the running process
    """
    args = ["nitro-cli", "console", "--enclave-id", enclave_id]

    if timeout is not None:
        args.extend(["--disconnect-timeout", str(timeout)])

    return subprocess.Popen(args, stdout=PIPE, stderr=PIPE)


def connect_console_by_name(enclave_name):
    """
    Connects to the enclave console defined by the enclave name
    :return: The handle to the running process
    """
    args = ["nitro-cli",
            "console",
            "--enclave-name", enclave_name]

    return subprocess.Popen(args, stdout=PIPE, stderr=PIPE)


def get_cpu_count():
    """Get the number of CPUs in the system, both on-line and off-line"""
    try:
        result = subprocess.run(["lscpu -a -p=cpu"], stdout=PIPE, check=True, shell=True)
    except: # pylint: disable=bare-except
        assert 0
    output = result.stdout.decode('UTF-8').splitlines()
    cpu_ids = [id for id in output if not id.startswith("#")]
    return len(cpu_ids)


def get_pcr(cert_name):
    """
    Runs pcr command, hashing the file at the given path
    :return: PCR value of the input and returns a CompletedProcess
    """
    cert_path = TEST_IMAGES + cert_name
    args = [
        "nitro-cli",
        "pcr",
        "--signing-certificate",
        cert_path,
    ]
    return run_subprocess_ok(args)
