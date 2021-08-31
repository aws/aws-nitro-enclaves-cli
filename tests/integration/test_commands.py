# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/python3
"""
This module tests various enclave commands.
"""

import json
import math
import time
from subprocess import TimeoutExpired
import pytest
from helpers import run_enclave_ok, run_enclave_err, terminate_enclave_ok, connect_console,\
    describe_enclaves_ok, describe_eif_ok, get_cpu_count, SAMPLE_EIF, kill_all_nitro_processes,\
    connect_console_by_name, terminate_enclave_by_name


@pytest.fixture(name="init_resources")
def fixture_init_resources():
    """Returns a TestResources instance and performs cleanup."""
    resources = TestResources()
    print("Initializing test")
    yield resources
    if resources.enclave_id is not None:
        print("Terminating: " + resources.enclave_id)
        terminate_enclave_ok(resources.enclave_id)

    # Make sure there is no running process of nitro-cli
    kill_all_nitro_processes()


class TestResources: # pylint: disable=too-few-public-methods
    """
    Various tests resources that need to be initialized for each test or clean up.
    """
    enclave_id = None


def test_run_enclave(init_resources):
    """Test run_enclave is successful."""
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
    result_json = json.loads(result.stdout.decode('UTF-8'))
    init_resources.enclave_id = result_json["EnclaveID"]


def test_run_with_console(init_resources):
    """
    Test that start the enclave in debug-mode and checks we could
    successfully connect to the console.
    """
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2", ["--debug-mode"])
    result_json = json.loads(result.stdout.decode('UTF-8'))
    init_resources.enclave_id = result_json["EnclaveID"]

    console_proc = connect_console(init_resources.enclave_id)
    try:
        outs, errs = console_proc.communicate(timeout=15)
        # Console should never exit
        assert 0
    except TimeoutExpired:
        console_proc.kill()
        outs, errs = console_proc.communicate()
        out_str = outs.decode('UTF-8')
        err_str = errs.decode('UTF-8')
        print("================= STDOUT =================")
        print(out_str)
        print("================= STDERR =================")
        print(err_str)

        assert out_str.find("Unpacking initramfs") != -1
        assert not err_str


def test_run_with_console_timeout(init_resources):
    """Test run with console timeout."""
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2", ["--debug-mode"])
    result_json = json.loads(result.stdout.decode('UTF-8'))
    init_resources.enclave_id = result_json["EnclaveID"]

    try:
        start = time.time()
        console_proc = connect_console(init_resources.enclave_id, 10)
        console_proc.communicate(timeout=15)
        end = time.time()
    except TimeoutExpired:
        console_proc.kill()
        console_proc.communicate()
        # Console should disconnect before the communicate timeout expires
        assert 0

    assert math.floor(end - start) == 10


def test_run_invalid_cpu_count(init_resources):
    """Test run with invalid number of CPUS."""
    result = run_enclave_err(SAMPLE_EIF, "1028", "0")
    _ = result.stdout.decode('UTF-8')
    error = result.stderr.decode('UTF-8')
    assert error.find("[ E29 ]") != -1

    result = run_enclave_err(SAMPLE_EIF, "1028", "1")
    result = run_enclave_err(SAMPLE_EIF, "1028", "3")
    result = run_enclave_err(SAMPLE_EIF, "1028", "-3")
    result = run_enclave_err(SAMPLE_EIF, "1028", "zzz")
    result = run_enclave_err(SAMPLE_EIF, "1028", str(get_cpu_count()))

    # At the end check we can still launch enclaves.
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
    result_json = json.loads(result.stdout.decode('UTF-8'))
    init_resources.enclave_id = result_json["EnclaveID"]


def test_run_invalid_memory(init_resources):
    """Test run with invalid memory numbers."""
    result = run_enclave_err(SAMPLE_EIF, "-10", "2")
    result = run_enclave_err(SAMPLE_EIF, "0", "2")
    result = run_enclave_err(SAMPLE_EIF, "VVV", "2")

    # At the end check we can still launch enclaves.
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
    result_json = json.loads(result.stdout.decode('UTF-8'))
    init_resources.enclave_id = result_json["EnclaveID"]


def test_describe_enclaves(init_resources): # pylint: disable=unused-argument
    """Test describe enclaves does what we expect it to do."""
    result = describe_enclaves_ok()
    result_json = json.loads(result.stdout.decode('UTF-8'))
    assert not result_json

    result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
    result_json = json.loads(result.stdout.decode('UTF-8'))
    enclave_id = result_json["EnclaveID"]

    result = describe_enclaves_ok()
    result_json = json.loads(result.stdout.decode('UTF-8'))
    assert result_json[0]["EnclaveID"] == enclave_id

    terminate_enclave_ok(enclave_id)

    result = describe_enclaves_ok()
    result_json = json.loads(result.stdout.decode('UTF-8'))
    assert not result_json


def test_describe_eif(init_resources): # pylint: disable=unused-argument
    """Test describe_eif command is successful and returns as expected."""
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
    result_json = json.loads(result.stdout.decode('UTF-8'))
    enclave_id = result_json["EnclaveID"]

    result = describe_enclaves_ok()
    result_json = json.loads(result.stdout.decode('UTF-8'))
    run_measurements = result_json[0]["Measurements"]

    terminate_enclave_ok(enclave_id)

    result = describe_eif_ok(SAMPLE_EIF)
    result_json = json.loads(result.stdout.decode('UTF-8'))
    static_measurements = result_json["Measurements"]

    assert static_measurements["HashAlgorithm"] == run_measurements[
        "HashAlgorithm"]
    assert static_measurements["PCR0"] == run_measurements["PCR0"]
    assert static_measurements["PCR1"] == run_measurements["PCR1"]
    assert static_measurements["PCR2"] == run_measurements["PCR2"]
    assert not result_json["IsSigned"]


def test_enclave_name(init_resources): # pylint: disable=unused-argument
    """Test running an enclave with a given name and applying the other commands on the name"""
    result = run_enclave_ok(SAMPLE_EIF, "1028", "2", ["--enclave-name", "testName", "--debug-mode"])
    result_json = json.loads(result.stdout.decode('UTF-8'))
    enclave_name = result_json["EnclaveName"]

    result = describe_enclaves_ok()
    result_json = json.loads(result.stdout.decode('UTF-8'))
    describe_name = result_json[0]["EnclaveName"]

    console_proc = connect_console_by_name(enclave_name)
    try:
        outs, errs = console_proc.communicate(timeout=15)
        # Console should never exit
        assert 0
    except TimeoutExpired:
        console_proc.kill()
        outs, errs = console_proc.communicate()
        out_str = outs.decode('UTF-8')
        err_str = errs.decode('UTF-8')

        assert out_str.find("Unpacking initramfs") != -1
        assert not err_str

    result = terminate_enclave_by_name(enclave_name)
    result_json = json.loads(result.stdout.decode('UTF-8'))
    terminate_name = result_json["EnclaveName"]

    assert enclave_name == "testName"
    assert describe_name == "testName"
    assert terminate_name == "testName"
