# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from helpers import *
from subprocess import TimeoutExpired
import pytest
import json
import os

@pytest.fixture
def init_resources():
        resources = TestResources()
        print("Initializing test")
        yield resources
        if resources.enclave_id is not None:
                print("Terminating: " + resources.enclave_id)
                terminate_enclave_ok(resources.enclave_id)

        # Make sure there is no running process of nitro-cli
        kill_all_nitro_processes()

# Various tests resources that need to be intialized for each test or
# clean up
class TestResources:
        enclave_id = None

# Test run_enclave is successful.
def test_run_enclave(init_resources):
        result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
        result_json = json.loads(result.stdout.decode('UTF-8'))
        init_resources.enclave_id = result_json["EnclaveID"]

# Test that start the enclave in debug-mode and checks we could sucessfully connect to the console
def test_run_with_console(init_resources):
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

# Test run with invalid number of CPUS
def test_run_invalid_cpu_count(init_resources):
        result = run_enclave_err(SAMPLE_EIF, "1028", "0")
        output = result.stdout.decode('UTF-8')
        error = result.stderr.decode('UTF-8')
        assert error.find("Failed to run enclave") != -1

        result = run_enclave_err(SAMPLE_EIF, "1028", "1")
        result = run_enclave_err(SAMPLE_EIF, "1028", "3")
        result = run_enclave_err(SAMPLE_EIF, "1028", "-3")
        result = run_enclave_err(SAMPLE_EIF, "1028", "zzz")
        result = run_enclave_err(SAMPLE_EIF, "1028", str(get_cpu_count()))

        # At the end check we can still launch enclaves.
        result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
        result_json = json.loads(result.stdout.decode('UTF-8'))
        init_resources.enclave_id = result_json["EnclaveID"]

# Test run with invalid memory numbers
def test_run_invalid_memory(init_resources):
        result = run_enclave_err(SAMPLE_EIF, "-10", "2")
        result = run_enclave_err(SAMPLE_EIF, "0", "2")
        result = run_enclave_err(SAMPLE_EIF, "VVV", "2")

        # At the end check we can still launch enclaves.
        result = run_enclave_ok(SAMPLE_EIF, "1028", "2")
        result_json = json.loads(result.stdout.decode('UTF-8'))
        init_resources.enclave_id = result_json["EnclaveID"]

# Test describe enclaves does what we expect it to do
def test_describe_enclaves(init_resources):
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
