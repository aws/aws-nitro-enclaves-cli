# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from helpers import *

from collections import defaultdict
import json
import os
import pytest
import re
import subprocess

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

class TestResources:
    """
    Various tests resources that need to be initialized for each test
    or clean up
    """
    enclave_id = None

def validate_info(string, pattern):
    """
    Checks that the given `string` contains at least
    one occurrence of the given `pattern`
    """
    p = re.compile(pattern)
    
    occurrence = p.search(string)

    print("Found occurrence {}".format(occurrence))

    assert occurrence is not None, 'Failed to find a match of {}'.format(pattern)

def get_dirs_by_regex(base_path, pattern):
    """
    Retrieves a list of directories found under `base_path`, whose
    names match the given `pattern`
    """
    matching_dirs = []

    p = re.compile(pattern)
    for _, dirs, _ in os.walk(base_path):
        for dir_ in dirs:
            if p.match(dir_):
                matching_dirs.append(dir_)

    return matching_dirs

def test_vsock_proxy_is_running():
    """
    Check that the vsock-proxy service is running as soon as
    the package is installed
    """

    info = 'Main PID: [0-9]+'

    status = os.system('systemctl status vsock-proxy.service > /dev/null 2>&1')
    try:
        result = subprocess.run(['systemctl', 'status', 'vsock-proxy.service'], stdout=PIPE, stderr=PIPE)
    except:
        assert False, 'Failed to check vsock-proxy status'

    out = result.stdout.decode('UTF-8')

    validate_info(out, info)

    assert status == 0, 'vsock-proxy service is not running'

def test_hugetlbfs_isset():
    """
    Tests that after the oneshot configuration service has been triggered
    (at least once, after the package installation), at least one NUMA
    node has some hugepages (any size) allocated

    Sample path which is to be checed:
    /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
    """

    available_hugepages = defaultdict(int)
    base_path = '/sys/devices/system/node/'
    numa_nodes = get_dirs_by_regex(base_path, 'node[0-9]+')

    # Walk all numa nodes
    for numa_node in numa_nodes:
        crt_numa_node = base_path + numa_node + '/hugepages'
        # Walk all hugepage sizes
        for _, dirs, _ in os.walk(crt_numa_node):
            for dir_ in dirs:
                # Add number of allocated hugepages to running total
                with open(crt_numa_node + '/' + dir_ + '/nr_hugepages') as f:
                    available_hugepages[int(dir_.split('-')[1][:-2])] += int(f.read().strip())

    assert any(list(available_hugepages.values())), 'No hugepages have been set'

def test_cpu_pool_isset():
    """
    Tests that after the oneshot configuration service has been triggered
    (at least once, after the package installation), there are some
    offlined CPUs
    """

    info = r'Off-line CPU\(s\) list: [0-9]+[,[0-9]+]*'
    try:
        result = subprocess.run(['lscpu'], stdout=PIPE, stderr=PIPE)
    except:
        assert False, 'Failed to get CPUs information'

    out = result.stdout.decode('UTF-8')

    validate_info(out, info)

def test_run_enclave_ok(init_resources):
    """
    Tests that it is possible to launch one enclave, after package installation
    """
    result = run_enclave_ok(SAMPLE_EIF, '256', '2')
    result_json = json.loads(result.stdout.decode('UTF-8'))
    init_resources.enclave_id = result_json['EnclaveID']

def test_run_enclave_err():
    """
    Tests that running an enclave with more memory than available is not possible
    """
    _ = run_enclave_err(SAMPLE_EIF, str(1 << 50), '2')
