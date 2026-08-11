# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/python3
"""
End-to-end tests for the generic Amazon Linux kernel build/boot flow
"""

import json
import re
from subprocess import TimeoutExpired

import pytest

from helpers import run_enclave_ok, terminate_enclave_ok, describe_eif_ok, \
    describe_enclaves_ok, connect_console, kill_all_nitro_processes, TEST_IMAGES
import kernel_helpers as kh


@pytest.fixture(name="init_resources")
def fixture_init_resources():
    """ Returns a TestResources instance and performs cleanup """
    resources = TestResources()
    print("Initializing test")
    yield resources
    if resources.enclave_id is not None:
        print("Terminating: " + resources.enclave_id)
        terminate_enclave_ok(resources.enclave_id)

    # Ensure no running process of nitro-cli
    kill_all_nitro_processes()


class TestResources: # pylint: disable=too-few-public-methods
    """ Test resources that need to be initialized or cleaned up """
    enclave_id = None


def test_legacy_and_kernel_version_conflict(init_resources): # pylint: disable=unused-argument
    """ --legacy-kernel conflicts with --kernel-version """
    kh.build_enclave_err(TEST_IMAGES + "conflict.eif",
                         extra_flags=["--legacy-kernel", "--kernel-version", "6.12"])


def test_legacy_and_rpm_path_conflict(init_resources): # pylint: disable=unused-argument
    """ --legacy-kernel conflicts with --kernel-rpm-path """
    kh.build_enclave_err(TEST_IMAGES + "conflict.eif",
                         extra_flags=["--legacy-kernel", "--kernel-rpm-path", "/tmp/x.rpm"])


def test_kernel_version_and_rpm_path_conflict(init_resources): # pylint: disable=unused-argument
    """ --kernel-version conflicts with --kernel-rpm-path """
    kh.build_enclave_err(TEST_IMAGES + "conflict.eif",
                         extra_flags=["--kernel-version", "6.12",
                                      "--kernel-rpm-path", "/tmp/x.rpm"])


def test_missing_local_rpm_errors(init_resources): # pylint: disable=unused-argument
    """ --kernel-rpm-path pointing at a nonexistent file must fail (not panic) """
    result = kh.build_enclave_err(TEST_IMAGES + "missing.eif",
                                  extra_flags=["--kernel-rpm-path", "/nonexistent/kernel.rpm"])
    
    stderr = result.stderr.decode("UTF-8")

    assert result.returncode != 0
    assert "[ E19 ]" in stderr
    assert "panicked" not in stderr



# Build the EIF with each kernel-selection mode.
def test_build_legacy_kernel_emits_deprecation_warning(init_resources): # pylint: disable=unused-argument
    """ --legacy-kernel still builds an EIF and outputs the deprecation warning """
    result = kh.build_enclave_ok(TEST_IMAGES + "legacy.eif", extra_flags=["--legacy-kernel"])
    err = result.stderr.decode("UTF-8")

    assert err.find("--legacy-kernel") != -1
    assert err.lower().find("deprecation notice") != -1


def test_build_al_repo_default(init_resources): # pylint: disable=unused-argument
    """Build an EIF using the default AL-repo kernel (no kernel flags)."""
    kh.build_enclave_ok(TEST_IMAGES + "al_default.eif")


def test_build_al_repo_pinned_version(init_resources): # pylint: disable=unused-argument
    """Build with a pinned --kernel-version."""
    kh.build_enclave_ok(TEST_IMAGES + "al_pinned.eif", extra_flags=["--kernel-version", "6.12"])


def test_build_al_repo_unavailable_version_errors(init_resources): # pylint: disable=unused-argument
    """An invalid --kernel-version must fail with a clear error."""
    kh.build_enclave_err(TEST_IMAGES + "al_bad.eif", extra_flags=["--kernel-version", "99.99.99"])


# Build and boot the AL-kernel EIF.
def test_al_kernel_boots_and_loads_modules(init_resources):
    """
    Build an AL-kernel EIF and boot it in debug mode, then confirm via the
    console that the multi-module init ran: the initramfs is unpacked and
    the init process logs the kernel modules it loads (from modules_load_order)
    """
    eif_name = "al_boot.eif"
    kh.build_enclave_ok(TEST_IMAGES + eif_name)

    result = run_enclave_ok(eif_name, "1028", "2", ["--debug-mode"])
    init_resources.enclave_id = json.loads(result.stdout.decode("UTF-8"))["EnclaveID"]

    console_proc = connect_console(init_resources.enclave_id)
    try:
        outs, errs = console_proc.communicate(timeout=15)
    except TimeoutExpired:
        console_proc.kill()
        outs, errs = console_proc.communicate()

    out_str = outs.decode("UTF-8")
    err_str = errs.decode("UTF-8")

    print("================= STDOUT =================")
    print(out_str)

    # Kernel unpacked the multi-module initramfs
    assert "Trying to unpack rootfs image as initramfs" in out_str

    # Init process started and walked modules_load_order:
    assert "Run /init as init process" in out_str
    assert "Loading module:" in out_str

    # Console closes (benign E45 disconnect) with non-empty stderr; only fail on a real panic:
    assert "panic" not in err_str.lower()


def test_al_kernel_eif_measurements(init_resources):
    """ Ensure the new AL kernel is the one measured into PCRs """
    eif_name = "al_meas.eif"
    build_err = kh.build_enclave_ok(TEST_IMAGES + eif_name).stderr.decode("UTF-8")

    found = re.search(r"Found:.*?(\d+\.\d+\.\d+)", build_err)
    assert found is not None, "build did not log the AL-repo kernel it selected"

    selected_version = found.group(1)
    selected_series = ".".join(selected_version.split(".")[:2])
    eif = json.loads(describe_eif_ok(eif_name).stdout.decode("UTF-8"))
    static = eif["Measurements"]
    kernel_version = eif["Metadata"]["KernelVersion"]

    assert kernel_version, "EIF metadata is missing KernelVersion"
    assert not kernel_version.startswith("4.14"), \
        "EIF was measured with the legacy bundled kernel: " + kernel_version
    assert kernel_version.startswith(selected_series), \
        "measured KernelVersion " + kernel_version + \
        " does not match the AL-repo kernel the build selected (" + \
        selected_version + ")"

    result_json = json.loads(run_enclave_ok(eif_name, "1028", "2").stdout.decode("UTF-8"))
    enclave_id = result_json["EnclaveID"]
    init_resources.enclave_id = enclave_id

    enclaves = json.loads(describe_enclaves_ok().stdout.decode("UTF-8"))
    matches = [e for e in enclaves if e.get("EnclaveID") == enclave_id]

    assert matches, "enclave " + enclave_id + " not found in describe-enclaves"

    running = matches[0]["Measurements"]

    assert static["PCR0"] == running["PCR0"]
    assert static["PCR1"] == running["PCR1"]
    assert static["PCR2"] == running["PCR2"]

    # Substituting the kernel changes the measurement
    legacy_eif_name = "al_meas_legacy.eif"
    kh.build_enclave_ok(TEST_IMAGES + legacy_eif_name, extra_flags=["--legacy-kernel"])
    legacy = json.loads(describe_eif_ok(legacy_eif_name).stdout.decode("UTF-8"))

    assert legacy["Metadata"]["KernelVersion"] != kernel_version, \
        "legacy and AL builds unexpectedly report the same KernelVersion"
    assert legacy["Measurements"]["PCR0"] != static["PCR0"], \
        "AL-kernel and legacy-kernel EIFs produced the same PCR0; " \
        "kernel substitution was not measured"
