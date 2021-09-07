# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/python3
"""
This module tests the install/uninstall flow.
"""

import tempfile
import helpers


def test_install_uninstall():
    """
    Test for checking install/uninstall flows correctly
    What it does:
       1. Runs make install in temp dir.
       2. Source the resulting env.sh.
       3. Check nitro-cli & vsock-proxy are in the path and ready to go.
    """

    install_dir = tempfile.TemporaryDirectory()
    build_dir = tempfile.TemporaryDirectory()
    make = helpers.make_prefix(install_dir.name, build_dir.name)

    # Expect that the binaries are not present on the system
    help_cmd = "nitro-cli --help || vsock-proxy --help"
    helpers.run_cmd_err(help_cmd)

    install_cmd = make + " install"
    build_nitro_cli = make + " nitro-cli"
    build_vsock = make + " vsock-proxy"
    helpers.run_cmd_ok(build_nitro_cli)
    helpers.run_cmd_ok(build_vsock)
    helpers.run_cmd_ok(install_cmd)

    # Expect that we are able to successfully run the binaries.
    help_cmd = "/bin/bash -ce \"source " + install_dir.name + \
                   "/etc/profile.d//nitro-cli-env.sh && nitro-cli --help && vsock-proxy --help\""
    helpers.run_cmd_ok(help_cmd)

    # Perform clean-up.
    uninstall_cmd = make + " uninstall"
    helpers.run_cmd_ok(uninstall_cmd)
    helpers.check_no_files(install_dir.name)

    # Also remove the inserted driver.
    rmmod_cmd = "rmmod nitro_enclaves"
    helpers.run_cmd_ok(rmmod_cmd)
