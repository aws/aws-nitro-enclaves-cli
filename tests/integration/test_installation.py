# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/python3

import os
import tempfile
import helpers

# Test for checking install/uninstall flows correctly
# What it does:
#    1. Runs make install in temp dir.
#    2. Source the resulting env.sh.
#    3. Check nitro-cli & vsock-proxy are in the path
#       and ready to go
#
#
def test_install_uninstall():
        install_dir = tempfile.TemporaryDirectory()
        build_dir = tempfile.TemporaryDirectory()
        make = helpers.make_prefix(install_dir.name, build_dir.name)

        # Expect that the binaries are not present on the system
        help_cmd = "nitro-cli --help || vsock-proxy --help"
        helpers.run_cmd_err(help_cmd)

        install_cmd = make + " install"
        helpers.run_cmd_ok(install_cmd)

        # Expect that we are able to successfully run the binaries.
        help_cmd = "/bin/bash -ce \"source " + install_dir.name + "/env.sh && \
                        nitro-cli --help && vsock-proxy --help\""
        helpers.run_cmd_ok(help_cmd)

        uninstall_cmd = make + " uninstall"
        helpers.run_cmd_ok(uninstall_cmd)
        helpers.check_no_files(install_dir.name)
