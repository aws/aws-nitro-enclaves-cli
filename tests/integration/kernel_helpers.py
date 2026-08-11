# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/python3
"""
Helpers for the generic Amazon Linux kernel build/boot tests
"""

import helpers

SAMPLE_DOCKER = "hello-world:latest"


def build_enclave_cmd(output_eif, docker_uri=SAMPLE_DOCKER, extra_flags=None):
    """ Builds a build-enclave command. """
    args = [
        "nitro-cli", "build-enclave",
        "--docker-uri", docker_uri,
        "--output-file", output_eif,
    ]
    if extra_flags is not None:
        args.extend(extra_flags)
    return args


def build_enclave_ok(output_eif, docker_uri=SAMPLE_DOCKER, extra_flags=None):
    """ Builds an EIF and checks it returned success. """
    args = build_enclave_cmd(output_eif, docker_uri, extra_flags)
    return helpers.run_subprocess_ok(args)


def build_enclave_err(output_eif, docker_uri=SAMPLE_DOCKER, extra_flags=None):
    """ Builds an EIF and checks it returned error. """
    args = build_enclave_cmd(output_eif, docker_uri, extra_flags)
    return helpers.run_subprocess_err(args)
