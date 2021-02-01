#!/bin/sh
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

count=1
while true; do
    printf "[%4d] $HELLO\n" $count
    count=$((count+1))
    sleep 5
done
