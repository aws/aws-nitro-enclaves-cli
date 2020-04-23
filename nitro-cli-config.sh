#!/bin/bash

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

################################################################
# Nitro CLI environment configuration script.
#
# This script provides:
# - Nitro Enclaves driver build, insertion, removal and clean-up
# - Huge-page number configuration, as needed for enclave memory
# Depending on the operation, it might require root privileges.
################################################################

# The directory holding the Nitro Enclaves driver source.
DRIVER_DIR="."

# The name of the Nitro Enclaves driver.
DRIVER_NAME="nitro_enclaves"

# The maximum percentage of free memory available.
FREE_MEM_MAX_PERCENTAGE=50

# Check if a provided string is a positive integer.
function check_if_number {
    case "$1" in
        # Non-digits.
        ''|*[!0-9]*)
            return 1
            ;;

        # Digits.
        *)
            return 0
            ;;
    esac
}

# Run the provided command under 'sudo'.
function sudo_run {
    if [ "$(id -u)" -eq 0 ]
    then
        "$SHELL" -c "$@"
    else
        sudo -- "$SHELL" -c "$@"
    fi

    return $?
}

# Configure the needed number of huge-pages.
function configure_huge_pages {
    local needed_mem
    local free_mem
    local huge_page_size

    # Get the requested memory, trimming starting and ending whitespace.
    needed_mem="$1"

    # Fetch the total free memory and size of a huge page.
    free_mem=$(grep -i "memfree" /proc/meminfo | tr -s ' ' | cut -d' ' -f2)
    huge_page_size=$(grep -i "hugepagesize" /proc/meminfo | tr -s ' ' | cut -d' ' -f2)

    # Check if the required parameters have been obtained.
    check_if_number "$needed_mem" || fail "The needed memory amount ($needed_mem) is invalid."
    check_if_number "$free_mem" || fail "The free memory amount ($free_mem) is invalid."
    check_if_number "$huge_page_size" || fail "The huge page size ($huge_page_size) is invalid."

    # The available memory and huge-page size are given in kB. Convert the needed memory to kB as well.
    [ "$needed_mem" -gt 0 ] || fail "Requested memory must be greater than 0."
    needed_mem=$((needed_mem * 1024))

    # Obtain and set the corresponding number of huge pages.
    num_pages=$((1 + (needed_mem - 1) / huge_page_size))
    actual_mem=$((num_pages * huge_page_size))

    # The maximum amount of free memory available for use as huge pages.
    free_mem=$((free_mem * FREE_MEM_MAX_PERCENTAGE / 100))

    # Fail if the requested memory is larger than what's available.
    [ "$actual_mem" -le "$free_mem" ] || fail "The actual memory amount ($actual_mem kB) is greater than the memory limit ($free_mem kB)."

    # Configure the number of huge pages.
    sudo_run "echo $num_pages > /proc/sys/vm/nr_hugepages" || fail "Failed to configure the number of huge pages."

    # Verify that the exact value was written (value may be smaller if the instance has too little available memory).
    actual_num_pages="$(cat /proc/sys/vm/nr_hugepages)"
    [ "$num_pages" -eq "$actual_num_pages" ] || fail "Insufficient huge pages available."
}

# Print an error message and fail.
function fail {
    echo "Error: $1"
    print_usage
    exit 1
}

# Print the script's usage instructions.
function print_usage {
    echo "Usage: $0 [-d <driver-directory>] [-i] [-r] [-c] [-h] [-m <memory_mb_needed>]"
}

# Verify that the provided driver directory is correct.
function verify_driver_directory {
    declare -a subdirs=("include/linux" "include/uapi/linux" "drivers/virt/amazon/$DRIVER_NAME")
    for subdir in "${subdirs[@]}"; do
        [ -d "$DRIVER_DIR/$subdir" ] || return 1
    done

    return 0
}

# Build and insert the driver.
function driver_build_and_insert {
    # Build the driver.
    echo "Building the driver..."
    make &> /dev/null || fail "Failed to build driver."
    echo "Done."

    # Remove an older driver if it is inserted.
    sudo_run "rmmod $DRIVER_NAME &> /dev/null"

    echo "Inserting the driver..."

    # Insert the new driver.
    sudo_run "insmod $DRIVER_NAME.ko" || fail "Failed to insert driver."

    # Verify that the new driver has been inserted.
    [ "$(lsmod | grep -c $DRIVER_NAME)" -eq 1 ] || fail "The driver is not visible."

    echo "Done."
}

# Clean the driver.
function driver_clean {
    echo "Cleaning the driver... "
    make clean &> /dev/null || fail "Failed to clean driver."
    echo "Done."
}

# Remove the driver.
function driver_remove {
    echo "Removing the driver..."

    # Attempt to remote the driver.
    sudo_run "rmmod $DRIVER_NAME &> /dev/null" || fail "Failed to remove driver."

    # Verify that the driver has indeed been removed.
    [ "$(lsmod | grep -c $DRIVER_NAME)" -eq 0 ] || fail "The driver is still visible."

    echo "Done."
}

# Run a function inside the driver directory.
function run_in_driver_dir {
    local driver_source_dir

    verify_driver_directory || fail "Driver directory '$DRIVER_DIR' is invalid."
    driver_source_dir="$DRIVER_DIR/drivers/virt/amazon/$DRIVER_NAME"
    pushd "$driver_source_dir" &> /dev/null || fail "Driver source directory '$driver_source_dir' can't be accessed."

    # Run the function here.
    "$@"

    popd &> /dev/null
}

# Script entry point.
[ "$#" -gt 0 ] || fail "No arguments given."

while getopts ":hd:cirm:" opt; do
    case ${opt} in
        h ) # Help was requested.
            print_usage
            exit 0
            ;;

        d)  # The driver directory was provided.
            DRIVER_DIR="$OPTARG"
            ;;

        i)  # Insert (after building) the driver.
            run_in_driver_dir driver_build_and_insert
            ;;

        r)  # Remove the driver.
            driver_remove
            ;;

        c)  # Clean-up was requested.
            run_in_driver_dir driver_clean
            ;;

        m)  # The needed memory was provided.
            echo "Configuring the huge page memory..."
            configure_huge_pages "$OPTARG"
            echo "Done."
            ;;

        \?) # Invalid option(s) provided.
            fail "Invalid argument(s) provided."
            ;;
    esac
done

exit 0