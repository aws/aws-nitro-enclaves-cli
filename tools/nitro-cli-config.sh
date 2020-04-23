#!/bin/bash

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

################################################################
# Nitro CLI environment configuration script.
#
# This script provides:
# - Nitro Enclaves driver build, insertion, removal and clean-up
# - Huge page number configuration, as needed for enclave memory
# Depending on the operation, it might require root privileges.
################################################################

set -eu

# The directory holding the Nitro Enclaves driver source.
DRIVER_DIR="."

# The name of the Nitro Enclaves driver.
DRIVER_NAME="nitro_enclaves"

# The maximum percentage of free memory available.
FREE_MEM_MAX_PERCENTAGE=50

# The name of the NE group that will own the device file.
NE_GROUP_NAME="ne"

# The name of the udev rules file for the device file.
UDEV_RULES_FILE="99-nitro-enclaves.rules"

# The current user.
THIS_USER="$(whoami)"

# A flag indicating if we must reset the terminal. This is needed when
# inserting the driver and configuring the NE access group, since group
# visibility normally requires a log-out / log-in or reboot.
SHELL_RESET="0"

# Trap any exit condition, including all fatal errors.
trap 'error_handler $? $LINENO' EXIT
error_handler() {
    if [ "$1" -ne 0 ]; then
        # error handling goes here
        echo "Error on line $2 with status: $1"
    fi
}

# Check if a provided string is a positive integer.
function check_if_number {
    [[ "$1" =~ ^[0-9]+$ ]]
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

# Configure the needed number of huge pages.
function configure_huge_pages {
    local needed_mem
    local free_mem
    local huge_page_size

    echo "Configuring the huge page memory..."

    # Get the requested memory, trimming starting and ending whitespace.
    needed_mem="$1"

    # Fetch the total free memory and size of a huge page.
    free_mem=$(grep -i "memfree" /proc/meminfo | tr -s ' ' | cut -d' ' -f2)
    huge_page_size=$(grep -i "hugepagesize" /proc/meminfo | tr -s ' ' | cut -d' ' -f2)

    # Check if the required parameters have been obtained.
    check_if_number "$needed_mem" || fail "The needed memory amount ($needed_mem) is invalid."
    check_if_number "$free_mem" || fail "The free memory amount ($free_mem) is invalid."
    check_if_number "$huge_page_size" || fail "The huge page size ($huge_page_size) is invalid."

    # The available memory and huge page size are given in kB. Convert the needed memory to kB as well.
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
    [ "$num_pages" -eq "$actual_num_pages" ] || fail "Insufficient huge pages available ($actual_num_pages instead of the $num_pages needed)."

    echo "Done."
}

# Print an error message and fail.
function fail {
    echo "Error: $1"
    exit 1
}

# Print the script's usage instructions.
function print_usage {
    echo "Usage: $0 [-d <driver-directory>] [-i] [-r] [-c] [-h] [-m <memory_mb_needed>]"
    echo -e "\t-d: The path to the directory containing the driver source code, including headers."
    echo -e "\t-i: Build the driver, insert it, configure its ownership and permissions."
    echo -e "\t-r: Remove the driver."
    echo -e "\t-c: Clean up the driver build."
    echo -e "\t-h: Print these help messages."
    echo -e "\t-m: The amount of memory that will be needed for running enclaves, in megabytes."
}

# Verify that the provided driver directory is correct.
function verify_driver_directory {
    declare -a subdirs=("include/linux" "include/uapi/linux" "drivers/virt/amazon/$DRIVER_NAME")
    for subdir in "${subdirs[@]}"; do
        [ -d "$DRIVER_DIR/$subdir" ] || return 1
    done

    return 0
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

    # Attempt to remove the driver.
    sudo_run "rmmod $DRIVER_NAME &> /dev/null" || fail "Failed to remove driver."

    # Verify that the driver has indeed been removed.
    [ "$(lsmod | grep -cw $DRIVER_NAME)" -eq 0 ] || fail "The driver is still visible."

    echo "Done."
}

# Build and insert the driver. Also configure udev after it is inserted.
function driver_build_and_insert {
    # Build the driver.
    echo "Building the driver..."
    make &> /dev/null || fail "Failed to build driver."
    echo "Done."

    # Remove an older driver if it is inserted.
    if [ "$(lsmod | grep -cw $DRIVER_NAME)" -gt 0 ]; then
        driver_remove
    fi

    echo "Inserting the driver..."

    # Insert the new driver.
    sudo_run "insmod $DRIVER_NAME.ko" || fail "Failed to insert driver."

    # Verify that the new driver has been inserted.
    [ "$(lsmod | grep -cw $DRIVER_NAME)" -eq 1 ] || fail "The driver is not visible."

    echo "Configuring the device file..."

    # Create the NE group if it doesn't already exist.
    if [ "$(grep -cw $NE_GROUP_NAME /etc/group)" -eq 0 ]; then
        sudo_run "groupadd $NE_GROUP_NAME"
    fi

    # Check that the group exists.
    sudo_run "getent group $NE_GROUP_NAME &> /dev/null" || fail "The group '$NE_GROUP_NAME' is not present."

    # Define the udev rules file. The string will be expanded twice (once below and the second time when it is
    # passed as an argument to $SHELL) and we need the double-quotes to make it into the rules file; hence, we
    # need to provide them pre-pre-expanded, i.e <\\\"> (since these expand to <\"> which expands to <">).
    sudo_run "echo KERNEL==\\\"$DRIVER_NAME\\\" SUBSYSTEM==\\\"misc\\\" OWNER=\\\"root\\\" GROUP=\\\"$NE_GROUP_NAME\\\" MODE=\\\"0660\\\" > /etc/udev/rules.d/$UDEV_RULES_FILE" || fail "Could not write udev rules file."

    # Trigger the udev rule.
    sudo_run "udevadm control --reload"
    sudo_run "udevadm trigger /dev/$DRIVER_NAME" || fail "Could not apply the NE udev rule."

    # Verify that the driver now has correct ownership and permissions
    [ "root" == "$(stat -c '%U' /dev/$DRIVER_NAME)" ] || fail "Device file has incorrect owner."
    [ "$NE_GROUP_NAME" == "$(stat -c '%G' /dev/$DRIVER_NAME)" ] || fail "Device file has incorrect group."
    [ "660" == "$(stat -c '%a' /dev/$DRIVER_NAME)" ] || fail "Device file has incorrect permissions."

    # Lastly, we need to add the non-root user to the NE group.
    echo "Adding user '$THIS_USER' to the group '$NE_GROUP_NAME'..."
    sudo_run "usermod -a -G $NE_GROUP_NAME $THIS_USER" || fail "Could not add user to the NE group."
    echo "Done."

    # If we have configured the group membership but the user still doesn't see it, we would normally need to
    # log-out and log-in or reboot. We avoid this by resetting the shell with the existing user. This must
    # always be done last in the script.
    if [ "$(groups | grep -cw $NE_GROUP_NAME)" -eq 0 ]; then
        SHELL_RESET="1"
    fi
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
            configure_huge_pages "$OPTARG"
            ;;

        \?) # Invalid option(s) provided.
            fail "Invalid argument(s) provided."
            ;;
    esac
done

# Reset the shell after configuring the driver.
if [ "$SHELL_RESET" -eq 1 ]; then
    echo "Shell will be reset."
    sudo_run "exec su -l $THIS_USER"
fi

exit 0
