

if [ -z ${NITRO_CLI_INSTALL_DIR} ];
then
    echo "INSTALLDIR variable not set, please set the variable to the location where nitro-cli is installed"
    return -1
fi

lsmod | grep -q nitro_enclaves || \
    sudo insmod ${NITRO_CLI_INSTALL_DIR}/lib/modules/extra/nitro_enclaves/nitro_enclaves.ko

export PATH=${PATH}:${NITRO_CLI_INSTALL_DIR}/usr/sbin/
export NITRO_CLI_BLOBS=${NITRO_CLI_INSTALL_DIR}/opt/nitro_cli
