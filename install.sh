#!/bin/bash

set -e -u

#The package names work for Ubuntu, AL2, RedHat 8 and CentOS 7
PACKAGES="docker make gcc"
PREREQ_OPTIONS="-y"

install_prerequisites() {
	if grep -qni "Amazon Linux\|CentOS\|RedHat" /etc/os-release
	then
		OPERATION="yum install"
	elif grep -qni "Ubuntu" /etc/os-release
	then
		OPERATION="apt-get install"
	else
		#Try to continue, just in case the user has done that themselves
		echo "Warning: prerequisite packages were not installed. Please manually install ${PACKAGES}."
		return
	fi
	${OPERATION} ${PREREQ_OPTIONS} ${PACKAGES}
}

update_git() {
	if [ -d .git ] || git rev-parse --git-dir > /dev/null 2>&1
	then
		git pull
		git checkout "$2"
	else
		echo "You're trying to install nitro-cli outside of the git repository."
		exit
	fi
}

install_nitro_cli() {
	make install
	source "${NITRO_CLI_INSTALL_DIR}"/env.sh
	echo "Nitro CLI is now installed. We recommend adding ${NITRO_CLI_INSTALL_DIR}/env.sh in your .bashrc file"
}

show_usage() {
	echo "Usage: $0 [--update <commit>] [--ask-for-confirmation] [--help]"
}

#Parse parameters
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
	-u|--update)
	update_git "$2" || show_usage
	shift 2
	;;
	-c|--ask-for-confirmation)
	PREREQ_OPTIONS=""
	shift
	;;
	-h|--help)
	show_usage
	exit
esac
done

install_prerequisites
install_nitro_cli
