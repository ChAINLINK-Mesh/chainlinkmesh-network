#!/usr/bin/env bash

if [ -z "${BUILD_DIR}" ]; then
	printf "Expected BUILD_DIR to be set\n" >&2
	exit 2
fi

if [ -z "${PROJ_DIR}" ]; then
	printf "Expected PROJ_DIR to be set\n" >&2
	exit 2
fi

export SERVER_CMD="${BUILD_DIR}/server/chainlinkmesh-server"
source "${PROJ_DIR}/utility-scripts.sh"

function run_client() {
	instance_ip="${1}"
	shift
	printf "Executing on %s\n" "${instance_ip}" >&2
	test_server "${instance_ip}" "${@}"
	exit $?
}

function run_server() {
	instance_ip="${1}"
	printf "Executing on %s\n" "${instance_ip}" >&2
	test_server "${instance_ip}"
	exit $?
}

while getopts "c:s:" options; do
	case "${options}" in
		c)
			shift "$((OPTIND-1))"

			if [ "${1}" = "--" ]; then
				shift
			fi

			run_client "${OPTARG}" "${@}"
			;;
		s)
			run_server "${OPTARG}"
			;;
		*)
			exit 1
			;;
	esac
done

if [ "${OPTIND}" -eq 1 ]; then
	printf "Expected to run as either a client or a server\n" >&2
	exit 1
fi
