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
	local instance_ip="${1}"
	shift

	local server_ip
	local server_port
	for arg in "${@}"; do
		if [[ "${arg}" =~ ^--client=(.*):(.*)$ ]]; then
			server_ip="${BASH_REMATCH[1]}"
			server_port="${BASH_REMATCH[2]}"
		fi
	done

	if [ -z "${server_ip}" ] || [ -z "${server_port}" ]; then
		printf "Failed to find server contact details" >&2
		exit 2
	fi

	(
		test_server "${instance_ip}" "${@}" &
		local client_pid=$!

		function cleanup_client() {
			err=$?
			trap - SIGINT EXIT
			kill -INT "${client_pid}"
			return ${err}
		}

		trap "cleanup_client" SIGINT EXIT

		sleep 5
		local server_wireguard_address="$(wg show all allowed-ips | grep '^chainlink' | head -n 1 | awk '{ sub(/\/[[:digit:]]+$/, "", $3); print $3 }')"

		iperf3 -c "${server_wireguard_address}" --time 60 >&2
	)

	exit $?
}

function run_server() {
	local instance_ip="${1}"

	(
		test_server "${instance_ip}" &
		local server_pid=$!

		function cleanup_server() {
			err=$?
			trap - SIGINT EXIT
			kill -INT "${server_pid}"
			return ${err}
		}

		trap "cleanup_server" SIGINT EXIT

		iperf3 -s --one-off >&2
	)

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
