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

TEST_COUNT=1000

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
		local client_pids=()

		function cleanup_client() {
			err=$?
			trap - SIGINT EXIT

			kill -INT "${client_pids[@]}"
			return ${err}
		}

		trap "cleanup_client" SIGINT EXIT

		printf "Connecting clients to server\n" >&2
		date --iso-8601=seconds

		for i in $(seq 1 ${TEST_COUNT}); do
			local instance_id="${i}"
			local config_file="${TEST_DATA_DIR}/${TEST_INSTANCE_PREFIX}${instance_id}"
			local hostname="${instance_ip}"
			local logname="/tmp/instance_${i}_log"

			touch "${config_file}"

			_run_test_server "${config_file}" "${hostname}" "${instance_id}" "${@}" >"${logname}" 2>&1 &
			client_pids+=("$!")
		done

		date --iso-8601=seconds
		printf "Now checking clients connected\n" >&2

		for i in $(seq 1 ${TEST_COUNT}); do
			local logname="/tmp/instance_${i}_log"

			while ! grep -q "Connected to server" "${logname}" && [ -d "/proc/${client_pids[$((${i}-1))]}" ]; do
				sleep 0.1
			done
		done

		date --iso-8601=seconds
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
