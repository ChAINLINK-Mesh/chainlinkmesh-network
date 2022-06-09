#!/usr/bin/env bash

if [ -z "${CHAINLINK_DIR}" ]; then
	printf "Expected CHAINLINK_DIR to be defined with the location that this repository is mounted at on the container\n" >&2
	exit 2
fi

dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source "${dir}/utils.sh"

# Either runs the command on the current host (assuming that it is the Proxmox instance), or uses ssh on the given host
# to first get to the Proxmox instance.
function _run_on_proxmox() {
	if [ -z "${PVE_HOST}" ]; then
		${@}
		return $?
	else
		ssh "${PVE_HOST}" -C "${*}"
		return $?
	fi
}

function run_on_container() {
	local container_id="${1}"
	shift
	printf "bash\ncd %s && source test/utils.sh && %s\n" "${CHAINLINK_DIR}" "${*}" | _run_on_proxmox pct enter "${container_id}"
	return $?
}

function run_client_server() {
	local client_id="${1}"
	local server_id="${2}"
	local test="${3}"

	# Get IP of server
	local server_ip="$(run_on_container "${server_id}" ip route get 1 | awk -F ' src ' '{ print $2 }' | awk '{ print $1 }')"

	if [ -z "${server_ip}" ]; then
		printf "Failed to get server IP\n" >&2
		return 1
	fi

	local client_ip="$(run_on_container "${client_id}" ip route get 1 | awk -F ' src ' '{ print $2 }' | awk '{ print $1 }')"

	if [ -z "${client_ip}" ]; then
		printf "Failed to get client IP\n" >&2
		return 1
	fi

	local server_result=1

	(
		local server_service
		local server_result
		server_service="$(run_on_container "${server_id}" ./test/testsuite.sh -f "${test}")"
		server_result=$?

		if [ ${server_result} -ne 0 ]; then
			printf "Server failed:\n" >&2
			run_on_container "${server_id}" service_output "${server_service}" | indent >&2
			exit 2
		fi

		local server_connection_flags="$(run_on_container "${server_id}" ./test/testsuite.sh -c "${test}")"

		function cleanup_server() {
			err=$?
			trap - SIGINT EXIT

			run_on_container "${server_id}" "systemctl stop ${server_service} 2>/dev/null"

			return ${err}
		}

		trap "cleanup_server" SIGINT EXIT

		(
			local client_service
			local client_result
			client_service="$(run_on_container "${client_id}" ./test/testsuite.sh -f "${test}" -- "${server_connection_flags}")"
			client_result=$?

			if [ ${client_result} -ne 0 ]; then
				printf "Client failed:\n" >&2
				run_on_container "${client_id}" service_output "${client_service}" | indent >&2
				exit 2
			fi

			function cleanup_client() {
				err=$?
				trap - SIGINT EXIT

				run_on_container "${client_id}" "systemctl stop ${client_service} 2>/dev/null"

				return ${err}
			}

			trap "cleanup_client" SIGINT EXIT

			printf "Client:\n"
			run_on_container "${client_id}" service_output follow "${client_service}" | indent >&2
		)

		printf "Server:\n" >&2
		run_on_container "${server_id}" service_output "${server_service}" | indent >&2
	)

	return ${server_result}
}

client_id="${1}"
server_id="${2}"
test="${3}"

if [ -z "${client_id}" ]; then
	printf "Must specify the client container ID\n" >&2
	exit 1
elif [ -z "${server_id}" ]; then
	printf "Must specify the server container ID\n" >&2
	exit 1
elif [ -z "${test}" ]; then
	printf "Must specify the test to run\n" >&2
	exit 1
fi

run_client_server "${client_id}" "${server_id}" "${test}"
