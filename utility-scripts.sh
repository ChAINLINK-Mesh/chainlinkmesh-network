#!/usr/bin/env -S sh -c 'printf "This file is meant to be sourced!\n" ; false'

if [ -z "${SERVER_CMD}" ]; then
	SERVER_CMD="${PWD}/server/chainlinkmesh-server"

	if [ ! -x "${SERVER_CMD}" ]; then
		printf "Could not find server executable at location %s\n" "${SERVER_CMD}" >/dev/stderr
		exit 1
	fi
fi

TEST_DATA_DIR="/tmp/chainlink/"
TEST_INSTANCE_PREFIX="instance_"
TEST_BASE_PORT=3001

function get_next_instance_id() {
	local next_instance_id=0

	if [ ! -d "${TEST_DATA_DIR}" ]; then
		mkdir "${TEST_DATA_DIR}"
	fi

	find "${TEST_DATA_DIR}" -name "${TEST_INSTANCE_PREFIX}"'*' -exec basename '{}' \; \
		| sed -e "s/^${TEST_INSTANCE_PREFIX}//" \
		| sort -n \
		| while read -r test_instance_id; do
		# Expect the $next_instance_id = $text_instances[$next_instance_id]
		# If there is a gap, then we have a missing index ID, so reassign to this instance.

		if [ ${next_instance_id} -lt "${test_instance_id}" ]; then
			break
		fi

		next_instance_id=$((${next_instance_id}+1))
	done

	printf "%d" ${next_instance_id}
}

function get_instance_public_port() {
	local instance=$1
	printf "%d" $((${instance}*3+0+${TEST_BASE_PORT}))
}

function get_instance_wireguard_port() {
	local instance=$1
	printf "%d" $((${instance}*3+1+${TEST_BASE_PORT}))
}

function get_instance_private_port() {
	local instance=$1
	printf "%d" $((${instance}*3+2+${TEST_BASE_PORT}))
}

function priv-net-run() {
	local prog="$(which ${1})"
	local suid=""

	which sudo > /dev/null 2> /dev/null && suid=(sudo -E)
	which doas > /dev/null 2> /dev/null && suid=doas

	# Use capsh if not root
	if [ "$EUID" -ne 0 ]; then
		if [ -z "${suid}" ]; then
			printf "No program to get root\n" > /dev/stderr
			return 1
		fi

		${suid} capsh --caps="cap_setpcap,cap_setuid,cap_setgid+ep cap_net_admin,cap_net_bind_service+eip" --keep=1 --user="$USER" --addamb="cap_net_admin,cap_net_bind_service" --shell="${prog}" -- ${@:2}
	else
		"${prog}" ${@:2}
	fi
}

function _run_test_server() {
	local config_file="${1}"
	local hostname="${2}"
	local instance_id="${3}"

	(
		# Remove instance config on exit
		function cleanup() {
			err=$?
			config_file=$1
			trap - SIGINT SIGTERM EXIT
			rm -f "${config_file}"
			exit $err
		}

		trap "cleanup ${config_file}" SIGINT SIGTERM EXIT

		priv-net-run ${SERVER_CMD} \
			"--config=${config_file}" \
			"--public-address=${hostname}:$(get_instance_public_port ${instance_id})" \
			"--wireguard-address=${hostname}:$(get_instance_wireguard_port ${instance_id})" \
			"--private-port=$(get_instance_private_port ${instance_id})" "${@}"
	)
}

function test_server() {
	local instance_id=$(get_next_instance_id)
	local config_file="${TEST_DATA_DIR}/${TEST_INSTANCE_PREFIX}${instance_id}"
	local hostname="${1:-"127.0.0.1"}"

	if [ $# -ge 1 ]; then
		shift 1
	fi

	touch "${config_file}"

	_run_test_server "${config_file}" "${hostname}" "${instance_id}" "${@}"

	return $err
}
