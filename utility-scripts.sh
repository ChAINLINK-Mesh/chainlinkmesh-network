#!/usr/bin/env -S sh -c 'printf "This file is meant to be sourced!\n" ; false'

SERVER_CMD="${PWD}/server/wgmesh-server"

if [ ! -x "${SERVER_CMD}" ]; then
	printf "Could not find server executable at location %s\n" "${SERVER_CMD}" >/dev/stderr
	exit 1
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

function test_server() {
	local instance_id=$(get_next_instance_id)
	local config_file="${TEST_DATA_DIR}/${TEST_INSTANCE_PREFIX}${instance_id}"

	touch "${config_file}"

	(
		# Remove instance config on exit
		function cleanup() {
			err=$?
			config_file=$1
			trap - SIGINT EXIT
			rm -f "${config_file}"
			exit $err
		}

		trap "cleanup ${config_file}" SIGINT EXIT

		priv-net-run ${SERVER_CMD} \
			"--config=${config_file}" \
			"--public-address=127.0.0.1:$(get_instance_public_port ${instance_id})" \
			"--wireguard-address=127.0.0.1:$(get_instance_wireguard_port ${instance_id})" \
			"--private-port=$(get_instance_private_port ${instance_id})" "$@"
	)

	return $err
}
