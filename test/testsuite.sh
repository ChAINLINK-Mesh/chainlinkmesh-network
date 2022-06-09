#!/usr/bin/env bash

dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source "${dir}/utils.sh"

# Looks for --referrer and --client flags in the output.
function strip_connection_info() {
	local test_service="${1}"
	local connection_info=""

	while service_running "${test_service}"; do
		sleep 0.5

		# Read the test output by following the systemd journal logs.
		local output
		output=($(service_output "${test_service}" | awk 'BEGIN { status=1 } /^\s*--referrer/ { print $0 } /^\s*--client/ { print $0; status=0; exit } END { exit status }'))

		# If we failed to find all details, try again
		if [ $? -ne 0 ]; then
			continue
		fi

		for param in "${output[@]}"; do
			if [ "${param}" = '\' ]; then
				continue
			fi

			connection_info="${connection_info} ${param}"
		done

		break
	done

	if service_running "${test_service}"; then
		printf "${connection_info}"
	else
		printf "Test '%s' died\n" "${test_service}" >&2
	fi
}

function run_forked_test() {
	test_service="$(systemd-run --no-block "${dir}/run-test-async.sh" "${@}" 2>&1)"
	test_service="$(get_property_from_details 'Running as unit' "${test_service}")"

	if [ -z "${test_service}" ]; then
		exit 2
	fi

	printf "%s\n" "${test_service}"
}

function get_connection_details() {
	test_service="${1}"

	if [ -z "${test_service}" ]; then
		exit 2
	fi

	server_connection="$(strip_connection_info "${test_service}")"

	if [ -z "${server_connection}" ]; then
		exit 3
	fi

	printf "%s\n" "${server_connection}"
}

forking=0

while getopts "lfc:" options; do
	case "${options}" in
		l)
			list_tests
			exit 0
			;;
		f)
			forking=1
			;;
		c)
			get_connection_details "${OPTARG}"
			exit 0
			;;
		*)
			exit 1
			;;
	esac
done

# If there is a positional argument indicating a testname
if [ ! -z "${@:${OPTIND}:1}" ]; then
	if [ "${forking}" -eq 1 ]; then
		run_forked_test "${@:${OPTIND}}"
	else
		run_test "${@:${OPTIND}}"
	fi
	exit $?
fi

if [ "${OPTIND}" -eq 1 ]; then
	list_tests
	exit 0
fi
