#!/usr/bin/env bash

if [ -z "${BASH_SOURCE}" ]; then
	printf "This script '%s' is not meant to be run, but instead sourced\n" "${0}" >&2
	return 255
fi

dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE}")" && pwd)"
script="$(basename -- "$0")"

function service_running() {
	systemctl is-active "${1}" >/dev/null
}

function service_output() {
	if [ "${1}" = "follow" ]; then
		shift
		journalctl --no-tail --follow -o cat _SYSTEMD_UNIT="${1}"
	else
		journalctl --no-tail -o cat _SYSTEMD_UNIT="${1}"
	fi
}

function indent() {
	local indent_amount="${1:-1}"
	local indent=""

	for i in {1..${indent_amount}}; do
		indent="$(printf "%s\t" "${indent}")"
	done

	while read -r line; do
		printf "%s%s\n" "${indent}" "${line}"
	done
}

function get_property_from_details() {
	local property="${1}"
	local details="${2}"

	printf "%s\n" "${details}" | grep "^${property}: " | awk -F "${property}: " '{ printf $2; }'
}

function list_tests() {
	local executables=$(find "${dir}/testsuite" -type f -executable -exec basename {} \;)

	for test in ${executables[@]}; do
		if [ "${test}" = "${script}" ]; then
			continue
		fi

		printf '%s\n' "${test}" | sed -e 's/\.sh$//' >&2
	done
}

function run_test() {
	build_dir="${BUILD_DIR:-"${dir}/../build"}"

	if [ ! -d "${build_dir}" ]; then
		printf "Build directory '%s' doesn't exist\n" "${build_dir}" >&2
		printf "Set BUILD_DIR to the correct value\n" >&2
		return 2
	fi

	local testname="${1}"
	local testfile="${dir}/testsuite/${testname}.sh"
	shift
	printf "Running test %s with arguments %s\n" "${testname}" "${*}" >&2

	if [ ! -x "${testfile}" ]; then
		printf "Couldn't find the test called '%s'\n" "${testname}" >&2
		return 1
	fi

	if [ "${1}" = "--" ]; then
		shift
	fi

	(
		export BUILD_DIR="${build_dir}"
		export PROJ_DIR="${dir}/.."
		local ip="$(ip route get 1 | awk -F ' src ' '{ print $2 }' | awk '{ print $1 }')"

		if [ -z "$1" ]; then
			"${testfile}" -s "${ip}"
		else
			"${testfile}" -c "${ip}" -- "${@}"
		fi
	)
}

