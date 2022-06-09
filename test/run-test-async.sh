#!/usr/bin/env bash

dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# Import testsuite function definitions.
source "${dir}/utils.sh"

run_test "${@}" 2>&1
printf "Test ended\n" >&2
