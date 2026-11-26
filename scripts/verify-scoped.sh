#!/usr/bin/env bash
# Scoped verification. Nothing in this project is slow yet, so it is the full check; split it when
# a step (an end-to-end suite, a footprint run) becomes too slow to run after every task.
set -uo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/verify.sh"
