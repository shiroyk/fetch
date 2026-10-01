#!/bin/sh
# Run the T1, T2 and T4 gates for a re-base.
# Usage: verify.sh [x/net version, defaults to the manifest base_version]
exec python3 -B "$(dirname "$0")/check.py" verify "$@"
