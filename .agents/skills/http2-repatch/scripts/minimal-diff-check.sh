#!/bin/sh
# Assert that only files with a manifest site differ from upstream (T4).
# Usage: minimal-diff-check.sh [x/net version, defaults to the manifest base_version]
exec python3 -B "$(dirname "$0")/check.py" minimal-diff "$@"
