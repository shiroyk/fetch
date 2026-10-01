#!/bin/sh
# Report file-selection drift for the vendored http2 copy.
# Usage: subset-check.sh [x/net version, defaults to the manifest base_version]
exec python3 -B "$(dirname "$0")/check.py" subset "$@"
