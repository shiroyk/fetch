#!/bin/sh
# Assert the copied internal/httpcommon package differs from upstream only at its sites.
# Usage: httpcommon-diff.sh [x/net version, defaults to the manifest base_version]
exec python3 -B "$(dirname "$0")/check.py" httpcommon "$@"
