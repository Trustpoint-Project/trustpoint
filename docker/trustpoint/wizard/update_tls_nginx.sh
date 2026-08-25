#!/bin/bash
set -eE -o pipefail

if [ "$#" -ne 1 ]; then
    echo "ERROR: Missing required parameter."
    echo "Usage: $0 [hsm|no_hsm]"
    exit 1
fi

storage_mode="$1"
if [[ "$storage_mode" != "hsm" && "$storage_mode" != "no_hsm" ]]; then
    echo "ERROR: Invalid parameter '$storage_mode'. Must be 'hsm' or 'no_hsm'."
    echo "Usage: $0 [hsm|no_hsm]"
    exit 2
fi

echo "Applying TLS credential for storage mode: $storage_mode"
exec "$(dirname "$0")/update_tls.sh"
