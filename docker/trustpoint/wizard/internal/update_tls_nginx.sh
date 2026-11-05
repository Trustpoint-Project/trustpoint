#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ] || [[ "$1" != "hsm" && "$1" != "no_hsm" ]]; then
    echo "Usage: $0 [hsm|no_hsm]" >&2
    exit 2
fi

exec /bin/bash /etc/trustpoint/wizard/internal/update_tls.sh
