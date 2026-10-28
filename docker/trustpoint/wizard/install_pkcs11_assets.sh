#!/bin/bash
# Root-owned sudo entry point: never interpret caller-selected shell files.
exec /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py privileged install_pkcs11_assets.sh "$@"
