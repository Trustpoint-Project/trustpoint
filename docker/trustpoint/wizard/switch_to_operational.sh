#!/bin/bash
# Root-owned control entry point: never interpret caller-selected shell files.
exec /usr/local/bin/python3 -I /etc/trustpoint/runtime_config.py switch "$@"
