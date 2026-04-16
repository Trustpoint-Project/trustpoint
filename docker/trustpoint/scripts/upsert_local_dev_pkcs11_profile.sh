#!/usr/bin/env bash
set -euo pipefail

HSM_ROOT="${TRUSTPOINT_HSM_ROOT:-/var/lib/trustpoint/hsm}"
HSM_CONFIG_DIR="${TRUSTPOINT_HSM_CONFIG_DIR:-${HSM_ROOT}/config}"
METADATA_FILE="${TRUSTPOINT_LOCAL_HSM_METADATA_FILE:-${HSM_CONFIG_DIR}/local-dev-token.env}"

if [[ ! -r "${METADATA_FILE}" ]]; then
  printf '[local-dev-pkcs11-profile] metadata file not found: %s\n' "${METADATA_FILE}" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "${METADATA_FILE}"
set +a

: "${TRUSTPOINT_LOCAL_HSM_PROFILE_NAME:?missing profile name in metadata}"
: "${TRUSTPOINT_LOCAL_HSM_MODULE_PATH:?missing module path in metadata}"
: "${TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL:?missing token serial in metadata}"
: "${TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE:?missing user PIN file in metadata}"

cd /var/www/html/trustpoint
uv run trustpoint/manage.py shell -c '
import os
import sys

from django.db import connection

table_names = set(connection.introspection.table_names())
if "crypto_provider_profile" not in table_names:
    print(
        "[local-dev-pkcs11-profile] crypto_provider_profile table does not exist yet; skipping profile upsert.",
        file=sys.stderr,
    )
    raise SystemExit(0)

from crypto.models import CryptoProviderProfileModel, ProviderAuthSource

profile_name = os.environ["TRUSTPOINT_LOCAL_HSM_PROFILE_NAME"]
profile, _ = CryptoProviderProfileModel.objects.update_or_create(
    name=profile_name,
    defaults={
        "module_path": os.environ["TRUSTPOINT_LOCAL_HSM_MODULE_PATH"],
        "token_label": None,
        "token_serial": os.environ["TRUSTPOINT_LOCAL_HSM_TOKEN_SERIAL"],
        "slot_id": None,
        "auth_source": ProviderAuthSource.FILE,
        "auth_source_ref": os.environ["TRUSTPOINT_LOCAL_HSM_USER_PIN_FILE"],
        "max_sessions": 8,
        "borrow_timeout_seconds": 5.0,
        "rw_sessions": True,
        "allow_legacy_label_lookup": False,
        "active": True,
    },
)
CryptoProviderProfileModel.objects.exclude(pk=profile.pk).filter(active=True).update(active=False)
print(f"Configured provider profile {profile.name} for token serial {profile.token_serial}.")
'