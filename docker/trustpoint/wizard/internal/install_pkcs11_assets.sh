#!/bin/bash
set -eu

STAGING_ROOT="$(dirname "${TRUSTPOINT_BOOTSTRAP_DB_PATH:-/var/lib/trustpoint/bootstrap/bootstrap.sqlite3}")/staging/pkcs11"
HSM_ROOT="${TRUSTPOINT_HSM_ROOT:-/var/lib/trustpoint/hsm}"
HSM_CONFIG_DIR="${TRUSTPOINT_HSM_CONFIG_DIR:-${HSM_ROOT}/config}"
HSM_LIB_DIR="${TRUSTPOINT_HSM_LIB_DIR:-${HSM_ROOT}/lib}"
FINAL_MODULE_PATH="${HSM_LIB_DIR}/uploaded-pkcs11-module.so"
PIN_FILE_PATH="${HSM_CONFIG_DIR}/user-pin.txt"
FINAL_CONFIG_PATH="${HSM_CONFIG_DIR}/uploaded-pkcs11-provider.cfg"
MODULE_PATH_FILE="${HSM_CONFIG_DIR}/pkcs11-module-path.txt"

log() {
    local level=$1
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - install_pkcs11_assets.sh - ${level} - $*"
}

# Never let root follow a link planted in the web-writable parent directory.
for path in "$HSM_ROOT" "$HSM_CONFIG_DIR" "$HSM_LIB_DIR"; do
    if [ -L "$path" ]; then
        log ERROR "Refusing symlinked PKCS#11 install path: $path"
        exit 2
    fi
done

case "${1:-}" in
    --clear-module)
        rm -f "$FINAL_MODULE_PATH" "$MODULE_PATH_FILE"
        log INFO "PKCS#11 module cleared from protected HSM area."
        exit 0
        ;;
    --clear-pin)
        rm -f "$PIN_FILE_PATH"
        log INFO "PKCS#11 user PIN cleared from protected HSM area."
        exit 0
        ;;
    --clear-config)
        rm -f "$FINAL_CONFIG_PATH"
        log INFO "PKCS#11 provider config cleared from protected HSM area."
        exit 0
        ;;
esac

use_installed_pin=0
if [ "${1:-}" = "--use-installed-pin" ]; then
    use_installed_pin=1
    shift
fi

if [ "$#" -ne 1 ] && [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
    log ERROR "Expected staged PIN, staged module plus PIN, staged module plus PIN plus provider config, or --use-installed-pin."
    exit 1
fi

staged_module=""
staged_pin=""
staged_config=""
install_module=0
install_config=0

if [ "$use_installed_pin" -eq 1 ]; then
    staged_module="$(readlink -f "$1" 2>/dev/null || true)"
    install_module=1
elif [ "$#" -ge 2 ]; then
    staged_module="$(readlink -f "$1" 2>/dev/null || true)"
    staged_pin="$(readlink -f "$2" 2>/dev/null || true)"
    install_module=1
else
    staged_pin="$(readlink -f "$1" 2>/dev/null || true)"
fi

if [ "$use_installed_pin" -eq 1 ] && [ "$#" -eq 2 ]; then
    staged_config="$(readlink -f "$2" 2>/dev/null || true)"
    install_config=1
elif [ "$#" -eq 3 ]; then
    staged_config="$(readlink -f "$3" 2>/dev/null || true)"
    install_config=1
fi

if [ "$use_installed_pin" -eq 1 ] && [ "$#" -ne 1 ] && [ "$#" -ne 2 ]; then
    log ERROR "Expected --use-installed-pin with staged module and optional staged provider config."
    exit 1
fi

if [ "$install_module" -eq 1 ]; then
    case "$staged_module" in
        "${STAGING_ROOT}"/*) ;;
        *)
            log ERROR "Refusing to install non-staged PKCS#11 module path: $1"
            exit 2
            ;;
    esac

    if [ ! -f "$staged_module" ]; then
        log ERROR "Staged PKCS#11 module file is missing: $staged_module"
        exit 2
    fi
fi

if [ "$install_config" -eq 1 ]; then
    case "$staged_config" in
        "${STAGING_ROOT}"/*) ;;
        *)
            log ERROR "Refusing to install non-staged PKCS#11 provider config path."
            exit 7
            ;;
    esac

    if [ ! -f "$staged_config" ]; then
        log ERROR "Staged PKCS#11 provider config file is missing: $staged_config"
        exit 7
    fi
fi

if [ "$use_installed_pin" -eq 1 ]; then
    if [ ! -f "$PIN_FILE_PATH" ]; then
        log ERROR "Existing protected PKCS#11 user PIN file is missing: $PIN_FILE_PATH"
        exit 3
    fi
else
    case "$staged_pin" in
        "${STAGING_ROOT}"/*) ;;
        *)
            log ERROR "Refusing to install non-staged PKCS#11 PIN path."
            exit 3
            ;;
    esac

    if [ ! -f "$staged_pin" ]; then
        log ERROR "Staged PKCS#11 PIN file is missing: $staged_pin"
        exit 3
    fi
fi

log INFO "Installing PKCS#11 assets into the protected HSM area."

snapshot_dir="$(mktemp -d)"
tmp_module=""
tmp_pin=""
tmp_config=""
tmp_module_path=""
# shellcheck disable=SC2329  # invoked by the EXIT trap
cleanup() {
    rm -rf -- "$snapshot_dir"
    for path in "$tmp_module" "$tmp_pin" "$tmp_config" "$tmp_module_path"; do
        if [ -n "$path" ]; then
            rm -f -- "$path"
        fi
    done
}
trap cleanup EXIT
snapshot_helper="$(dirname "$0")/snapshot_pkcs11_file.py"
if [ "$install_module" -eq 1 ]; then
    python3 -I "$snapshot_helper" "$STAGING_ROOT" "$staged_module" "$snapshot_dir/module"
fi
if [ "$use_installed_pin" -eq 0 ]; then
    python3 -I "$snapshot_helper" "$STAGING_ROOT" "$staged_pin" "$snapshot_dir/pin"
fi
if [ "$install_config" -eq 1 ]; then
    python3 -I "$snapshot_helper" "$STAGING_ROOT" "$staged_config" "$snapshot_dir/config"
fi

install -o root -g www-data -m 0750 -d "$HSM_CONFIG_DIR" "$HSM_LIB_DIR"

# Stage every file next to its final name, then rename. A failure leaves the
# currently installed assets untouched.
if [ "$install_module" -eq 1 ]; then
    tmp_module="${FINAL_MODULE_PATH}.new.$$"
    if ! install -o root -g www-data -m 0640 "$snapshot_dir/module" "$tmp_module"; then
        log ERROR "Failed to stage PKCS#11 module for $FINAL_MODULE_PATH"
        exit 4
    fi
fi

if [ "$use_installed_pin" -eq 0 ]; then
    tmp_pin="${PIN_FILE_PATH}.new.$$"
    if ! install -o root -g www-data -m 0640 "$snapshot_dir/pin" "$tmp_pin"; then
        log ERROR "Failed to stage PKCS#11 user PIN for $PIN_FILE_PATH"
        exit 5
    fi
fi

if [ "$install_config" -eq 1 ]; then
    tmp_config="${FINAL_CONFIG_PATH}.new.$$"
    if ! install -o root -g www-data -m 0640 "$snapshot_dir/config" "$tmp_config"; then
        log ERROR "Failed to stage PKCS#11 provider config for $FINAL_CONFIG_PATH"
        exit 8
    fi
fi

if [ "$install_module" -eq 1 ]; then
    tmp_module_path="${MODULE_PATH_FILE}.new.$$"
    if ! printf '%s\n' "$FINAL_MODULE_PATH" > "$tmp_module_path"; then
        log ERROR "Failed to stage PKCS#11 module path for $MODULE_PATH_FILE"
        exit 6
    fi
    chown root:www-data "$tmp_module_path"
    chmod 0640 "$tmp_module_path"
fi

if [ -n "$tmp_module" ]; then
    mv -f -- "$tmp_module" "$FINAL_MODULE_PATH"
fi
if [ -n "$tmp_pin" ]; then
    mv -f -- "$tmp_pin" "$PIN_FILE_PATH"
fi
if [ -n "$tmp_config" ]; then
    mv -f -- "$tmp_config" "$FINAL_CONFIG_PATH"
fi
if [ -n "$tmp_module_path" ]; then
    mv -f -- "$tmp_module_path" "$MODULE_PATH_FILE"
fi

if [ "$use_installed_pin" -eq 0 ]; then
    python3 -I "$snapshot_helper" --remove "$STAGING_ROOT" "$staged_pin"
fi
if [ "$install_module" -eq 1 ]; then
    python3 -I "$snapshot_helper" --remove "$STAGING_ROOT" "$staged_module"
fi
if [ "$install_config" -eq 1 ]; then
    python3 -I "$snapshot_helper" --remove "$STAGING_ROOT" "$staged_config"
fi

log INFO "PKCS#11 assets installed successfully."
exit 0
