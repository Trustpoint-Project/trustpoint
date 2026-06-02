#!/bin/bash
set -eu

LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
STAGING_ROOT=/tmp/trustpoint-wizard/pkcs11
HSM_ROOT="${TRUSTPOINT_HSM_ROOT:-/var/lib/trustpoint/hsm}"
HSM_CONFIG_DIR="${TRUSTPOINT_HSM_CONFIG_DIR:-${HSM_ROOT}/config}"
HSM_LIB_DIR="${TRUSTPOINT_HSM_LIB_DIR:-${HSM_ROOT}/lib}"
FINAL_MODULE_PATH="${HSM_LIB_DIR}/uploaded-pkcs11-module.so"
PIN_FILE_PATH="${HSM_CONFIG_DIR}/user-pin.txt"
FINAL_CONFIG_PATH="${HSM_CONFIG_DIR}/uploaded-pkcs11-vendor.cfg"
MODULE_PATH_FILE="${HSM_CONFIG_DIR}/pkcs11-module-path.txt"

log() {
    local level=$1
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - install_pkcs11_assets.sh - ${level} - $*" | tee -a "$LOGFILE"
}

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
        log INFO "PKCS#11 vendor config cleared from protected HSM area."
        exit 0
        ;;
esac

if [ "$#" -ne 1 ] && [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
    log ERROR "Expected staged PIN, staged module plus PIN, or staged module plus PIN plus vendor config."
    exit 1
fi

staged_module=""
staged_pin=""
staged_config=""
install_module=0
install_config=0

if [ "$#" -ge 2 ]; then
    staged_module="$(readlink -f "$1" 2>/dev/null || true)"
    staged_pin="$(readlink -f "$2" 2>/dev/null || true)"
    install_module=1
else
    staged_pin="$(readlink -f "$1" 2>/dev/null || true)"
fi

if [ "$#" -eq 3 ]; then
    staged_config="$(readlink -f "$3" 2>/dev/null || true)"
    install_config=1
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
            log ERROR "Refusing to install non-staged PKCS#11 vendor config path."
            exit 7
            ;;
    esac

    if [ ! -f "$staged_config" ]; then
        log ERROR "Staged PKCS#11 vendor config file is missing: $staged_config"
        exit 7
    fi
fi

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

log INFO "Installing PKCS#11 assets into the protected HSM area."

install -o root -g www-data -m 0750 -d "$HSM_CONFIG_DIR" "$HSM_LIB_DIR"

if [ "$install_module" -eq 1 ]; then
    if ! install -o root -g www-data -m 0640 "$staged_module" "$FINAL_MODULE_PATH"; then
        log ERROR "Failed to install PKCS#11 module into $FINAL_MODULE_PATH"
        exit 4
    fi
fi

if ! install -o root -g www-data -m 0640 "$staged_pin" "$PIN_FILE_PATH"; then
    log ERROR "Failed to install PKCS#11 user PIN file into $PIN_FILE_PATH"
    exit 5
fi

if [ "$install_config" -eq 1 ]; then
    if ! install -o root -g www-data -m 0640 "$staged_config" "$FINAL_CONFIG_PATH"; then
        log ERROR "Failed to install PKCS#11 vendor config into $FINAL_CONFIG_PATH"
        exit 8
    fi
fi

if [ "$install_module" -eq 1 ]; then
    tmp_module_path_file="$(mktemp)"
    printf '%s\n' "$FINAL_MODULE_PATH" > "$tmp_module_path_file"
    if ! install -o root -g www-data -m 0640 "$tmp_module_path_file" "$MODULE_PATH_FILE"; then
        rm -f "$tmp_module_path_file"
        log ERROR "Failed to persist PKCS#11 module path into $MODULE_PATH_FILE"
        exit 6
    fi
    rm -f "$tmp_module_path_file"
fi

rm -f "$staged_pin"
if [ "$install_module" -eq 1 ]; then
    rm -f "$staged_module"
fi
if [ "$install_config" -eq 1 ]; then
    rm -f "$staged_config"
fi

log INFO "PKCS#11 assets installed successfully."
exit 0
