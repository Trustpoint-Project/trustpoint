#!/bin/bash
set -e

# 0. Quit if started with Docker Desktop (mDNS only supported in Linux deployment)
IS_DOCKER_DESKTOP=false

if uname -r | grep -qiE "linuxkit|microsoft"; then
    IS_DOCKER_DESKTOP=true
fi

if getent hosts host.docker.internal > /dev/null 2>&1; then
    IS_DOCKER_DESKTOP=true
fi

if [ -d /run/host-services ] || [ -f /run/desktop-build-entrypoint.sh ]; then
    IS_DOCKER_DESKTOP=true
fi
if [ "$IS_DOCKER_DESKTOP" = true ]; then
    echo '[WARN] Docker Desktop detected. mDNS advertising is not supported. Exiting...';
    exit 0;
fi;

# 1. Identify the primary LAN IP
# We use 1.1.1.1 as a target to find the interface that actually has a route out.
AUTO_IP=$(ip route get 1.1.1.1 | grep -o 'src [0-9\.]*' | cut -d' ' -f2)

if [ -z "$AUTO_IP" ]; then
    # 1st Fallback: Default gateway (offline deployment)
    echo "[WARN] Could not detect Host IP. Using fallback gateway detection."
    GATEWAY_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

    # 2nd Fallback: If no default gateway exists (e.g., isolated switch), 
    # just take the first non-loopback interface with an IP.
    if [ -z "$GATEWAY_IFACE" ]; then
        echo "[WARN] No default gateway found. Picking first available LAN interface..."
        GATEWAY_IFACE=$(ip -4 route show scope global | awk '{print $3}' | head -n1)
    fi

    # 3. Extract the actual IP from that interface
    AUTO_IP=$(ip -4 addr show "$GATEWAY_IFACE" | awk '/inet / {split($2, address, "/"); print address[1]; exit}')

    if [ -z "$AUTO_IP" ]; then
        echo "[ERROR] Could not detect any LAN IP. Check physical connection."
        exit 1
    fi
fi

echo "[INFO] Detected Host IP: $AUTO_IP"

# Run a private D-Bus and Avahi; host sockets are not mounted.
pids=()
cleanup() {
    kill "${pids[@]}" 2>/dev/null || true
    wait || true
}
trap cleanup EXIT
trap 'exit 0' INT TERM

wait_for_service() {
    local pid=$1 service=$2
    local deadline=$((SECONDS + 10))
    while (( SECONDS < deadline )); do
        kill -0 "$pid" 2>/dev/null || return 1
        if dbus-send --system --print-reply --reply-timeout=1000 \
            --dest=org.freedesktop.DBus / org.freedesktop.DBus.NameHasOwner \
            "string:$service" 2>/dev/null | grep -q 'boolean true'; then
            return 0
        fi
        sleep 0.2
    done
    echo "[ERROR] Timed out waiting for $service" >&2
    return 1
}

# A killed container retains socket and PID files in its private filesystem.
rm -f /var/run/dbus/pid /run/dbus/dbus.pid /var/run/dbus/system_bus_socket \
      /var/run/avahi-daemon/pid /var/run/avahi-daemon/socket
dbus-uuidgen --ensure
dbus-daemon --system --nofork --nopidfile &
pids+=("$!")
wait_for_service "$!" org.freedesktop.DBus

avahi-daemon --no-chroot --no-proc-title &
pids+=("$!")
wait_for_service "$!" org.freedesktop.Avahi

echo "[INFO] Publishing address and services -> $AUTO_IP"
avahi-publish -a -R trustpoint.local "$AUTO_IP" &
pids+=("$!")
avahi-publish -s -H trustpoint.local 'Trustpoint Web Interface' _https._tcp 443 &
pids+=("$!")
avahi-publish -s -H trustpoint.local 'Trustpoint' _trustpoint._tcp 443 &
pids+=("$!")
avahi-publish -s -H trustpoint.local 'AOKI Owner Service' _aoki._tcp 443 &
pids+=("$!")

echo "[INFO] mDNS services published. Container is running."
while true; do
    for pid in "${pids[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[ERROR] Advertising service $pid exited." >&2
            exit 1
        fi
    done
    sleep 1
done
