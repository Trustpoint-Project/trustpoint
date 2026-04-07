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
    AUTO_IP=$(ip -4 addr show "$GATEWAY_IFACE" | grep -oP 'inet \K[\d.]+')

    if [ -z "$AUTO_IP" ]; then
        echo "[ERROR] Could not detect any LAN IP. Check physical connection."
        exit 1
    fi
fi

echo "[INFO] Detected Host IP: $AUTO_IP"

# 2. Handle the Avahi/D-Bus Stack
if [ -S /var/run/avahi-daemon/socket ]; then
    echo "[INFO] Found existing Avahi socket on host. Using host daemon."
else
    echo "[INFO] No host Avahi found. Starting internal D-Bus and Avahi..."

    # Ensure D-Bus is ready
    rm -f /var/run/dbus/pid
    rm -f /run/dbus/dbus.pid
    dbus-uuidgen --ensure
    #dbus-daemon --system --fork
    dbus-daemon --system --fork --nopidfile --print-address

    # Wait for the socket to actually appear
    until [ -S /var/run/dbus/system_bus_socket ]; do
        echo "[INFO] Waiting for D-Bus socket..."
        sleep 0.5
    done

    # Start Avahi in the background
    #avahi-daemon -D --no-chroot
    echo "[INFO] Starting Avahi-daemon..."
    avahi-daemon --no-chroot --no-proc-title

    until [ -S /var/run/avahi-daemon/socket ]; do
        echo "[INFO] Waiting for Avahi socket..."
        sleep 0.5
    done
fi

# 3. Launch Advertisements
# We use & to background them so we can track them all
echo "[INFO] Publishing address and services -> $AUTO_IP"

avahi-publish -a -R trustpoint.local "$AUTO_IP" &

avahi-publish -s 'Trustpoint Web Interface' _https._tcp 443 &
avahi-publish -s 'Trustpoint' _trustpoint._tcp 443 &
avahi-publish -s 'AOKI Owner Service' _aoki._tcp 443 &

echo "[INFO] mDNS services published. Container is running."

wait -n
