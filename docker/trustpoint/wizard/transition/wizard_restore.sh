#!/usr/bin/env bash
#
# wizard_restore.sh — with clean timestamped logging
#

# 1) Pipe all output (stdout+stderr) into your trustpoint log and to the console
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log
exec > >(tee -a "$LOGFILE") 2>&1

# 2) Exit on any error, and fail on pipe errors
set -eE -o pipefail

# 3) A simple log function matching your other logs
#    Usage: log LEVEL "your message…"
log() {
  local level=$1; shift
  printf '%s - wizard_restore.sh - %s - %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" \
    "$level" \
    "$*"
}

# 4) Trap unexpected errors and log them
trap 'log ERROR "in ${FUNCNAME[0]:-main} at line $LINENO (exit=$?)"; exit 1' ERR

# ————— Paths —————
STATE_DIR="/etc/trustpoint/wizard/state"
WIZARD_INITIAL="$STATE_DIR/WIZARD_INITIAL"
WIZARD_COMPLETED="$STATE_DIR/WIZARD_COMPLETED"
APACHE_TLS_DIR="/etc/trustpoint/tls"

log INFO "STARTING APACHE RESTORE"

# 5) (Re-)create and clean TLS directory
log INFO "Ensuring TLS directory exists: $APACHE_TLS_DIR"
mkdir -p "$APACHE_TLS_DIR"

log INFO "Removing old TLS files from $APACHE_TLS_DIR"
rm -f "$APACHE_TLS_DIR"/*

# 6) Copy new TLS certs
log INFO "Copying new TLS files"
cp /var/www/html/trustpoint/docker/trustpoint/apache/tls/* "$APACHE_TLS_DIR"/

# 7) Remove existing Apache sites
log INFO "Removing enabled Apache sites"
rm -f /etc/apache2/sites-enabled/*

# 8) Install HTTP config
log INFO "Installing HTTP config"
cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-http.conf \
   /etc/apache2/sites-available/
cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-http.conf \
   /etc/apache2/sites-enabled/

# 9) Install HTTPS config
log INFO "Installing HTTPS config"
cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-https.conf \
   /etc/apache2/sites-available/
cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-https.conf \
   /etc/apache2/sites-enabled/

# 10) Enable Apache modules
log INFO "Enabling Apache modules: ssl & rewrite"
a2enmod ssl
a2enmod rewrite

# 11) Restart Apache gracefully
log INFO "Restarting Apache (graceful)"
apache2ctl graceful

log INFO "RESTORE SCRIPT COMPLETED SUCCESSFULLY"
exit 0
