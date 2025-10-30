#!/bin/bash
# 1) Pipe all output (stdout+stderr) into your trustpoint log and to the console
APACHE_TLS_DIRECTORY="/etc/trustpoint/tls/"
LOGFILE=/var/www/html/trustpoint/trustpoint/media/log/trustpoint.log

# 2) Exit on any error, and fail on pipe errors
set -eE -o pipefail

# 3) A simple log function matching your other logs
#    Usage: log LEVEL "your message…"
log() {
  local level=$1; shift
  local message
  message="$(printf '%s - update_tls.sh - %s - %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
  echo "$message" | tee -a "$LOGFILE" # >> "$LOGFILE" 
}

# 1) (Re-)create and clean TLS directory
log INFO "Ensuring TLS directory exists: $APACHE_TLS_DIRECTORY"
if ! mkdir -p "$APACHE_TLS_DIRECTORY"
then
    log "ERROR: Failed to create the required TLS directory at $APACHE_TLS_DIRECTORY."
    exit 3
fi

# Makes sure the apache2 tls directory does not contain any files or directories.
log INFO "Removing may exisiting old TLS files from $APACHE_TLS_DIRECTORY"
if ! rm -f /etc/trustpoint/tls/*
then
    log "ERROR: Failed to clear existing files in $APACHE_TLS_DIRECTORY."
    exit 4
fi

# 2) Move new TLS certs
log INFO "Move TLS Server credentials into $APACHE_TLS_DIRECTORY"

# Copies the TLS-Server credentials into the apache2 TLS directory.
if ! mv /var/www/html/trustpoint/docker/trustpoint/apache/tls/* "$APACHE_TLS_DIRECTORY"
then
    log "ERROR: Failed to copy Trustpoint TLS files to $APACHE_TLS_DIRECTORY."
    exit 5
fi


# If Apache is running try to gracefully restart and reload the apache2 webserver.
if pgrep apache2 >/dev/null; then
   log INFO "Restarting Apache (graceful)"
   if ! apache2ctl graceful
     then
         log "ERROR: Failed to gracefully restart Apache."
         exit 13
     fi
fi
