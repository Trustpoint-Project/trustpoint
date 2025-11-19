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
  message="$(printf '%s - configure_apache.sh - %s - %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*")"
  echo "$message" | tee -a "$LOGFILE" # >> "$LOGFILE" # 
}

# 3) Makes sure no other sites are enabled within the apache2
log INFO "Removing standard enabled Apache sites"
if ! rm -f /etc/apache2/sites-enabled/*
then
    log "ERROR: Failed to remove existing Apache sites from /etc/apache2/sites-enabled."
    exit 6
fi
rm -f /etc/apache2/sites-enabled/*

# 4) Install HTTP config
log INFO "Installing HTTP config..."
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-http.conf /etc/apache2/sites-available/trustpoint-apache-http.conf
then
    log "ERROR: Failed to copy trustpoint-apache-http.conf to /etc/apache2/sites-available."
    exit 7
fi
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-http.conf /etc/apache2/sites-enabled/trustpoint-apache-http.conf
then
    log "ERROR: Failed to copy trustpoint-apache-http.conf to /etc/apache2/sites-enabled."
    exit 8
fi

# 5) Install HTTPS config
log INFO "Installing HTTPS config..."
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-https.conf /etc/apache2/sites-available/trustpoint-apache-https.conf
then
    log "ERROR: Failed to copy trustpoint-apache-https.conf to /etc/apache2/sites-available."
    exit 9
fi
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-https.conf /etc/apache2/sites-enabled/trustpoint-apache-https.conf
then
    log "ERROR: Failed to copy trustpoint-apache-https.conf to /etc/apache2/sites-enabled."
    exit 10
fi

# 6) Enable Apache modules
log INFO "Enabling Apache modules: ssl & rewrite"
if ! output=$(a2enmod ssl 2>/dev/null); then
    log "ERROR: Failed to enable Apache mod_ssl."
    exit 11
fi

if ! output=$(a2enmod rewrite 2>/dev/null); then
    log "ERROR: Failed to enable Apache mod_rewrite."
    exit 12
fi