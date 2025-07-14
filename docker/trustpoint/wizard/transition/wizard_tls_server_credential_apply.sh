#!/bin/bash
# This script will transition the from the WIZARD_INITIAL state to the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state.

STATE_FILE_DIR="/etc/trustpoint/wizard/state/"
APACHE_TLS_DIRECTORY="/etc/trustpoint/tls/"
WIZARD_TLS_SERVER_CREDENTIAL_APPLY="/etc/trustpoint/wizard/state/WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
WIZARD_DEMO_DATA="/etc/trustpoint/wizard/state/WIZARD_DEMO_DATA"

# Checks if the state file is present.
if [ ! -f "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY" ]; then
    echo "ERROR: Trustpoint is not in the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state. State file not found."
    exit 1
fi

# Checks consistency, that is if only a single state file is present.
# TODO(AlexHx8472): Replace ls by find: SC2012
STATE_COUNT=$(ls -1 -A "$STATE_FILE_DIR" | wc -l)
if [[ 1 -ne STATE_COUNT ]]; then
    echo "ERROR: Found $STATE_COUNT state files in $STATE_FILE_DIR. Wizard state seems to be corrupted."
    exit 2
fi

# Makes sure the apache2 directory exists.
if ! mkdir -p "$APACHE_TLS_DIRECTORY"
then
    echo "ERROR: Failed to create the required TLS directory at $APACHE_TLS_DIRECTORY."
    exit 3
fi

# Makes sure the apache2 tls directory does not contain any files or directories.
if ! rm -f /etc/trustpoint/tls/*
then
    echo "ERROR: Failed to clear existing files in $APACHE_TLS_DIRECTORY."
    exit 4
fi

# Copies the TLS-Server credentials into the apache2 TLS directory.
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/tls/* "$APACHE_TLS_DIRECTORY"
then
    echo "ERROR: Failed to copy Trustpoint TLS files to $APACHE_TLS_DIRECTORY."
    exit 5
fi

# Makes sure no other sites are enabled within the apache2
if ! rm -f /etc/apache2/sites-enabled/*
then
    echo "ERROR: Failed to remove existing Apache sites from /etc/apache2/sites-enabled."
    exit 6
fi

# Copies the apache http (80) config into site-available.
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-http.conf /etc/apache2/sites-available/trustpoint-apache-http.conf
then
    echo "ERROR: Failed to copy trustpoint-apache-http.conf to /etc/apache2/sites-available."
    exit 7
fi

# Copies the apache http (80) config into site-enabled.
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-http.conf /etc/apache2/sites-enabled/trustpoint-apache-http.conf
then
    echo "ERROR: Failed to copy trustpoint-apache-http.conf to /etc/apache2/sites-enabled."
    exit 8
fi

# Copies the apache https (443) config into site-available.
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-https.conf /etc/apache2/sites-available/trustpoint-apache-https.conf
then
    echo "ERROR: Failed to copy trustpoint-apache-https.conf to /etc/apache2/sites-available."
    exit 9
fi

# Copies the apache https (443) config into site-enabled.
if ! cp /var/www/html/trustpoint/docker/trustpoint/apache/trustpoint-apache-https.conf /etc/apache2/sites-enabled/trustpoint-apache-https.conf
then
    echo "ERROR: Failed to copy trustpoint-apache-https.conf to /etc/apache2/sites-enabled."
    exit 10
fi

if ! a2enmod ssl
then
    echo "ERROR: Failed to enable Apache mod_ssl."
    exit 11
fi

if ! a2enmod rewrite
then
    echo "ERROR: Failed to enable Apache mod_rewrite."
    exit 12
fi

# Tries to gracefully restart and reload the apache2 webserver.
if ! apache2ctl graceful
then
    echo "ERROR: Failed to gracefully restart Apache."
    exit 13
fi

# Removes the current WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file.
if ! rm "$WIZARD_TLS_SERVER_CREDENTIAL_APPLY"
then
    echo "ERROR: Failed to remove the WIZARD_TLS_SERVER_CREDENTIAL_APPLY state file."
    exit 14
fi

# Creates the WIZARD_DEMO_DATA state file.
if ! touch "$WIZARD_DEMO_DATA"
then
    echo "ERROR: Failed to create the WIZARD_DEMO_DATA state file."
    exit 15
fi

log "Transition from WIZARD_TLS_SERVER_CREDENTIAL_APPLY to WIZARD_DEMO_DATA completed successfully."
exit 0
