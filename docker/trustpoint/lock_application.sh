#!/bin/bash
# Build-time only: protect installed code and dependencies from the web account.
set -euo pipefail

APP_DIR=/var/www/html/trustpoint

chown -Rh root:root "$APP_DIR"
chmod -R a+rX,go-w "$APP_DIR"

# These data directories have root-owned parents so www-data cannot replace
# source trees, dependency directories, or build configuration alongside them.
for directory in \
    "$APP_DIR/trustpoint/media" \
    "$APP_DIR/trustpoint/collected_static" \
    "$APP_DIR/docker/trustpoint/nginx/tls" \
    "$APP_DIR/docs/build"
do
    mkdir -p "$directory"
    chown -R www-data:www-data "$directory"
    chmod 750 "$directory"
done
