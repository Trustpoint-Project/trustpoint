#!/usr/bin/env bash

start_sftpgo() {
  mkdir -p "$SFTPGO_ROOT"
  remove_container sftpgo
  start_container sftpgo -p "${SFTPGO_SFTP_PORT}:2022" -p "${SFTPGO_WEB_PORT}:8080" \
    -v "$SFTPGO_ROOT:/srv/sftpgo" -e SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=true \
    -e SFTPGO_DEFAULT_ADMIN_USERNAME="$SFTPGO_ADMIN_USER" \
    -e SFTPGO_DEFAULT_ADMIN_PASSWORD="$SFTPGO_ADMIN_PASSWORD" "$SFTPGO_IMAGE"
  ok 'SFTPGo started'
}
