# -------------------------- Constants & defaults ------------------------------
PROJECT="trustpoint"
NET="${PROJECT}-net"
VOL_DB="${PROJECT}_postgres_data"

# trustpoint image handling
TP_DOCKERFILE="docker/trustpoint/Dockerfile"
TP_REPO="trustpointproject/trustpoint"
APP_IMAGE="${TP_REPO}:latest"   # overridden to trustpoint:local when BUILD_LOCAL=true
BUILD_LOCAL=false

# Fixed images
PG_IMAGE="postgres:15.14"
MAILPIT_IMAGE="axllent/mailpit:v1.27"
SFTPGO_IMAGE="drakkan/sftpgo:2.6.x-slim"
WF2_WORKER_NAME="trustpoint-worker"

# Fixed trustpoint ports
APP_HTTP_HOST=80
APP_HTTPS_HOST=443

# PostgreSQL defaults
DEF_DB_NAME="trustpoint_db"
DEF_DB_USER="admin"
DEF_DB_PASS="testing321"
DEF_DB_PORT=5432
DEF_DB_HOST_INTERNAL="postgres"   # container name/hostname

# Mailpit defaults
DEF_MAILPIT_SMTP_PORT=1025
DEF_MAILPIT_UI_PORT=8025

# SFTPGo defaults
DEF_SFTPGO_SFTP_PORT=2222
DEF_SFTPGO_WEB_PORT=8080
DEF_SFTPGO_ADMIN_USER="admin"
DEF_SFTPGO_ADMIN_PASS="testing321"
SFTPGO_ROOT="${PWD}/sftpgo-data"
WF2_FOLDER="${PWD}/workflow2Folder"
WF2_WORKER_ENV_FILE="${WF2_FOLDER}/worker.env"
WF2_WORKER_README="${WF2_FOLDER}/README.txt"
DEF_WF2_WORKER_LEASE=30
DEF_WF2_WORKER_BATCH=10
DEF_WF2_WORKER_SLEEP=1
MAILPIT_PROBE_TIMEOUT=20

# Timeouts
READINESS_TIMEOUT=90
TLS_FP_TIMEOUT=150

# Optional backup user provisioning
SFTPGO_BACKUP_USER="tpbackup"
SFTPGO_BACKUP_PASS="testing321"
SFTPGO_BACKUP_HOME=""
