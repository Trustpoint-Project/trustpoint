# -------------------------- Constants & defaults ------------------------------
PROJECT="trustpoint"
NET="${PROJECT}-net"
VOL_DB="${PROJECT}_postgres_data"
VOL_GRAFANA="${PROJECT}_grafana_data"
ENV_FILE="${ENV_FILE:-${PWD}/.env}"

# Load .env early so defaults below can inherit repository-local configuration.
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

# trustpoint image handling
TP_DOCKERFILE="docker/trustpoint/Dockerfile"
TP_REPO="trustpointproject/trustpoint"
APP_IMAGE="${TP_REPO}:latest"   # overridden to trustpoint:local when BUILD_LOCAL=true
BUILD_LOCAL=false

# Fixed images
PG_IMAGE="postgres:15.14"
MAILPIT_IMAGE="axllent/mailpit:v1.27"
SFTPGO_IMAGE="drakkan/sftpgo:2.6.x-slim"
PROMETHEUS_IMAGE="prom/prometheus:latest"
GRAFANA_IMAGE="grafana/grafana:latest"
WF2_WORKER_NAME="trustpoint-worker"

# trustpoint host ports. These names match docker-compose.yml.
APP_HTTP_HOST="${TP_HTTP_PORT:-80}"
APP_HTTPS_HOST="${TP_HTTPS_PORT:-443}"

# PostgreSQL defaults. These names match docker-compose.yml and .env.
DEF_DB_NAME="${POSTGRES_DB:-trustpoint_db}"
DEF_DB_USER="${DATABASE_USER:-admin}"
DEF_DB_PASS="${DATABASE_PASSWORD:-testing321}"
DEF_DB_PORT="${DATABASE_PORT:-5432}"
DEF_DB_HOST="${DATABASE_HOST:-postgres}"
DEF_DB_HOST_INTERNAL="postgres"   # container name/hostname

# trustpoint runtime environment.
DEF_TP_TLS_DNS_NAMES="${TP_TLS_DNS_NAMES:-trustpoint.local}"
DEF_TP_TLS_IPV4_ADDRESSES="${TP_TLS_IPV4_ADDRESSES:-}"
DEF_TP_TLS_IPV6_ADDRESSES="${TP_TLS_IPV6_ADDRESSES:-}"

# The setup-skip variable is configurable because the exact application-side
# name can change. The default used by the wizard is TP_SKIP_SETUP=true.
TRUSTPOINT_SKIP_SETUP_ENV_KEY="${TRUSTPOINT_SKIP_SETUP_ENV_KEY:-TP_SKIP_SETUP}"
TRUSTPOINT_SKIP_SETUP_ENV_VALUE="${TRUSTPOINT_SKIP_SETUP_ENV_VALUE:-true}"
if [[ -v "$TRUSTPOINT_SKIP_SETUP_ENV_KEY" ]]; then
  DEF_TRUSTPOINT_SKIP_SETUP_VALUE="${!TRUSTPOINT_SKIP_SETUP_ENV_KEY}"
else
  DEF_TRUSTPOINT_SKIP_SETUP_VALUE="$TRUSTPOINT_SKIP_SETUP_ENV_VALUE"
fi

# Mailpit defaults
DEF_MAILPIT_SMTP_PORT=1025
DEF_MAILPIT_UI_PORT=8025

# SFTPGo defaults
DEF_SFTPGO_SFTP_PORT=2222
DEF_SFTPGO_WEB_PORT=8080
DEF_SFTPGO_ADMIN_USER="admin"
DEF_SFTPGO_ADMIN_PASS="testing321"
SFTPGO_ROOT="${PWD}/sftpgo-data"

# workflows2 worker defaults
WF2_FOLDER="${PWD}/workflow2Folder"
WF2_WORKER_ENV_FILE="${WF2_FOLDER}/worker.env"
WF2_WORKER_README="${WF2_FOLDER}/README.txt"
DEF_WF2_WORKER_LEASE=30
DEF_WF2_WORKER_BATCH=10
DEF_WF2_WORKER_SLEEP=1
MAILPIT_PROBE_TIMEOUT=20

# Monitoring defaults
DEF_PROMETHEUS_PORT=9090
DEF_GRAFANA_PORT=3000
DEF_GRAFANA_ADMIN_USER="admin"
DEF_GRAFANA_ADMIN_PASS="testing321"
PROMETHEUS_CONFIG="${PWD}/prometheus/prometheus.yml"
GRAFANA_PROVISIONING_ROOT="${PWD}/grafana-provisioning"
GRAFANA_DATASOURCES_DIR="${GRAFANA_PROVISIONING_ROOT}/datasources"

# Timeouts
READINESS_TIMEOUT=90
TLS_FP_TIMEOUT=150

# Optional backup user provisioning
SFTPGO_BACKUP_USER="tpbackup"
SFTPGO_BACKUP_PASS="testing321"
SFTPGO_BACKUP_HOME=""
