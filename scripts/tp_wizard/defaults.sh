# -------------------------- Constants & defaults ------------------------------
PROJECT="trustpoint"
NET="${PROJECT}-net"
VOL_DB="${PROJECT}_postgres_data"
VOL_GRAFANA="${PROJECT}_grafana_data"
ENV_FILE="${ENV_FILE:-${PWD}/.env}"
TP_WIZARD_ENV_FILE="${TP_WIZARD_ENV_FILE:-${PWD}/.env.tp_wizard}"
TP_WIZARD_WRITE_PROJECT_ENV="${TP_WIZARD_WRITE_PROJECT_ENV:-false}"

# Load the repository .env as read-only input so defaults below can inherit
# developer-local configuration. The wizard writes generated values to
# TP_WIZARD_ENV_FILE by default and does not modify .env unless
# TP_WIZARD_WRITE_PROJECT_ENV=true is set explicitly.
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

# Trustpoint auto-setup bypasses the in-app setup wizard. The key is
# configurable for local app changes, but the current app uses TP_AUTO_SETUP.
# Use --skip-setup to set it to true for CLI/demo runs.
TRUSTPOINT_SKIP_SETUP_ENV_KEY="${TRUSTPOINT_SKIP_SETUP_ENV_KEY:-TP_AUTO_SETUP}"
TRUSTPOINT_SKIP_SETUP_ENV_KEYS="${TRUSTPOINT_SKIP_SETUP_ENV_KEYS:-$TRUSTPOINT_SKIP_SETUP_ENV_KEY}"
TRUSTPOINT_SKIP_SETUP_ENV_VALUE="${TRUSTPOINT_SKIP_SETUP_ENV_VALUE:-false}"
if [[ -v "$TRUSTPOINT_SKIP_SETUP_ENV_KEY" ]]; then
  DEF_TRUSTPOINT_SKIP_SETUP_VALUE="${!TRUSTPOINT_SKIP_SETUP_ENV_KEY}"
else
  DEF_TRUSTPOINT_SKIP_SETUP_VALUE="$TRUSTPOINT_SKIP_SETUP_ENV_VALUE"
fi
DEF_TP_ADMIN_USERNAME="${TP_ADMIN_USERNAME:-admin}"
DEF_TP_ADMIN_PASSWORD="${TP_ADMIN_PASSWORD:-testing321}"
DEF_TP_ADMIN_EMAIL="${TP_ADMIN_EMAIL:-admin@trustpoint.local}"
DEF_TP_INJECT_DEMO_DATA="${TP_INJECT_DEMO_DATA:-true}"

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

# Wizard-generated observability config. Keep this separate from the repository's
# prometheus/prometheus.yml so existing project config is not overwritten.
TP_WIZARD_GENERATED_ROOT="${TP_WIZARD_GENERATED_ROOT:-${PWD}/.tp_wizard}"
PROMETHEUS_CONFIG="${PROMETHEUS_CONFIG:-${TP_WIZARD_GENERATED_ROOT}/prometheus/prometheus.yml}"
TRUSTPOINT_METRICS_SCHEME="${TRUSTPOINT_METRICS_SCHEME:-http}"
TRUSTPOINT_METRICS_TARGET="${TRUSTPOINT_METRICS_TARGET:-trustpoint:80}"
TRUSTPOINT_METRICS_PATH="${TRUSTPOINT_METRICS_PATH:-/prometheus/metrics}"
GRAFANA_PROVISIONING_ROOT="${TP_WIZARD_GENERATED_ROOT}/grafana/provisioning"
GRAFANA_DATASOURCES_DIR="${GRAFANA_PROVISIONING_ROOT}/datasources"
GRAFANA_DASHBOARD_PROVIDERS_DIR="${GRAFANA_PROVISIONING_ROOT}/dashboards"
GRAFANA_DASHBOARDS_DIR="${TP_WIZARD_GENERATED_ROOT}/grafana/dashboards"

# Timeouts
READINESS_TIMEOUT=90
TLS_FP_TIMEOUT=150

# Optional backup user provisioning
SFTPGO_BACKUP_USER="tpbackup"
SFTPGO_BACKUP_PASS="testing321"
SFTPGO_BACKUP_HOME=""
