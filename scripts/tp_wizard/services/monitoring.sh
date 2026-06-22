monitoring_prompt_config(){
  EN_PROMETHEUS=$(ask_yes_no "Enable Prometheus metrics stack?" "n" && echo true || echo false)
  if $EN_PROMETHEUS; then
    PROMETHEUS_PORT="$(ask_free_port 'Prometheus host port' "$PROMETHEUS_PORT")"
    ask "Prometheus config file" "$PROMETHEUS_CONFIG"
    PROMETHEUS_CONFIG="$REPLY"
  fi

  EN_GRAFANA=$(ask_yes_no "Enable Grafana dashboard UI?" "n" && echo true || echo false)
  if $EN_GRAFANA; then
    GRAFANA_PORT="$(ask_free_port 'Grafana host port' "$GRAFANA_PORT")"
    GRAFANA_ADMIN_USER="$(ask_user 'Grafana admin user' "$GRAFANA_ADMIN_USER")"
    GRAFANA_ADMIN_PASS="$(ask_password 'Grafana admin password' "$GRAFANA_ADMIN_PASS")"
  fi
}

ensure_prometheus_config(){
  mkdir -p "$(dirname "$PROMETHEUS_CONFIG")"

  if [[ -f "$PROMETHEUS_CONFIG" ]]; then
    return 0
  fi

  cat > "$PROMETHEUS_CONFIG" <<'EOF2'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: trustpoint
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ["trustpoint:80"]
EOF2

  warn "Created default Prometheus config at ${PROMETHEUS_CONFIG}. Adjust the trustpoint metrics path/port there if needed."
}

prepare_grafana_provisioning(){
  mkdir -p "$GRAFANA_DATASOURCES_DIR"

  cat > "${GRAFANA_DATASOURCES_DIR}/prometheus.yml" <<'EOF2'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF2
}

start_prometheus(){
  $EN_PROMETHEUS || return 0

  local name="prometheus"
  stop_one "$name"

  if port_in_use "$PROMETHEUS_PORT"; then
    die "Host port ${PROMETHEUS_PORT} is in use (Prometheus)."
  fi

  ensure_prometheus_config

  log "Starting Prometheus..."
  docker run -d --name "$name" --network "$NET" \
    -p "${PROMETHEUS_PORT}:9090" \
    -v "${PROMETHEUS_CONFIG}:/etc/prometheus/prometheus.yml:ro" \
    "$PROMETHEUS_IMAGE" \
    --config.file=/etc/prometheus/prometheus.yml >/dev/null
}

start_grafana(){
  $EN_GRAFANA || return 0

  local name="grafana"
  stop_one "$name"

  if port_in_use "$GRAFANA_PORT"; then
    die "Host port ${GRAFANA_PORT} is in use (Grafana)."
  fi

  ensure_volume "$VOL_GRAFANA"
  prepare_grafana_provisioning

  log "Starting Grafana..."
  docker run -d --name "$name" --network "$NET" \
    -p "${GRAFANA_PORT}:3000" \
    -v "${VOL_GRAFANA}:/var/lib/grafana" \
    -v "${GRAFANA_PROVISIONING_ROOT}:/etc/grafana/provisioning:ro" \
    -e "GF_SECURITY_ADMIN_USER=${GRAFANA_ADMIN_USER}" \
    -e "GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASS}" \
    "$GRAFANA_IMAGE" >/dev/null
}

await_monitoring_ready(){
  if $EN_PROMETHEUS; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for Prometheus on localhost:${PROMETHEUS_PORT} ..."
    local prometheus_deadline=$(( $(date +%s) + READINESS_TIMEOUT ))
    while (( $(date +%s) < prometheus_deadline )); do
      if tcp_check 127.0.0.1 "$PROMETHEUS_PORT" 1; then
        ok "Prometheus reachable on :${PROMETHEUS_PORT}"
        break
      fi
      printf "."
      sleep 1
    done
    echo
  fi

  if $EN_GRAFANA; then
    echo "Waiting (<= ${READINESS_TIMEOUT}s) for Grafana on localhost:${GRAFANA_PORT} ..."
    local grafana_deadline=$(( $(date +%s) + READINESS_TIMEOUT ))
    while (( $(date +%s) < grafana_deadline )); do
      if tcp_check 127.0.0.1 "$GRAFANA_PORT" 1; then
        ok "Grafana reachable on :${GRAFANA_PORT}"
        break
      fi
      printf "."
      sleep 1
    done
    echo
  fi
}
