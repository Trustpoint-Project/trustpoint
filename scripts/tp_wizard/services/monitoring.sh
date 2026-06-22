monitoring_prompt_config(){
  EN_PROMETHEUS=$(ask_yes_no "Enable Prometheus metrics stack?" "n" && echo true || echo false)
  if $EN_PROMETHEUS; then
    PROMETHEUS_PORT="$(ask_free_port 'Prometheus host port' "$PROMETHEUS_PORT")"
    ask "Trustpoint metrics scheme" "$TRUSTPOINT_METRICS_SCHEME_VALUE"
    TRUSTPOINT_METRICS_SCHEME_VALUE="$REPLY"
    ask "Trustpoint metrics target from Prometheus container" "$TRUSTPOINT_METRICS_TARGET_VALUE"
    TRUSTPOINT_METRICS_TARGET_VALUE="$REPLY"
    ask "Trustpoint metrics path" "$TRUSTPOINT_METRICS_PATH_VALUE"
    TRUSTPOINT_METRICS_PATH_VALUE="$REPLY"
    ask "Prometheus generated config file" "$PROMETHEUS_CONFIG"
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

  cat > "$PROMETHEUS_CONFIG" <<EOF2
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: trustpoint
    metrics_path: ${TRUSTPOINT_METRICS_PATH_VALUE}
    scheme: ${TRUSTPOINT_METRICS_SCHEME_VALUE}
    static_configs:
      - targets: ["${TRUSTPOINT_METRICS_TARGET_VALUE}"]
EOF2

  ok "Generated Prometheus config at ${PROMETHEUS_CONFIG}"
}

prepare_grafana_datasource(){
  mkdir -p "$GRAFANA_DATASOURCES_DIR"

  cat > "${GRAFANA_DATASOURCES_DIR}/prometheus.yml" <<'EOF2'
apiVersion: 1

datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF2
}

prepare_grafana_dashboard_provider(){
  mkdir -p "$GRAFANA_DASHBOARD_PROVIDERS_DIR" "$GRAFANA_DASHBOARDS_DIR"

  cat > "${GRAFANA_DASHBOARD_PROVIDERS_DIR}/trustpoint.yml" <<'EOF2'
apiVersion: 1

providers:
  - name: trustpoint
    orgId: 1
    folder: Trustpoint
    type: file
    disableDeletion: false
    allowUiUpdates: true
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
EOF2
}

prepare_grafana_trustpoint_dashboard(){
  mkdir -p "$GRAFANA_DASHBOARDS_DIR"

  cat > "${GRAFANA_DASHBOARDS_DIR}/trustpoint-overview.json" <<'EOF2'
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": {
          "type": "grafana",
          "uid": "-- Grafana --"
        },
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "target": {
          "limit": 100,
          "matchAny": false,
          "tags": [],
          "type": "dashboard"
        },
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "red",
                "value": null
              },
              {
                "color": "green",
                "value": 1
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 6,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "textMode": "auto",
        "wideLayout": true
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "up{job=\"trustpoint\"}",
          "legendFormat": "trustpoint",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Trustpoint scrape status",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisBorderShow": false,
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "insertNulls": false,
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "s"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 9,
        "x": 6,
        "y": 0
      },
      "id": 2,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "scrape_duration_seconds{job=\"trustpoint\"}",
          "legendFormat": "scrape duration",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Scrape duration",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisBorderShow": false,
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "insertNulls": false,
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 9,
        "x": 15,
        "y": 0
      },
      "id": 3,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "scrape_samples_scraped{job=\"trustpoint\"}",
          "legendFormat": "samples scraped",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Samples scraped",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisBorderShow": false,
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "legend": false,
              "tooltip": false,
              "viz": false
            },
            "insertNulls": false,
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": false,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 8
      },
      "id": 4,
      "options": {
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "single",
          "sort": "none"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "scrape_series_added{job=\"trustpoint\"}",
          "legendFormat": "series added",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "New series per scrape",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "fieldConfig": {
        "defaults": {},
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 8
      },
      "id": 5,
      "options": {
        "cellHeight": "sm",
        "footer": {
          "countRows": false,
          "fields": "",
          "reducer": [
            "sum"
          ],
          "show": false
        },
        "showHeader": true
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "count by (__name__)({job=\"trustpoint\"})",
          "format": "table",
          "instant": true,
          "legendFormat": "{{__name__}}",
          "range": false,
          "refId": "A"
        }
      ],
      "title": "Exported metric names",
      "type": "table"
    }
  ],
  "refresh": "10s",
  "schemaVersion": 39,
  "tags": [
    "trustpoint",
    "tp_wizard"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-15m",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "browser",
  "title": "Trustpoint Overview",
  "uid": "trustpoint-overview",
  "version": 1,
  "weekStart": ""
}
EOF2
}

prepare_grafana_provisioning(){
  prepare_grafana_datasource
  prepare_grafana_dashboard_provider
  prepare_grafana_trustpoint_dashboard
  ok "Generated Grafana datasource and dashboard provisioning under ${TP_WIZARD_GENERATED_ROOT}/grafana"
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
    -v "${GRAFANA_DASHBOARDS_DIR}:/var/lib/grafana/dashboards:ro" \
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
