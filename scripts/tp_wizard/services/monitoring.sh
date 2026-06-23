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
EOF2

  if [[ "$TRUSTPOINT_METRICS_SCHEME_VALUE" == "https" && "$TRUSTPOINT_METRICS_TLS_INSECURE_SKIP_VERIFY_VALUE" == "true" ]]; then
    cat >> "$PROMETHEUS_CONFIG" <<'EOF2'
    tls_config:
      insecure_skip_verify: true
EOF2
  fi

  cat >> "$PROMETHEUS_CONFIG" <<EOF2
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
  "graphTooltip": 1,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Prometheus scrape health for the Trustpoint target.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [
            {
              "options": {
                "0": {
                  "color": "red",
                  "text": "DOWN"
                },
                "1": {
                  "color": "green",
                  "text": "UP"
                }
              },
              "type": "value"
            }
          ],
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
        "h": 4,
        "w": 4,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "colorMode": "background",
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
          "expr": "min(up{job=\"trustpoint\"})",
          "legendFormat": "trustpoint",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Trustpoint availability",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Application request throughput, excluding Prometheus scraping of the metrics endpoint.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "decimals": 2,
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
          "unit": "reqps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 5,
        "x": 4,
        "y": 0
      },
      "id": 2,
      "options": {
        "colorMode": "background",
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
          "expr": "sum(rate(django_http_requests_total_by_view_transport_method_total{job=\"trustpoint\",view!=\"prometheus-metrics\"}[$__rate_interval])) or vector(0)",
          "legendFormat": "requests/s",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Request rate",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Ratio of HTTP 4xx and 5xx responses over all HTTP responses.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "decimals": 2,
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.01
              },
              {
                "color": "red",
                "value": 0.05
              }
            ]
          },
          "unit": "percentunit"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 5,
        "x": 9,
        "y": 0
      },
      "id": 3,
      "options": {
        "colorMode": "background",
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
          "expr": "(sum(rate(django_http_responses_total_by_status_total{job=\"trustpoint\",status=~\"4..|5..\"}[$__rate_interval])) or vector(0)) / clamp_min((sum(rate(django_http_responses_total_by_status_total{job=\"trustpoint\"}[$__rate_interval])) or vector(0)), 0.001)",
          "legendFormat": "error ratio",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "HTTP error ratio",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "95th percentile request latency including Django middleware.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "decimals": 3,
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.5
              },
              {
                "color": "red",
                "value": 1.5
              }
            ]
          },
          "unit": "s"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 5,
        "x": 14,
        "y": 0
      },
      "id": 4,
      "options": {
        "colorMode": "background",
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
          "expr": "histogram_quantile(0.95, sum by (le) (rate(django_http_requests_latency_including_middlewares_seconds_bucket{job=\"trustpoint\"}[$__rate_interval])))",
          "legendFormat": "p95",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "p95 latency",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Open file descriptors divided by the process file descriptor limit.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "decimals": 2,
          "max": 1,
          "min": 0,
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.7
              },
              {
                "color": "red",
                "value": 0.9
              }
            ]
          },
          "unit": "percentunit"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 5,
        "x": 19,
        "y": 0
      },
      "id": 5,
      "options": {
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showThresholdLabels": false,
        "showThresholdMarkers": true
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "process_open_fds{job=\"trustpoint\"} / process_max_fds{job=\"trustpoint\"}",
          "legendFormat": "fd usage",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "FD usage",
      "type": "gauge"
    },
    {
      "collapsed": false,
      "gridPos": {
        "h": 1,
        "w": 24,
        "x": 0,
        "y": 4
      },
      "id": 100,
      "panels": [],
      "title": "HTTP traffic and latency",
      "type": "row"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Request throughput by Django view and HTTP method.",
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
          "unit": "reqps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 5
      },
      "id": 6,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull",
            "max"
          ],
          "displayMode": "table",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum by (view, method) (rate(django_http_requests_total_by_view_transport_method_total{job=\"trustpoint\",view!=\"prometheus-metrics\"}[$__rate_interval]))",
          "legendFormat": "{{view}} {{method}}",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Requests by view and method",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "HTTP status code rate.",
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
          "unit": "reqps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 6,
        "x": 12,
        "y": 5
      },
      "id": 7,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull",
            "max"
          ],
          "displayMode": "table",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum by (status) (rate(django_http_responses_total_by_status_total{job=\"trustpoint\"}[$__rate_interval]))",
          "legendFormat": "HTTP {{status}}",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Responses by status",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Total responses by status in the selected time range.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
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
        "w": 6,
        "x": 18,
        "y": 5
      },
      "id": 8,
      "options": {
        "displayMode": "gradient",
        "minVizHeight": 10,
        "minVizWidth": 0,
        "orientation": "horizontal",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showUnfilled": true,
        "valueMode": "color"
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum by (status) (increase(django_http_responses_total_by_status_total{job=\"trustpoint\"}[$__range]))",
          "legendFormat": "HTTP {{status}}",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Status code mix",
      "type": "bargauge"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Request latency percentiles and average latency from Django middleware histogram metrics.",
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
        "w": 12,
        "x": 0,
        "y": 13
      },
      "id": 9,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull",
            "max"
          ],
          "displayMode": "table",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "histogram_quantile(0.50, sum by (le) (rate(django_http_requests_latency_including_middlewares_seconds_bucket{job=\"trustpoint\"}[$__rate_interval])))",
          "legendFormat": "p50",
          "range": true,
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "histogram_quantile(0.95, sum by (le) (rate(django_http_requests_latency_including_middlewares_seconds_bucket{job=\"trustpoint\"}[$__rate_interval])))",
          "legendFormat": "p95",
          "range": true,
          "refId": "B"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "histogram_quantile(0.99, sum by (le) (rate(django_http_requests_latency_including_middlewares_seconds_bucket{job=\"trustpoint\"}[$__rate_interval])))",
          "legendFormat": "p99",
          "range": true,
          "refId": "C"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "rate(django_http_requests_latency_including_middlewares_seconds_sum{job=\"trustpoint\"}[$__rate_interval]) / clamp_min(rate(django_http_requests_latency_including_middlewares_seconds_count{job=\"trustpoint\"}[$__rate_interval]), 0.001)",
          "legendFormat": "avg",
          "range": true,
          "refId": "D"
        }
      ],
      "title": "Latency percentiles",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Average view latency over the last five minutes. This helps identify the currently slowest Trustpoint views.",
      "fieldConfig": {
        "defaults": {
          "custom": {
            "align": "auto",
            "cellOptions": {
              "type": "auto"
            },
            "inspect": false
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.5
              },
              {
                "color": "red",
                "value": 1.5
              }
            ]
          },
          "unit": "s"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 13
      },
      "id": 10,
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
          "expr": "topk(10, sum by (view, method) (rate(django_http_requests_latency_seconds_by_view_method_sum{job=\"trustpoint\",view!=\"prometheus-metrics\"}[5m])) / clamp_min(sum by (view, method) (rate(django_http_requests_latency_seconds_by_view_method_count{job=\"trustpoint\",view!=\"prometheus-metrics\"}[5m])), 0.001))",
          "format": "table",
          "instant": true,
          "legendFormat": "{{view}} {{method}}",
          "range": false,
          "refId": "A"
        }
      ],
      "title": "Slowest views now",
      "type": "table"
    },
    {
      "collapsed": false,
      "gridPos": {
        "h": 1,
        "w": 24,
        "x": 0,
        "y": 21
      },
      "id": 101,
      "panels": [],
      "title": "Runtime health",
      "type": "row"
    },
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
          "decimals": 0,
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
        "h": 4,
        "w": 6,
        "x": 0,
        "y": 22
      },
      "id": 11,
      "options": {
        "colorMode": "background",
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
          "expr": "time() - process_start_time_seconds{job=\"trustpoint\"}",
          "legendFormat": "uptime",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Process uptime",
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
            "mode": "thresholds"
          },
          "decimals": 0,
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
          "unit": "bytes"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 6,
        "y": 22
      },
      "id": 12,
      "options": {
        "colorMode": "background",
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
          "expr": "process_resident_memory_bytes{job=\"trustpoint\"}",
          "legendFormat": "resident memory",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Resident memory",
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
            "mode": "thresholds"
          },
          "decimals": 3,
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 0.7
              },
              {
                "color": "red",
                "value": 1
              }
            ]
          },
          "unit": "cores"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 12,
        "y": 22
      },
      "id": 13,
      "options": {
        "colorMode": "background",
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
          "expr": "rate(process_cpu_seconds_total{job=\"trustpoint\"}[$__rate_interval])",
          "legendFormat": "cpu",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "CPU usage",
      "type": "stat"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Should be zero in a healthy production deployment.",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "decimals": 0,
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 1
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 18,
        "y": 22
      },
      "id": 14,
      "options": {
        "colorMode": "background",
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
          "expr": "sum(django_migrations_unapplied_total{job=\"trustpoint\"}) or vector(0)",
          "legendFormat": "unapplied migrations",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Unapplied migrations",
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
          "unit": "bytes"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 26
      },
      "id": 15,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull",
            "max"
          ],
          "displayMode": "table",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "process_resident_memory_bytes{job=\"trustpoint\"}",
          "legendFormat": "resident memory",
          "range": true,
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "process_virtual_memory_bytes{job=\"trustpoint\"}",
          "legendFormat": "virtual memory",
          "range": true,
          "refId": "B"
        }
      ],
      "title": "Memory usage",
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
        "x": 12,
        "y": 26
      },
      "id": 16,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull",
            "max"
          ],
          "displayMode": "table",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "rate(process_cpu_seconds_total{job=\"trustpoint\"}[$__rate_interval])",
          "legendFormat": "cpu cores",
          "range": true,
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "process_open_fds{job=\"trustpoint\"}",
          "legendFormat": "open fds",
          "range": true,
          "refId": "B"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "process_max_fds{job=\"trustpoint\"}",
          "legendFormat": "max fds",
          "range": true,
          "refId": "C"
        }
      ],
      "title": "CPU and file descriptors",
      "type": "timeseries"
    },
    {
      "collapsed": false,
      "gridPos": {
        "h": 1,
        "w": 24,
        "x": 0,
        "y": 34
      },
      "id": 102,
      "panels": [],
      "title": "Django application details",
      "type": "row"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Django responses by template name. Useful for checking login and rendered pages during demos.",
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
          "unit": "reqps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 7,
        "w": 8,
        "x": 0,
        "y": 35
      },
      "id": 17,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull"
          ],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum by (templatename) (rate(django_http_responses_total_by_templatename_total{job=\"trustpoint\"}[$__rate_interval]))",
          "legendFormat": "{{templatename}}",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Responses by template",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Django exceptions by type. Empty or zero is good.",
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
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 1
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 7,
        "w": 8,
        "x": 8,
        "y": 35
      },
      "id": 18,
      "options": {
        "displayMode": "gradient",
        "minVizHeight": 10,
        "minVizWidth": 0,
        "orientation": "horizontal",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showUnfilled": true,
        "valueMode": "color"
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum by (type) (increase(django_http_exceptions_total_by_type_total{job=\"trustpoint\"}[$__range])) or vector(0)",
          "legendFormat": "{{type}}",
          "range": true,
          "refId": "A"
        }
      ],
      "title": "Exceptions by type",
      "type": "bargauge"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Django model write activity. Empty or zero is expected until the demo creates, updates, or deletes objects.",
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
          "unit": "ops"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 7,
        "w": 8,
        "x": 16,
        "y": 35
      },
      "id": 19,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull"
          ],
          "displayMode": "list",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
        }
      },
      "targets": [
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum(rate(django_model_inserts_total{job=\"trustpoint\"}[$__rate_interval])) or vector(0)",
          "legendFormat": "inserts/s",
          "range": true,
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum(rate(django_model_updates_total{job=\"trustpoint\"}[$__rate_interval])) or vector(0)",
          "legendFormat": "updates/s",
          "range": true,
          "refId": "B"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "sum(rate(django_model_deletes_total{job=\"trustpoint\"}[$__rate_interval])) or vector(0)",
          "legendFormat": "deletes/s",
          "range": true,
          "refId": "C"
        }
      ],
      "title": "Model write activity",
      "type": "timeseries"
    },
    {
      "collapsed": false,
      "gridPos": {
        "h": 1,
        "w": 24,
        "x": 0,
        "y": 42
      },
      "id": 103,
      "panels": [],
      "title": "Observability pipeline",
      "type": "row"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Prometheus-side scrape health for the Trustpoint metrics endpoint.",
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
        "y": 43
      },
      "id": 20,
      "options": {
        "legend": {
          "calcs": [
            "lastNotNull",
            "max"
          ],
          "displayMode": "table",
          "placement": "bottom",
          "showLegend": true
        },
        "tooltip": {
          "mode": "multi",
          "sort": "desc"
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
          "legendFormat": "scrape duration seconds",
          "range": true,
          "refId": "A"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "scrape_samples_scraped{job=\"trustpoint\"}",
          "legendFormat": "samples scraped",
          "range": true,
          "refId": "B"
        },
        {
          "datasource": {
            "type": "prometheus",
            "uid": "prometheus"
          },
          "editorMode": "code",
          "expr": "scrape_series_added{job=\"trustpoint\"}",
          "legendFormat": "series added",
          "range": true,
          "refId": "C"
        }
      ],
      "title": "Scrape duration, samples, and series",
      "type": "timeseries"
    },
    {
      "datasource": {
        "type": "prometheus",
        "uid": "prometheus"
      },
      "description": "Metric families currently exported by Trustpoint. Useful for validating the demo setup.",
      "fieldConfig": {
        "defaults": {
          "custom": {
            "align": "auto",
            "cellOptions": {
              "type": "auto"
            },
            "inspect": false
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
        "x": 12,
        "y": 43
      },
      "id": 21,
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
      "title": "Exported metric families",
      "type": "table"
    }
  ],
  "refresh": "10s",
  "schemaVersion": 39,
  "tags": [
    "trustpoint",
    "tp_wizard",
    "production",
    "demo"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "timepicker": {
    "refresh_intervals": [
      "5s",
      "10s",
      "30s",
      "1m",
      "5m",
      "15m",
      "30m",
      "1h"
    ],
    "time_options": [
      "5m",
      "15m",
      "1h",
      "6h",
      "12h",
      "24h",
      "2d",
      "7d",
      "30d"
    ]
  },
  "timezone": "browser",
  "title": "Trustpoint Production Overview",
  "uid": "trustpoint-overview",
  "version": 2,
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
    -e "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/trustpoint-overview.json" \
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
