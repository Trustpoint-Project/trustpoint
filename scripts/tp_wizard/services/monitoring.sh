#!/usr/bin/env bash

write_monitoring_files() {
  mkdir -p "$GENERATED_ROOT/prometheus" "$GENERATED_ROOT/grafana/provisioning/datasources" "$GENERATED_ROOT/grafana/provisioning/dashboards" "$GENERATED_ROOT/grafana/dashboards"
  printf '%s\n' 'global:' '  scrape_interval: 15s' 'scrape_configs:' '  - job_name: trustpoint' '    scheme: https' '    metrics_path: /prometheus/metrics' '    tls_config:' '      insecure_skip_verify: true' '    static_configs:' '      - targets: ["trustpoint:443"]' >"$GENERATED_ROOT/prometheus/prometheus.yml"
  printf '%s\n' 'apiVersion: 1' 'datasources:' '  - name: Prometheus' '    type: prometheus' '    access: proxy' '    url: http://prometheus:9090' '    isDefault: true' >"$GENERATED_ROOT/grafana/provisioning/datasources/prometheus.yml"
  printf '%s\n' 'apiVersion: 1' 'providers:' '  - name: Trustpoint' '    type: file' '    options:' '      path: /var/lib/grafana/dashboards' >"$GENERATED_ROOT/grafana/provisioning/dashboards/provider.yml"
  printf '%s\n' '{"title":"Trustpoint Overview","schemaVersion":39,"version":1,"refresh":"15s","panels":[{"id":1,"type":"stat","title":"Target Up","gridPos":{"h":4,"w":6,"x":0,"y":0},"targets":[{"expr":"up{job=\"trustpoint\"}","refId":"A"}]},{"id":2,"type":"timeseries","title":"Process CPU Seconds","gridPos":{"h":8,"w":12,"x":0,"y":4},"targets":[{"expr":"process_cpu_seconds_total{job=\"trustpoint\"}","refId":"A"}]},{"id":3,"type":"timeseries","title":"Resident Memory Bytes","gridPos":{"h":8,"w":12,"x":12,"y":4},"targets":[{"expr":"process_resident_memory_bytes{job=\"trustpoint\"}","refId":"A"}]}],"templating":{"list":[]},"time":{"from":"now-1h","to":"now"}}' >"$GENERATED_ROOT/grafana/dashboards/trustpoint-overview.json"
}

start_monitoring() {
  write_monitoring_files
  remove_container "$PROMETHEUS_NAME"
  start_container "$PROMETHEUS_NAME" -p 9090:9090 -v "$GENERATED_ROOT/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" prom/prometheus:latest --config.file=/etc/prometheus/prometheus.yml
  remove_container "$GRAFANA_NAME"
  start_container "$GRAFANA_NAME" -p 3000:3000 -v "$GENERATED_ROOT/grafana/provisioning:/etc/grafana/provisioning:ro" -v "$GENERATED_ROOT/grafana/dashboards:/var/lib/grafana/dashboards:ro" -e GF_SECURITY_ADMIN_USER="$GRAFANA_ADMIN_USER" -e GF_SECURITY_ADMIN_PASSWORD="$GRAFANA_ADMIN_PASSWORD" grafana/grafana:latest
  ok 'Prometheus and Grafana started'
}
