#!/usr/bin/env bash

write_monitoring_files() {
  mkdir -p "$GENERATED_ROOT/prometheus" "$GENERATED_ROOT/grafana/provisioning/datasources" "$GENERATED_ROOT/grafana/provisioning/dashboards" "$GENERATED_ROOT/grafana/dashboards"
  printf '%s\n' 'global:' '  scrape_interval: 15s' '  evaluation_interval: 15s' 'scrape_configs:' '  - job_name: trustpoint' '    scheme: https' '    metrics_path: /prometheus/metrics' '    tls_config:' '      insecure_skip_verify: true' '    static_configs:' '      - targets: ["trustpoint.local:443"]' >"$GENERATED_ROOT/prometheus/prometheus.yml"
  printf '%s\n' 'apiVersion: 1' 'datasources:' '  - name: Prometheus' '    type: prometheus' '    access: proxy' '    url: http://prometheus:9090' '    isDefault: true' >"$GENERATED_ROOT/grafana/provisioning/datasources/prometheus.yml"
  printf '%s\n' 'apiVersion: 1' 'providers:' '  - name: Trustpoint' '    type: file' '    options:' '      path: /var/lib/grafana/dashboards' >"$GENERATED_ROOT/grafana/provisioning/dashboards/provider.yml"
  printf '%s\n' '{"title":"Trustpoint Overview","uid":"trustpoint-overview","schemaVersion":39,"version":2,"refresh":"15s","tags":["trustpoint","django"],"time":{"from":"now-1h","to":"now"},"panels":[{"id":1,"type":"stat","title":"Trustpoint scrape","gridPos":{"h":4,"w":6,"x":0,"y":0},"fieldConfig":{"defaults":{"unit":"short","thresholds":{"mode":"absolute","steps":[{"color":"red","value":0},{"color":"green","value":1}]}},"overrides":[]},"options":{"reduceOptions":{"calcs":["lastNotNull"]}},"targets":[{"expr":"up{job=\"trustpoint\"}","refId":"A"}]},{"id":2,"type":"stat","title":"Requests / sec","gridPos":{"h":4,"w":6,"x":6,"y":0},"fieldConfig":{"defaults":{"unit":"reqps"},"overrides":[]},"targets":[{"expr":"sum(rate(django_http_requests_before_middlewares_total{job=\"trustpoint\"}[5m]))","refId":"A"}]},{"id":3,"type":"stat","title":"Resident memory","gridPos":{"h":4,"w":6,"x":12,"y":0},"fieldConfig":{"defaults":{"unit":"bytes"},"overrides":[]},"targets":[{"expr":"process_resident_memory_bytes{job=\"trustpoint\"}","refId":"A"}]},{"id":4,"type":"stat","title":"Open file descriptors","gridPos":{"h":4,"w":6,"x":18,"y":0},"targets":[{"expr":"process_open_fds{job=\"trustpoint\"}","refId":"A"}]},{"id":5,"type":"timeseries","title":"HTTP request rate","gridPos":{"h":8,"w":12,"x":0,"y":4},"fieldConfig":{"defaults":{"unit":"reqps"},"overrides":[]},"targets":[{"expr":"sum by (method, transport) (rate(django_http_requests_total_by_method_total{job=\"trustpoint\"}[5m]))","legendFormat":"{{method}} {{transport}}","refId":"A"}]},{"id":6,"type":"timeseries","title":"HTTP latency p95","gridPos":{"h":8,"w":12,"x":12,"y":4},"fieldConfig":{"defaults":{"unit":"s"},"overrides":[]},"targets":[{"expr":"histogram_quantile(0.95, sum by (le) (rate(django_http_requests_latency_including_middlewares_seconds_bucket{job=\"trustpoint\"}[5m])))","legendFormat":"p95","refId":"A"}]},{"id":7,"type":"timeseries","title":"Process resources","gridPos":{"h":8,"w":12,"x":0,"y":12},"fieldConfig":{"defaults":{"unit":"short"},"overrides":[]},"targets":[{"expr":"rate(process_cpu_seconds_total{job=\"trustpoint\"}[5m])","legendFormat":"CPU cores","refId":"A"},{"expr":"process_virtual_memory_bytes{job=\"trustpoint\"}","legendFormat":"Virtual memory","refId":"B"}]},{"id":8,"type":"timeseries","title":"Python garbage collection","gridPos":{"h":8,"w":12,"x":12,"y":12},"targets":[{"expr":"rate(python_gc_collections_total{job=\"trustpoint\"}[5m])","legendFormat":"generation {{generation}}","refId":"A"}]}],"templating":{"list":[]}}' >"$GENERATED_ROOT/grafana/dashboards/trustpoint-overview.json"
}

start_monitoring() {
  write_monitoring_files
  remove_container "$PROMETHEUS_NAME"
  start_container "$PROMETHEUS_NAME" -p 9090:9090 -v "$GENERATED_ROOT/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" prom/prometheus:latest --config.file=/etc/prometheus/prometheus.yml
  remove_container "$GRAFANA_NAME"
  start_container "$GRAFANA_NAME" -p 3000:3000 -v "$GENERATED_ROOT/grafana/provisioning:/etc/grafana/provisioning:ro" -v "$GENERATED_ROOT/grafana/dashboards:/var/lib/grafana/dashboards:ro" -e GF_SECURITY_ADMIN_USER="$GRAFANA_ADMIN_USER" -e GF_SECURITY_ADMIN_PASSWORD="$GRAFANA_ADMIN_PASSWORD" grafana/grafana:latest
  ok 'Prometheus and Grafana started'
}

monitoring_wait_target() {
  $NOWAIT && return 0
  local query='http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22trustpoint%22%7D'
  for ((i=0; i<60; i++)); do
    if curl -fsS "$query" 2>/dev/null | grep -q '"value":\[[^]]*,"1"\]'; then
      ok 'Prometheus is scraping Trustpoint'
      return 0
    fi
    sleep 1
  done
  warn 'Prometheus is running, but Trustpoint is not scraped yet; check http://localhost:9090/targets'
}
