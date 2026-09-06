#!/usr/bin/env bash

container_exists() { docker container inspect "$1" >/dev/null 2>&1; }
container_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" == true ]]; }
ensure_network() { docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null; }
ensure_volume() { docker volume inspect "$1" >/dev/null 2>&1 || docker volume create "$1" >/dev/null; }
remove_container() { container_exists "$1" && docker rm -f "$1" >/dev/null 2>&1 || true; }
container_env() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null | sed -n "s/^$2=//p" | head -n1; }
start_container() { local name="$1"; shift; docker run -d --restart unless-stopped --name "$name" --network "$NET" "$@" >/dev/null; }

compose_file="${ROOT_DIR}/docker-compose.yml"
compose_available() { [[ -f "$compose_file" ]] && docker compose -f "$compose_file" version >/dev/null 2>&1; }
compose_service_containers() { compose_available || return 0; docker compose -f "$compose_file" ps -aq "$1" 2>/dev/null; }
remove_compose_service() {
  local service="$1" id
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    docker rm -f "$id" >/dev/null 2>&1 || true
  done < <(compose_service_containers "$service")
}
compose_down() {
  compose_available || return 0
  docker compose -f "$compose_file" down "$@" >/dev/null 2>&1 || true
}
