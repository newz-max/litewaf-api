#!/usr/bin/env sh
set -eu

PROJECT_NAME="${PROJECT_NAME:-litewaf}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
COMPOSE_FILES="${COMPOSE_FILES:-}"
ENV_FILE="${ENV_FILE:-.env}"
BACKUP_DIR="${BACKUP_DIR:-backups}"
STATE_DIR="${STATE_DIR:-state}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-180}"
SKIP_PULL="${LITEWAF_SKIP_PULL:-0}"

usage() {
  cat <<'EOF'
Usage: ./litewafctl.sh <command> [args]

Commands:
  validate                  Check Docker, Compose, env, ports, and compose config.
  install                   Pull prebuilt images, start services, and wait for health.
  diagnose                  Report listener mode, mapped ranges, ports, and reload status.
  backup [output-dir]       Create a timestamped backup archive.
  restore <archive>         Restore a backup archive into this deployment.
  upgrade <image-tag>       Backup, switch image tag, pull, start, and verify health.
  rollback [state-file]     Roll back to the previous image tag recorded by upgrade.
  geoip init|update          Download/update GeoIP data and restart the API container.
  health                    Wait for production services to become healthy.

Environment:
  PROJECT_NAME              Docker Compose project name, default litewaf.
  COMPOSE_FILE              Compose file path, default docker-compose.prod.yml.
  COMPOSE_FILES             Space-separated Compose files. Overrides COMPOSE_FILE.
  ENV_FILE                  Environment file path, default .env.
  BACKUP_DIR                Backup output directory, default backups.
  STATE_DIR                 Upgrade state directory, default state.
  LITEWAF_SKIP_PULL=1       Skip image pulls and start from already-loaded images.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

info() {
  printf '==> %s\n' "$*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

compose() {
  files="${COMPOSE_FILES:-$COMPOSE_FILE}"
  file_args=""
  for file in $files; do
    file_args="$file_args -f $file"
  done
  docker compose -p "$PROJECT_NAME" --env-file "$ENV_FILE" $file_args "$@"
}

local_images_available() {
  missing=0
  for image in $(compose config --images | sort -u); do
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      warn "local image is missing: $image"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ]
}

pull_images() {
  if [ "$SKIP_PULL" = "1" ]; then
    warn "skipping image pull because LITEWAF_SKIP_PULL=1"
    return 0
  fi

  info "pulling prebuilt images"
  if compose pull; then
    return 0
  fi

  warn "image pull failed; checking whether all required images already exist locally"
  if local_images_available; then
    warn "all required images are available locally; continuing without fresh pull"
    return 0
  fi

  die "image pull failed and one or more required images are missing locally"
}

env_value() {
  key="$1"
  if [ -f "$ENV_FILE" ]; then
    grep -E "^${key}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- || true
  fi
}

set_env_key() {
  key="$1"
  value="$2"
  file="$3"
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

ensure_env_key() {
  key="$1"
  value="$2"
  file="$3"
  if ! grep -q "^${key}=" "$file"; then
    printf '%s=%s\n' "$key" "$value" >>"$file"
  fi
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return
  fi
  LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 48
}

is_unsafe_value() {
  value="$1"
  case "$value" in
    ""|"change-me"|"admin123456"|"litewaf_dev_password"|"dev-litewaf-change-me"|"dev-gateway-change-me")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

ensure_env() {
  if [ ! -f "$ENV_FILE" ]; then
    [ -f ".env.example" ] || die "cannot create $ENV_FILE because .env.example is missing"
    cp ".env.example" "$ENV_FILE"
    chmod 600 "$ENV_FILE" 2>/dev/null || true
    info "created $ENV_FILE from .env.example"
  fi

  ensure_env_key APP_ENV production "$ENV_FILE"
  ensure_env_key LITEWAF_IMAGE_PREFIX litewaf "$ENV_FILE"
  ensure_env_key LITEWAF_IMAGE_TAG latest "$ENV_FILE"
  ensure_env_key POSTGRES_DB litewaf "$ENV_FILE"
  ensure_env_key POSTGRES_USER litewaf "$ENV_FILE"
  ensure_env_key PUBLISH_OPERATOR compose "$ENV_FILE"
  ensure_env_key METRICS_ENABLED false "$ENV_FILE"
  ensure_env_key LITEWAF_METRICS_ENABLED false "$ENV_FILE"
  ensure_env_key LITEWAF_SENSITIVE_HEADERS authorization,cookie,set-cookie "$ENV_FILE"
  ensure_env_key LITEWAF_LOG_VALUE_MAX_LEN 160 "$ENV_FILE"
  ensure_env_key LITEWAF_GEOIP_DB_PATH "" "$ENV_FILE"
  ensure_env_key LITEWAF_GEOIP_CACHE_SIZE 2048 "$ENV_FILE"
  ensure_env_key LITEWAF_REAL_IP_TRUSTED_CIDRS "" "$ENV_FILE"
  ensure_env_key LITEWAF_REAL_IP_HEADER X-Forwarded-For "$ENV_FILE"
  ensure_env_key LITEWAF_REAL_IP_RECURSIVE on "$ENV_FILE"
  ensure_env_key LITEWAF_ADMIN_USERNAME admin "$ENV_FILE"
  ensure_env_key LITEWAF_ADMIN_ROLE admin "$ENV_FILE"
  ensure_env_key DASHBOARD_PORT 18080 "$ENV_FILE"
  ensure_env_key GATEWAY_LISTENER_MODE host-network "$ENV_FILE"
  ensure_env_key GATEWAY_BRIDGE_PORT_RANGE "" "$ENV_FILE"
  ensure_env_key GATEWAY_RELOAD_COMMAND "" "$ENV_FILE"
  ensure_env_key API_LOOPBACK_ADDR 127.0.0.1 "$ENV_FILE"
  ensure_env_key API_LOOPBACK_PORT 18081 "$ENV_FILE"
  ensure_env_key LITEWAF_INGESTION_URL http://127.0.0.1:18081 "$ENV_FILE"
  if grep -Eq '^GATEWAY_PORT=(18081|8081)$' "$ENV_FILE"; then
    warn "GATEWAY_PORT is ignored by production listener mode; application listeners now bind their own ports"
  fi

  for key in POSTGRES_PASSWORD AUTH_TOKEN_SECRET GATEWAY_INGESTION_TOKEN LITEWAF_ADMIN_PASSWORD; do
    value="$(env_value "$key")"
    if is_unsafe_value "$value"; then
      set_env_key "$key" "$(random_secret)" "$ENV_FILE"
      info "generated secret for $key"
    fi
  done
}

check_port_free() {
  name="$1"
  port="$2"
  [ -n "$port" ] || die "$name is empty"
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "sport = :$port" | grep -q LISTEN; then
      die "$name=$port is already occupied"
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -ltn | awk '{print $4}' | grep -Eq "[:.]${port}$"; then
      die "$name=$port is already occupied"
    fi
  else
    warn "cannot check $name=$port because ss/netstat is unavailable"
  fi
}

http_url() {
  host="$1"
  port="$2"
  if [ "$port" = "80" ]; then
    printf 'http://%s/' "$host"
  else
    printf 'http://%s:%s/' "$host" "$port"
  fi
}

listener_mode() {
  mode="$(env_value GATEWAY_LISTENER_MODE)"
  case "$mode" in
    bridge|bridge-range|fixed-range|fixed-port-range)
      printf 'bridge-range'
      ;;
    *)
      printf 'host-network'
      ;;
  esac
}

listener_ports_to_check() {
  mode="$(listener_mode)"
  if [ "$mode" = "bridge-range" ]; then
    range="$(env_value GATEWAY_BRIDGE_PORT_RANGE)"
    if [ -n "$range" ]; then
      printf '%s\n' "$range" | tr ',' '\n' | while IFS= read -r item; do
        item="$(printf '%s' "$item" | tr -d ' ')"
        [ -n "$item" ] || continue
        case "$item" in
          *-*)
            printf '%s\n' "${item%%-*}"
            ;;
          *)
            printf '%s\n' "$item"
            ;;
        esac
      done
      return
    fi
  fi
  printf '80\n443\n'
}

validate_env_secrets() {
  failed=0
  for key in POSTGRES_PASSWORD AUTH_TOKEN_SECRET GATEWAY_INGESTION_TOKEN LITEWAF_ADMIN_PASSWORD; do
    value="$(env_value "$key")"
    if is_unsafe_value "$value"; then
      printf 'unsafe production value for %s\n' "$key" >&2
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] || die "unsafe production secrets detected"
}

validate() {
  need_cmd docker
  docker --version
  docker compose version
  [ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE"

  ensure_env
  validate_env_secrets

  df -h . || true
  ulimit -n || true

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    warn "firewalld is active; ensure dashboard and gateway ports are intentionally exposed"
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    warn "ufw is active; ensure dashboard and gateway ports are intentionally exposed"
  fi

  running="$(compose ps -q 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$running" = "0" ]; then
    check_port_free DASHBOARD_PORT "$(env_value DASHBOARD_PORT)"
    check_port_free API_LOOPBACK_PORT "$(env_value API_LOOPBACK_PORT)"
    listener_ports_to_check | while IFS= read -r port; do
      [ -n "$port" ] || continue
      check_port_free GATEWAY_LISTENER_PORT "$port"
    done
  else
    warn "existing $PROJECT_NAME containers found; skipping host port availability checks"
  fi
  compose config >/dev/null
  info "validation passed"
}

wait_health() {
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT_SECONDS ))
  services="postgres redis waf-api dashboard gateway"
  while :; do
    unhealthy=""
    pending=""
    for service in $services; do
      cid="$(compose ps -q "$service" 2>/dev/null || true)"
      if [ -z "$cid" ]; then
        pending="$pending $service"
        continue
      fi
      state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || true)"
      case "$state" in
        healthy|running)
          ;;
        unhealthy|exited|dead)
          unhealthy="$unhealthy $service($state)"
          ;;
        *)
          pending="$pending $service($state)"
          ;;
      esac
    done

    [ -z "$unhealthy" ] || die "unhealthy services:$unhealthy"
    if [ -z "$pending" ]; then
      info "all required services are healthy"
      return 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || die "timed out waiting for services:$pending"
    sleep 5
  done
}

install_stack() {
  validate
  pull_images
  info "starting production stack"
  compose up -d --no-build --remove-orphans
  wait_health
  compose ps
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  dashboard_port="$(env_value DASHBOARD_PORT)"
  info "Dashboard: $(http_url "$host_ip" "$dashboard_port")"
  info "Gateway listener mode: $(listener_mode)"
  info "Application listeners are opened by published protected applications."
  info "Admin username: $(env_value LITEWAF_ADMIN_USERNAME)"
  info "Admin password: $(env_value LITEWAF_ADMIN_PASSWORD)"
}

diagnose_stack() {
  ensure_env
  info "listener_mode=$(listener_mode)"
  info "bridge_port_range=$(env_value GATEWAY_BRIDGE_PORT_RANGE)"
  info "dashboard_port=$(env_value DASHBOARD_PORT)"
  info "api_loopback=$(env_value API_LOOPBACK_ADDR):$(env_value API_LOOPBACK_PORT)"
  if [ -n "$(env_value GATEWAY_PORT)" ]; then
    warn "GATEWAY_PORT is present but ignored by production application-listener mode"
  fi
  if command -v ss >/dev/null 2>&1; then
    for port in $(listener_ports_to_check); do
      [ -n "$port" ] || continue
      if ss -ltn "sport = :$port" | grep -q LISTEN; then
        info "port $port: listening"
      else
        warn "port $port: not listening yet or no published listener"
      fi
    done
  else
    warn "cannot inspect listener ports because ss is unavailable"
  fi
  cid="$(compose ps -q gateway 2>/dev/null || true)"
  if [ -n "$cid" ]; then
    info "gateway_container=$cid"
    docker exec "$cid" /bin/sh -c 'test -f /var/lib/litewaf/runtime/reload-status.json && cat /var/lib/litewaf/runtime/reload-status.json || true' 2>/dev/null || true
    docker exec "$cid" /bin/sh -c 'find /etc/litewaf/listeners -maxdepth 1 -type f -name "*.conf" -printf "%f\n" 2>/dev/null || true' 2>/dev/null || true
    docker exec "$cid" /bin/sh -c 'find /etc/litewaf/certificates -maxdepth 2 -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.key" \) -printf "%p\n" 2>/dev/null | sed "s#privkey[^/]*#privkey(redacted)#g; s#\\.key$#.key(redacted)#g" || true' 2>/dev/null || true
  else
    warn "gateway container is not running"
  fi
}

backup_stack() {
  output_dir="${1:-$BACKUP_DIR}"
  mkdir -p "$output_dir"
  chmod 700 "$output_dir" 2>/dev/null || true
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  tmp_dir="$(mktemp -d)"
  archive="$output_dir/litewaf-backup-$ts.tar.gz"
  trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

  info "creating PostgreSQL dump"
  compose exec -T postgres pg_dump --clean --if-exists -U "$(env_value POSTGRES_USER)" -d "$(env_value POSTGRES_DB)" >"$tmp_dir/postgres.sql"

  info "collecting gateway configuration and deployment metadata"
  mkdir -p "$tmp_dir/gateway"
  cid="$(compose ps -q gateway 2>/dev/null || true)"
  if [ -n "$cid" ]; then
    docker cp "$cid:/etc/litewaf/." "$tmp_dir/gateway" >/dev/null
  fi
  cp "$ENV_FILE" "$tmp_dir/env"
  compose config >"$tmp_dir/compose.config.yml"
  cat >"$tmp_dir/manifest.json" <<EOF
{"created_at":"$ts","project":"$PROJECT_NAME","compose_file":"$COMPOSE_FILE","image_tag":"$(env_value LITEWAF_IMAGE_TAG)","contains_secrets":true}
EOF

  tar -C "$tmp_dir" -czf "$archive.tmp" .
  chmod 600 "$archive.tmp" 2>/dev/null || true
  mv "$archive.tmp" "$archive"
  info "backup created: $archive"
  warn "backup archives contain secrets; store them in a protected location"
}

restore_stack() {
  archive="${1:-}"
  [ -n "$archive" ] || die "restore requires a backup archive path"
  [ -f "$archive" ] || die "backup archive not found: $archive"

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
  tar -C "$tmp_dir" -xzf "$archive"
  [ -f "$tmp_dir/manifest.json" ] || die "backup manifest is missing"
  [ -f "$tmp_dir/postgres.sql" ] || die "postgres.sql is missing from backup"
  [ -f "$tmp_dir/env" ] || die "env is missing from backup"

  running="$(compose ps -q 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$running" != "0" ]; then
    [ "${LITEWAF_RESTORE_CONFIRM:-}" = "yes" ] || die "services are running; set LITEWAF_RESTORE_CONFIRM=yes to restore"
  fi

  info "stopping services for restore"
  compose down
  cp "$tmp_dir/env" "$ENV_FILE"
  ensure_env

  info "starting PostgreSQL and Redis"
  compose up -d postgres redis
  wait_for_db

  info "restoring PostgreSQL dump"
  compose exec -T postgres psql -U "$(env_value POSTGRES_USER)" -d "$(env_value POSTGRES_DB)" -v ON_ERROR_STOP=1 <"$tmp_dir/postgres.sql"

  compose up -d --no-build --remove-orphans
  if [ -d "$tmp_dir/gateway" ]; then
    info "restoring gateway configuration volume"
    cid="$(compose ps -q gateway 2>/dev/null || true)"
    if [ -n "$cid" ]; then
      docker cp "$tmp_dir/gateway/." "$cid:/etc/litewaf/" >/dev/null
      compose restart gateway >/dev/null
    fi
  fi
  wait_health
  info "restore complete"
}

wait_for_db() {
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT_SECONDS ))
  while :; do
    if compose exec -T postgres pg_isready -U "$(env_value POSTGRES_USER)" -d "$(env_value POSTGRES_DB)" >/dev/null 2>&1; then
      return 0
    fi
    [ "$(date +%s)" -lt "$deadline" ] || die "timed out waiting for PostgreSQL"
    sleep 3
  done
}

upgrade_stack() {
  target="${1:-}"
  [ -n "$target" ] || die "upgrade requires a target image tag"
  ensure_env
  validate_env_secrets
  mkdir -p "$STATE_DIR"
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  state_file="$STATE_DIR/upgrade-$ts.env"
  previous="$(env_value LITEWAF_IMAGE_TAG)"
  {
    printf 'PREVIOUS_TAG=%s\n' "$previous"
    printf 'TARGET_TAG=%s\n' "$target"
    printf 'CREATED_AT=%s\n' "$ts"
    printf 'COMPOSE_FILE=%s\n' "$COMPOSE_FILE"
    printf 'PROJECT_NAME=%s\n' "$PROJECT_NAME"
  } >"$state_file"
  info "recorded upgrade state: $state_file"
  backup_stack "$BACKUP_DIR"
  set_env_key LITEWAF_IMAGE_TAG "$target" "$ENV_FILE"
  pull_images
  compose up -d --no-build --remove-orphans
  if wait_health; then
    cp "$state_file" "$STATE_DIR/current.env"
    info "upgrade complete: $previous -> $target"
  else
    die "upgrade health verification failed; run ./litewafctl.sh rollback $state_file"
  fi
}

rollback_stack() {
  state_file="${1:-$STATE_DIR/current.env}"
  [ -f "$state_file" ] || die "rollback state file not found: $state_file"
  previous="$(grep '^PREVIOUS_TAG=' "$state_file" | tail -n 1 | cut -d= -f2-)"
  [ -n "$previous" ] || die "rollback state does not contain PREVIOUS_TAG"
  ensure_env
  info "rolling back to image tag $previous"
  set_env_key LITEWAF_IMAGE_TAG "$previous" "$ENV_FILE"
  pull_images
  compose up -d --no-build --remove-orphans
  wait_health
  info "rollback complete"
  warn "if the failed upgrade changed data irreversibly, restore the pre-upgrade backup before serving traffic"
}

geoip_stack() {
  action="${1:-update}"
  case "$action" in
    init|update)
      ;;
    *)
      die "geoip requires init or update"
      ;;
  esac
  ensure_env
  if [ ! -x "./geoip-init.sh" ]; then
    die "geoip-init.sh is missing or not executable; refresh deployment files first"
  fi
  PROJECT_NAME="$PROJECT_NAME" COMPOSE_FILE="$COMPOSE_FILE" COMPOSE_FILES="$COMPOSE_FILES" LITEWAF_ENV_FILE="$ENV_FILE" ./geoip-init.sh "$action"
}

cmd="${1:-}"
case "$cmd" in
  validate)
    validate
    ;;
  install)
    install_stack
    ;;
  diagnose)
    diagnose_stack
    ;;
  backup)
    shift
    backup_stack "${1:-$BACKUP_DIR}"
    ;;
  restore)
    shift
    restore_stack "${1:-}"
    ;;
  upgrade)
    shift
    upgrade_stack "${1:-}"
    ;;
  rollback)
    shift
    rollback_stack "${1:-$STATE_DIR/current.env}"
    ;;
  geoip)
    shift
    geoip_stack "${1:-update}"
    ;;
  health)
    wait_health
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    usage >&2
    die "unknown command: $cmd"
    ;;
esac
