#!/usr/bin/env sh
set -eu

DEFAULT_BASE_URL="https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy"
GITEE_BASE_URL="https://gitee.com/old_records/litewaf-api/raw/master/deploy"

INSTALL_DIR="${LITEWAF_INSTALL_DIR:-/opt/litewaf}"
IMAGE_PREFIX="${LITEWAF_IMAGE_PREFIX:-mmxiaozhi}"
IMAGE_TAG="${LITEWAF_IMAGE_TAG:-latest}"
PROJECT_NAME="${PROJECT_NAME:-litewaf}"
DASHBOARD_PORT_OVERRIDE="${LITEWAF_DASHBOARD_PORT:-}"
GATEWAY_LISTENER_MODE_OVERRIDE="${LITEWAF_GATEWAY_LISTENER_MODE:-${GATEWAY_LISTENER_MODE:-}}"
GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE="${LITEWAF_GATEWAY_BRIDGE_PORT_RANGE:-${GATEWAY_BRIDGE_PORT_RANGE:-}}"
CONNECT_TIMEOUT_SECONDS="${LITEWAF_CONNECT_TIMEOUT_SECONDS:-15}"
DOWNLOAD_RETRIES="${LITEWAF_DOWNLOAD_RETRIES:-2}"
HEARTBEAT_SECONDS="${LITEWAF_HEARTBEAT_SECONDS:-15}"
TOTAL_STEPS=7
CURRENT_STEP=0

timestamp() {
  date '+%Y-%m-%d %H:%M:%S'
}

info() {
  printf '[%s] ==> %s\n' "$(timestamp)" "$*"
}

warn() {
  printf '[%s] warning: %s\n' "$(timestamp)" "$*" >&2
}

die() {
  printf '[%s] error: %s\n' "$(timestamp)" "$*" >&2
  exit 1
}

step() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  info "[$CURRENT_STEP/$TOTAL_STEPS] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_port() {
  name="$1"
  port="$2"
  case "$port" in
    ""|*[!0-9]*)
      die "$name must be a number between 1 and 65535"
      ;;
  esac
  if [ "${#port}" -gt 5 ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    die "$name must be a number between 1 and 65535"
  fi
}

if [ -n "$DASHBOARD_PORT_OVERRIDE" ]; then
  validate_port LITEWAF_DASHBOARD_PORT "$DASHBOARD_PORT_OVERRIDE"
fi

if [ "${LITEWAF_SKIP_SUDO:-}" = "1" ]; then
  SUDO=""
elif [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    die "run as root or install sudo"
  fi
else
  SUDO=""
fi

if command -v curl >/dev/null 2>&1; then
  FETCH_CMD="curl"
elif command -v wget >/dev/null 2>&1; then
  FETCH_CMD="wget"
else
  die "required command not found: curl or wget"
fi

download() {
  url="$1"
  dest="$2"
  if [ "$FETCH_CMD" = "curl" ]; then
    curl -fL --connect-timeout "$CONNECT_TIMEOUT_SECONDS" --retry "$DOWNLOAD_RETRIES" --retry-delay 2 -o "$dest" "$url"
  else
    wget -O "$dest" "$url"
  fi
}

download_deploy_file() {
  file="$1"
  dest="$TMP_DIR/$file"
  for base_url in $BASE_URLS; do
    if download "$base_url/$file" "$dest"; then
      info "downloaded $file from $base_url"
      return 0
    fi
    warn "failed to download $file from $base_url"
  done
  die "failed to download $file"
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

set_env_key() {
  key="$1"
  value="$2"
  file="$3"
  if $SUDO grep -q "^${key}=" "$file"; then
    $SUDO sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" | $SUDO tee -a "$file" >/dev/null
  fi
}

run_with_heartbeat() {
  label="$1"
  shift
  start_ts="$(date +%s)"
  info "$label started"
  "$@" &
  pid="$!"
  (
    while :; do
      sleep "$HEARTBEAT_SECONDS"
      kill -0 "$pid" 2>/dev/null || exit 0
      now_ts="$(date +%s)"
      info "$label still running for $((now_ts - start_ts))s"
    done
  ) &
  heartbeat_pid="$!"
  if wait "$pid"; then
    kill "$heartbeat_pid" 2>/dev/null || true
    wait "$heartbeat_pid" 2>/dev/null || true
    end_ts="$(date +%s)"
    info "$label finished in $((end_ts - start_ts))s"
  else
    status="$?"
    kill "$heartbeat_pid" 2>/dev/null || true
    wait "$heartbeat_pid" 2>/dev/null || true
    end_ts="$(date +%s)"
    die "$label failed after $((end_ts - start_ts))s with exit code $status"
  fi
}

run_litewafctl() {
  command_name="$1"
  label="$2"
  if [ -n "$SUDO" ]; then
    run_with_heartbeat "$label" "$SUDO" env PROJECT_NAME="$PROJECT_NAME" COMPOSE_FILES="$COMPOSE_FILES" COMPOSE_FILE=docker-compose.prod.yml ENV_FILE=.env ./litewafctl.sh "$command_name"
  else
    run_with_heartbeat "$label" env PROJECT_NAME="$PROJECT_NAME" COMPOSE_FILES="$COMPOSE_FILES" COMPOSE_FILE=docker-compose.prod.yml ENV_FILE=.env ./litewafctl.sh "$command_name"
  fi
}

installed_env_value() {
  key="$1"
  $SUDO grep "^${key}=" "$INSTALL_DIR/.env" 2>/dev/null | tail -n 1 | cut -d= -f2- || true
}

need_cmd id
need_cmd mktemp

if [ -n "${LITEWAF_BASE_URL:-}" ]; then
  BASE_URLS="${LITEWAF_BASE_URL%/}"
else
  BASE_URLS="$DEFAULT_BASE_URL $GITEE_BASE_URL"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

step "Preparing LiteWaf installer"
info "install directory: $INSTALL_DIR"
info "project name: $PROJECT_NAME"
info "image: $IMAGE_PREFIX:$IMAGE_TAG"
if [ -n "$DASHBOARD_PORT_OVERRIDE" ]; then
  info "dashboard port override: $DASHBOARD_PORT_OVERRIDE"
fi
if [ -n "$GATEWAY_LISTENER_MODE_OVERRIDE" ]; then
  info "gateway listener mode override: $GATEWAY_LISTENER_MODE_OVERRIDE"
fi
if [ -n "$GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE" ]; then
  info "gateway bridge port range override: $GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE"
fi
info "download source candidates: $BASE_URLS"
info "heartbeat interval: ${HEARTBEAT_SECONDS}s"

step "Downloading deployment files"
download_deploy_file docker-compose.prod.yml
download_deploy_file docker-compose.bridge-range.yml
download_deploy_file .env.example
download_deploy_file litewafctl.sh
download_deploy_file geoip-init.sh

step "Installing deployment files"
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO cp "$TMP_DIR/docker-compose.prod.yml" "$INSTALL_DIR/docker-compose.prod.yml"
$SUDO cp "$TMP_DIR/docker-compose.bridge-range.yml" "$INSTALL_DIR/docker-compose.bridge-range.yml"
$SUDO cp "$TMP_DIR/.env.example" "$INSTALL_DIR/.env.example"
$SUDO cp "$TMP_DIR/litewafctl.sh" "$INSTALL_DIR/litewafctl.sh"
$SUDO cp "$TMP_DIR/geoip-init.sh" "$INSTALL_DIR/geoip-init.sh"
$SUDO chmod 644 "$INSTALL_DIR/docker-compose.prod.yml" "$INSTALL_DIR/docker-compose.bridge-range.yml" "$INSTALL_DIR/.env.example"
$SUDO chmod 755 "$INSTALL_DIR/litewafctl.sh" "$INSTALL_DIR/geoip-init.sh"
info "installed docker-compose.prod.yml, docker-compose.bridge-range.yml, .env.example, litewafctl.sh, and geoip-init.sh"

step "Preparing environment file"
if [ ! -f "$INSTALL_DIR/.env" ]; then
  $SUDO cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
  $SUDO chmod 600 "$INSTALL_DIR/.env" 2>/dev/null || true
  set_env_key LITEWAF_IMAGE_PREFIX "$IMAGE_PREFIX" "$INSTALL_DIR/.env"
  set_env_key LITEWAF_IMAGE_TAG "$IMAGE_TAG" "$INSTALL_DIR/.env"
  if [ -n "$DASHBOARD_PORT_OVERRIDE" ]; then
    set_env_key DASHBOARD_PORT "$DASHBOARD_PORT_OVERRIDE" "$INSTALL_DIR/.env"
  fi
  if [ -n "$GATEWAY_LISTENER_MODE_OVERRIDE" ]; then
    set_env_key GATEWAY_LISTENER_MODE "$GATEWAY_LISTENER_MODE_OVERRIDE" "$INSTALL_DIR/.env"
  fi
  if [ -n "$GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE" ]; then
    set_env_key GATEWAY_BRIDGE_PORT_RANGE "$GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE" "$INSTALL_DIR/.env"
  fi
  info "created $INSTALL_DIR/.env"
else
  env_updated=0
  if [ -n "${LITEWAF_IMAGE_PREFIX:-}" ]; then
    set_env_key LITEWAF_IMAGE_PREFIX "$IMAGE_PREFIX" "$INSTALL_DIR/.env"
    env_updated=1
  fi
  if [ -n "${LITEWAF_IMAGE_TAG:-}" ]; then
    set_env_key LITEWAF_IMAGE_TAG "$IMAGE_TAG" "$INSTALL_DIR/.env"
    env_updated=1
  fi
  if [ -n "$DASHBOARD_PORT_OVERRIDE" ]; then
    set_env_key DASHBOARD_PORT "$DASHBOARD_PORT_OVERRIDE" "$INSTALL_DIR/.env"
    env_updated=1
  fi
  if [ -n "$GATEWAY_LISTENER_MODE_OVERRIDE" ]; then
    set_env_key GATEWAY_LISTENER_MODE "$GATEWAY_LISTENER_MODE_OVERRIDE" "$INSTALL_DIR/.env"
    env_updated=1
  fi
  if [ -n "$GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE" ]; then
    set_env_key GATEWAY_BRIDGE_PORT_RANGE "$GATEWAY_BRIDGE_PORT_RANGE_OVERRIDE" "$INSTALL_DIR/.env"
    env_updated=1
  fi
  if [ "$env_updated" = "1" ]; then
    info "updated environment settings in $INSTALL_DIR/.env"
  else
    info "preserving existing $INSTALL_DIR/.env"
  fi
fi

gateway_listener_mode="$(installed_env_value GATEWAY_LISTENER_MODE)"
case "$gateway_listener_mode" in
  bridge|bridge-range|fixed-range|fixed-port-range)
    COMPOSE_FILES="docker-compose.prod.yml docker-compose.bridge-range.yml"
    info "using compose files: $COMPOSE_FILES"
    ;;
  *)
    COMPOSE_FILES="docker-compose.prod.yml"
    info "using compose file: $COMPOSE_FILES"
    ;;
esac

step "Running production install"
(
  cd "$INSTALL_DIR"
  run_litewafctl install "litewafctl install"
)

step "Checking service health"
(
  cd "$INSTALL_DIR"
  run_litewafctl health "litewafctl health"
)

step "Printing access information"
info "LiteWaf installation complete"
dashboard_port="$($SUDO grep '^DASHBOARD_PORT=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
gateway_listener_mode="$($SUDO grep '^GATEWAY_LISTENER_MODE=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
gateway_bridge_range="$($SUDO grep '^GATEWAY_BRIDGE_PORT_RANGE=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
printf 'Dashboard: %s\n' "$(http_url SERVER_IP "$dashboard_port")"
if [ "$gateway_listener_mode" = "bridge-range" ] && [ -n "$gateway_bridge_range" ]; then
  printf 'Gateway listeners: bridge-range %s\n' "$gateway_bridge_range"
else
  printf 'Gateway listeners: %s\n' "${gateway_listener_mode:-host-network}"
fi
printf 'Admin username: %s\n' "$($SUDO grep '^LITEWAF_ADMIN_USERNAME=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
printf 'Admin password: %s\n' "$($SUDO grep '^LITEWAF_ADMIN_PASSWORD=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
printf 'Config:    %s/.env\n' "$INSTALL_DIR"
