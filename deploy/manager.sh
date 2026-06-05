#!/usr/bin/env sh
set -eu

DEFAULT_BASE_URL="https://raw.githubusercontent.com/newz-max/litewaf-api/master/deploy"
GITEE_BASE_URL="https://gitee.com/old_records/litewaf-api/raw/master/deploy"

INSTALL_DIR="${LITEWAF_INSTALL_DIR:-/opt/litewaf}"
IMAGE_PREFIX="${LITEWAF_IMAGE_PREFIX:-mmxiaozhi}"
IMAGE_TAG="${LITEWAF_IMAGE_TAG:-latest}"
PROJECT_NAME="${PROJECT_NAME:-litewaf}"

info() {
  printf '==> %s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

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
    curl -fsSL -o "$dest" "$url"
  else
    wget -qO "$dest" "$url"
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

need_cmd id
need_cmd mktemp

if [ -n "${LITEWAF_BASE_URL:-}" ]; then
  BASE_URLS="${LITEWAF_BASE_URL%/}"
else
  BASE_URLS="$DEFAULT_BASE_URL $GITEE_BASE_URL"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

info "installing LiteWaf into $INSTALL_DIR"
download_deploy_file docker-compose.prod.yml
download_deploy_file .env.example
download_deploy_file litewafctl.sh

$SUDO mkdir -p "$INSTALL_DIR"
$SUDO cp "$TMP_DIR/docker-compose.prod.yml" "$INSTALL_DIR/docker-compose.prod.yml"
$SUDO cp "$TMP_DIR/.env.example" "$INSTALL_DIR/.env.example"
$SUDO cp "$TMP_DIR/litewafctl.sh" "$INSTALL_DIR/litewafctl.sh"
$SUDO chmod 644 "$INSTALL_DIR/docker-compose.prod.yml" "$INSTALL_DIR/.env.example"
$SUDO chmod 755 "$INSTALL_DIR/litewafctl.sh"

if [ ! -f "$INSTALL_DIR/.env" ]; then
  $SUDO cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
  $SUDO chmod 600 "$INSTALL_DIR/.env" 2>/dev/null || true
  set_env_key LITEWAF_IMAGE_PREFIX "$IMAGE_PREFIX" "$INSTALL_DIR/.env"
  set_env_key LITEWAF_IMAGE_TAG "$IMAGE_TAG" "$INSTALL_DIR/.env"
  info "created $INSTALL_DIR/.env"
elif [ -n "${LITEWAF_IMAGE_PREFIX:-}" ] || [ -n "${LITEWAF_IMAGE_TAG:-}" ]; then
  if [ -n "${LITEWAF_IMAGE_PREFIX:-}" ]; then
    set_env_key LITEWAF_IMAGE_PREFIX "$IMAGE_PREFIX" "$INSTALL_DIR/.env"
  fi
  if [ -n "${LITEWAF_IMAGE_TAG:-}" ]; then
    set_env_key LITEWAF_IMAGE_TAG "$IMAGE_TAG" "$INSTALL_DIR/.env"
  fi
  info "updated image coordinates in $INSTALL_DIR/.env"
else
  info "preserving existing $INSTALL_DIR/.env"
fi

info "starting LiteWaf"
(
  cd "$INSTALL_DIR"
  $SUDO env PROJECT_NAME="$PROJECT_NAME" COMPOSE_FILE=docker-compose.prod.yml ENV_FILE=.env ./litewafctl.sh install
  $SUDO env PROJECT_NAME="$PROJECT_NAME" COMPOSE_FILE=docker-compose.prod.yml ENV_FILE=.env ./litewafctl.sh health
)

info "LiteWaf installation complete"
printf 'Dashboard: http://SERVER_IP:%s\n' "$($SUDO grep '^DASHBOARD_PORT=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
printf 'Gateway:   http://SERVER_IP:%s\n' "$($SUDO grep '^GATEWAY_PORT=' "$INSTALL_DIR/.env" | tail -n 1 | cut -d= -f2-)"
printf 'Config:    %s/.env\n' "$INSTALL_DIR"
