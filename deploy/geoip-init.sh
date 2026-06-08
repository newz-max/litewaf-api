#!/usr/bin/env sh
set -eu

INSTALL_DIR="${LITEWAF_INSTALL_DIR:-/opt/litewaf}"
ENV_FILE="${LITEWAF_ENV_FILE:-$INSTALL_DIR/.env}"
DATA_DIR="${LITEWAF_GEOIP_DATA_DIR:-$INSTALL_DIR/data/geoip}"
CONTAINER_DB_PATH="${LITEWAF_GEOIP_CONTAINER_PATH:-/var/lib/litewaf/geoip/geoip.csv}"
CONTAINER_CHINA_DB_PATH="${LITEWAF_GEOIP_CHINA_CONTAINER_PATH:-/var/lib/litewaf/geoip/ip2region_v4.xdb}"
SOURCE_MONTH="${LITEWAF_GEOIP_DBIP_MONTH:-$(date -u +%Y-%m)}"
DBIP_EDITION="${LITEWAF_GEOIP_DBIP_EDITION:-country}"
CHINA_ENABLED="${LITEWAF_GEOIP_CHINA_ENABLED:-1}"
RESTART_API="${LITEWAF_GEOIP_RESTART_API:-1}"
PROJECT_NAME="${PROJECT_NAME:-litewaf}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.prod.yml}"
COMPOSE_FILES="${COMPOSE_FILES:-}"

CUSTOM_SOURCE_URL="${LITEWAF_GEOIP_SOURCE_URL:-}"
CHINA_SOURCE_URL="${LITEWAF_GEOIP_CHINA_SOURCE_URL:-https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb}"
case "$DBIP_EDITION" in
  country|city)
    ;;
  *)
    printf 'error: LITEWAF_GEOIP_DBIP_EDITION must be country or city\n' >&2
    exit 1
    ;;
esac
SOURCE_URL="${CUSTOM_SOURCE_URL:-https://download.db-ip.com/free/dbip-$DBIP_EDITION-lite-$SOURCE_MONTH.csv.gz}"

usage() {
  cat <<'EOF'
Usage: ./geoip-init.sh [init|update]

Downloads DB-IP Lite data, converts it to LiteWaf CSV format, updates
LITEWAF_GEOIP_DB_PATH plus the optional ip2region China database path in .env,
and restarts the API container by default.

Environment:
  LITEWAF_INSTALL_DIR          Install directory, default /opt/litewaf.
  LITEWAF_GEOIP_DATA_DIR       Host data directory, default $INSTALL_DIR/data/geoip.
  LITEWAF_GEOIP_CONTAINER_PATH Container CSV path, default /var/lib/litewaf/geoip/geoip.csv.
  LITEWAF_GEOIP_CHINA_CONTAINER_PATH
                                Container xdb path, default /var/lib/litewaf/geoip/ip2region_v4.xdb.
  LITEWAF_GEOIP_RESTART_API=0  Do not restart the API container.
  LITEWAF_GEOIP_DBIP_MONTH     DB-IP Lite month, default current UTC YYYY-MM.
  LITEWAF_GEOIP_DBIP_EDITION   country or city, default country.
  LITEWAF_GEOIP_SOURCE_URL     Override the DB-IP CSV.gz download URL.
  LITEWAF_GEOIP_CHINA_ENABLED=0
                                Do not download or enable ip2region China data.
  LITEWAF_GEOIP_CHINA_SOURCE_URL
                                Override the ip2region_v4.xdb download URL.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '==> %s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

download() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 2 --retry-delay 2 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$url"
  else
    die "required command not found: curl or wget"
  fi
}

download_dbip_data() {
  dest="$1"
  if download "$SOURCE_URL" "$dest"; then
    return 0
  fi
  [ -z "$CUSTOM_SOURCE_URL" ] || die "failed to download configured GeoIP source: $SOURCE_URL"
  if previous_month="$(date -u -d "$SOURCE_MONTH-15 -1 month" +%Y-%m 2>/dev/null)"; then
    fallback_url="https://download.db-ip.com/free/dbip-$DBIP_EDITION-lite-$previous_month.csv.gz"
    warn "failed to download $SOURCE_MONTH data; trying $previous_month"
    SOURCE_MONTH="$previous_month"
    SOURCE_URL="$fallback_url"
    download "$SOURCE_URL" "$dest"
    return 0
  fi
  die "failed to download GeoIP data: $SOURCE_URL"
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

append_dbip_csv() {
  input="$1"
  output="$2"
  gzip -cd "$input" | awk -F, -v edition="$DBIP_EDITION" '
    NF >= 3 {
      start_ip=$1
      end_ip=$2
      if (edition == "city") {
        country_code=$4
        region=$5
      } else {
        country_code=$3
        region=""
      }
      gsub(/^"|"$/, "", start_ip)
      gsub(/^"|"$/, "", end_ip)
      gsub(/"/, "", country_code)
      gsub(/"/, "", region)
      if (start_ip != "" && end_ip != "" && country_code != "" && country_code != "ZZ") {
        printf "%s,%s,%s,%s,,,,db-ip-lite,dbip-city\n", start_ip, end_ip, country_code, region
      }
    }
  ' >>"$output"
}

restart_api() {
  [ "$RESTART_API" = "1" ] || return 0
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker is unavailable; restart LiteWaf API manually"
    return 0
  fi
  if [ ! -f "$INSTALL_DIR/$COMPOSE_FILE" ]; then
    warn "compose file not found; restart LiteWaf API manually"
    return 0
  fi
  if [ ! -f "$ENV_FILE" ]; then
    warn "env file not found; restart LiteWaf API manually"
    return 0
  fi

  files="${COMPOSE_FILES:-$COMPOSE_FILE}"
  file_args=""
  for file in $files; do
    file_args="$file_args -f $file"
  done

  info "restarting LiteWaf API to load GeoIP data"
  # shellcheck disable=SC2086
  (cd "$INSTALL_DIR" && docker compose -p "$PROJECT_NAME" --env-file "$ENV_FILE" $file_args up -d --no-build waf-api)
  # File content changes in the bind-mounted GeoIP directory do not change the
  # Compose service definition, so force a process restart to reload the CSV.
  # shellcheck disable=SC2086
  (cd "$INSTALL_DIR" && docker compose -p "$PROJECT_NAME" --env-file "$ENV_FILE" $file_args restart waf-api)
}

cmd="${1:-update}"
case "$cmd" in
  init|update)
    ;;
  ""|-h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    die "unknown command: $cmd"
    ;;
esac

need_cmd awk
need_cmd gzip
need_cmd mktemp

[ -f "$ENV_FILE" ] || die "env file not found: $ENV_FILE"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

mkdir -p "$DATA_DIR"
chmod 755 "$DATA_DIR" 2>/dev/null || true

info "downloading DB-IP Lite $DBIP_EDITION data: $SOURCE_MONTH"
download_dbip_data "$tmp_dir/dbip-lite.csv.gz"

if [ "$CHINA_ENABLED" = "1" ]; then
  info "downloading ip2region China IPv4 data"
  download "$CHINA_SOURCE_URL" "$tmp_dir/ip2region_v4.xdb" || die "failed to download ip2region China data: $CHINA_SOURCE_URL"
fi

output="$tmp_dir/geoip.csv"
printf 'start_ip,end_ip,country_code,region,city,longitude,latitude,source,version\n' >"$output"
append_dbip_csv "$tmp_dir/dbip-lite.csv.gz" "$output"

if [ "$(wc -l <"$output" | tr -d ' ')" -le 1 ]; then
  die "downloaded GeoIP data produced no usable rows"
fi

mv "$output" "$DATA_DIR/geoip.csv.tmp"
chmod 644 "$DATA_DIR/geoip.csv.tmp" 2>/dev/null || true
mv "$DATA_DIR/geoip.csv.tmp" "$DATA_DIR/geoip.csv"

if [ "$CHINA_ENABLED" = "1" ]; then
  mv "$tmp_dir/ip2region_v4.xdb" "$DATA_DIR/ip2region_v4.xdb.tmp"
  chmod 644 "$DATA_DIR/ip2region_v4.xdb.tmp" 2>/dev/null || true
  mv "$DATA_DIR/ip2region_v4.xdb.tmp" "$DATA_DIR/ip2region_v4.xdb"
fi

cat >"$DATA_DIR/ATTRIBUTION.txt" <<'EOF'
LiteWaf GeoIP data source:
DB-IP Lite data from https://db-ip.com/db/download/.
License: Creative Commons Attribution 4.0 International (CC BY 4.0).
Attribution: IP Geolocation by DB-IP (https://db-ip.com/).
EOF

if [ "$CHINA_ENABLED" = "1" ]; then
  cat >>"$DATA_DIR/ATTRIBUTION.txt" <<'EOF'
ip2region IPv4 data from https://github.com/lionsoul2014/ip2region.
License: Apache License 2.0.
EOF
fi

set_env_key LITEWAF_GEOIP_DB_PATH "$CONTAINER_DB_PATH" "$ENV_FILE"
if [ "$CHINA_ENABLED" = "1" ]; then
  set_env_key LITEWAF_GEOIP_CHINA_DB_PATH "$CONTAINER_CHINA_DB_PATH" "$ENV_FILE"
else
  set_env_key LITEWAF_GEOIP_CHINA_DB_PATH "" "$ENV_FILE"
fi
set_env_key LITEWAF_GEOIP_CACHE_SIZE "${LITEWAF_GEOIP_CACHE_SIZE:-2048}" "$ENV_FILE"

info "GeoIP CSV installed: $DATA_DIR/geoip.csv"
info "GeoIP container path: $CONTAINER_DB_PATH"
if [ "$CHINA_ENABLED" = "1" ]; then
  info "GeoIP China xdb installed: $DATA_DIR/ip2region_v4.xdb"
  info "GeoIP China container path: $CONTAINER_CHINA_DB_PATH"
fi
info "DB-IP attribution written: $DATA_DIR/ATTRIBUTION.txt"
restart_api
