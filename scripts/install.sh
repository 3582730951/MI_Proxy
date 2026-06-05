#!/usr/bin/env sh
set -eu

PROJECT_NAME="sing-box-next-panel"
REPO_URL="${MI_PANEL_REPO_URL:-https://github.com/3582730951/MI_Proxy.git}"
BRANCH="${MI_PANEL_BRANCH:-main}"
INSTALL_DIR="${MI_PANEL_INSTALL_DIR:-/opt/sing-box-next-panel}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
POSTGRES_BIND="${POSTGRES_BIND:-127.0.0.1}"
REDIS_BIND="${REDIS_BIND:-127.0.0.1}"
AUTO_UPDATE="${AUTO_UPDATE:-1}"
PASSWD_FILE="${PASSWD_FILE:-}"
HOST_CONFIGURED=0
PORT_CONFIGURED=0
PASSWD_FILE_CONFIGURED=0
[ -z "$PASSWD_FILE" ] || PASSWD_FILE_CONFIGURED=1
SKIP_DEPS=0
NO_SYSTEMD=0
DRY_RUN=0
COMMAND="install"
CONFIG_FILE=""
PREVIOUS_REVISION=""

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  scripts/install.sh [install|update] [options] [KEY=VALUE...]

Zero-interaction VPS install:
  scripts/install.sh
  scripts/install.sh -l
  scripts/install.sh -k PORT=8080
  scripts/install.sh -f install.conf

Options:
  -l, --local            bind admin HTTP port to 127.0.0.1
  -k, --public           bind admin HTTP port to 0.0.0.0
  -f, --file PATH        load KEY=VALUE config file
      --repo-url URL     git repository to deploy
      --branch NAME      git branch to deploy
      --install-dir DIR  target directory
      --host HOST        bind host, defaults to 127.0.0.1
      --port PORT        bind port, defaults to 8080
      --passwd-file PATH write generated passwords to PATH, defaults to INSTALL_DIR/passwd.txt
      --skip-deps        skip package installation
      --no-systemd       skip service and auto-update timer registration
      --no-auto-update   do not register the update timer
      --dry-run          print actions without changing the host
  -h, --help             show this help

Supported KEY=VALUE names:
  REPO_URL BRANCH INSTALL_DIR HOST PORT POSTGRES_BIND REDIS_BIND AUTO_UPDATE PASSWD_FILE
EOF
}

apply_kv() {
  key=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
  value=$2
  case "$key" in
    REPO_URL|MI_PANEL_REPO_URL) REPO_URL=$value ;;
    BRANCH|MI_PANEL_BRANCH) BRANCH=$value ;;
    INSTALL_DIR|MI_PANEL_INSTALL_DIR) INSTALL_DIR=$value ;;
    HOST) HOST=$value; HOST_CONFIGURED=1 ;;
    PORT) PORT=$value; PORT_CONFIGURED=1 ;;
    POSTGRES_BIND) POSTGRES_BIND=$value ;;
    REDIS_BIND) REDIS_BIND=$value ;;
    AUTO_UPDATE) AUTO_UPDATE=$value ;;
    PASSWD_FILE|MI_PANEL_PASSWD_FILE) PASSWD_FILE=$value; PASSWD_FILE_CONFIGURED=1 ;;
    *) die "unknown config key $1" ;;
  esac
}

load_config_file() {
  file=$1
  [ -f "$file" ] || die "config file not found: $file"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue ;;
      *=*) apply_kv "${line%%=*}" "${line#*=}" ;;
      *) die "invalid config line: $line" ;;
    esac
  done < "$file"
}

while [ $# -gt 0 ]; do
  case "$1" in
    install|update) COMMAND=$1; shift ;;
    -l|--local) HOST="127.0.0.1"; HOST_CONFIGURED=1; shift ;;
    -k|--public) HOST="0.0.0.0"; HOST_CONFIGURED=1; shift ;;
    -f|--file) [ $# -ge 2 ] || die "--file requires a path"; CONFIG_FILE=$2; shift 2 ;;
    --repo-url) [ $# -ge 2 ] || die "--repo-url requires a value"; REPO_URL=$2; shift 2 ;;
    --branch) [ $# -ge 2 ] || die "--branch requires a value"; BRANCH=$2; shift 2 ;;
    --install-dir) [ $# -ge 2 ] || die "--install-dir requires a value"; INSTALL_DIR=$2; shift 2 ;;
    --host) [ $# -ge 2 ] || die "--host requires a value"; HOST=$2; HOST_CONFIGURED=1; shift 2 ;;
    --port) [ $# -ge 2 ] || die "--port requires a value"; PORT=$2; PORT_CONFIGURED=1; shift 2 ;;
    --passwd-file) [ $# -ge 2 ] || die "--passwd-file requires a value"; PASSWD_FILE=$2; PASSWD_FILE_CONFIGURED=1; shift 2 ;;
    --skip-deps) SKIP_DEPS=1; shift ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    --no-auto-update) AUTO_UPDATE=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *=*) apply_kv "${1%%=*}" "${1#*=}"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -z "$CONFIG_FILE" ] || load_config_file "$CONFIG_FILE"

ENV_FILE="$INSTALL_DIR/.env"
[ -n "$PASSWD_FILE" ] || PASSWD_FILE="$INSTALL_DIR/passwd.txt"
META_DIR="/etc/$PROJECT_NAME"
META_FILE="$META_DIR/install.env"

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf '+'
    for arg in "$@"; do
      printf ' %s' "$arg"
    done
    printf '\n'
    return 0
  fi
  "$@"
}

require_root_for_vps() {
  uid=$(id -u 2>/dev/null || printf '1')
  if [ "$uid" = "0" ]; then
    return
  fi
  case "$INSTALL_DIR" in
    /opt/*|/usr/*|/var/*|/etc/*) die "run as root for zero-interaction VPS install into $INSTALL_DIR" ;;
  esac
  if [ "$SKIP_DEPS" != "1" ] || [ "$NO_SYSTEMD" != "1" ]; then
    die "run as root, or pass --skip-deps --no-systemd for a user-local install"
  fi
}

compose_v2_available() {
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1
}

compose_legacy_v1_available() {
  ! compose_v2_available && command -v docker-compose >/dev/null 2>&1
}

install_packages() {
  [ "$SKIP_DEPS" = "0" ] || return 0
  if command -v docker >/dev/null 2>&1 && compose_v2_available && command -v git >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    run env DEBIAN_FRONTEND=noninteractive apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git docker.io curl
    if ! compose_v2_available; then
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-compose-plugin || {
        command -v docker-compose >/dev/null 2>&1 || run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker-compose
      }
    fi
  elif command -v dnf >/dev/null 2>&1; then
    run dnf install -y ca-certificates git docker curl
    run dnf install -y docker-compose-plugin || run dnf install -y docker-compose
  elif command -v yum >/dev/null 2>&1; then
    run yum install -y ca-certificates git docker curl
    run yum install -y docker-compose-plugin || run yum install -y docker-compose
  elif command -v apk >/dev/null 2>&1; then
    run apk add --no-cache ca-certificates git docker docker-cli-compose curl
  elif command -v pacman >/dev/null 2>&1; then
    run pacman -Sy --noconfirm ca-certificates git docker docker-compose curl
  else
    die "unsupported package manager; install git, Docker, and Docker Compose first or pass --skip-deps"
  fi
}

start_docker_service() {
  if [ "$SKIP_DEPS" = "1" ]; then
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl enable --now docker || true
  elif command -v service >/dev/null 2>&1; then
    run service docker start || true
  elif command -v rc-service >/dev/null 2>&1; then
    run rc-update add docker default || true
    run rc-service docker start || true
  fi
}

clone_or_update_repo() {
  parent=$(dirname "$INSTALL_DIR")
  run mkdir -p "$parent"
  if [ -d "$INSTALL_DIR/.git" ]; then
    PREVIOUS_REVISION=$(current_revision)
    run git -C "$INSTALL_DIR" fetch --prune origin "$BRANCH"
    run git -C "$INSTALL_DIR" checkout "$BRANCH"
    run git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
    return 0
  fi
  if [ -e "$INSTALL_DIR" ] && [ "$(ls -A "$INSTALL_DIR" 2>/dev/null || true)" ]; then
    die "$INSTALL_DIR exists and is not an empty git checkout"
  fi
  run git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
}

current_revision() {
  git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || true
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  else
    die "secure random source unavailable"
  fi
}

read_kv_value() {
  file=$1
  var=$2
  if [ -f "$file" ]; then
    value=$(sed -n "s/^${var}=//p" "$file" | tail -n 1)
    if [ -n "$value" ]; then
      printf '%s' "$value"
      return
    fi
  fi
  return 0
}

read_env_value() {
  var=$1
  fallback=$2
  value=$(read_kv_value "$ENV_FILE" "$var")
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return
  fi
  printf '%s' "$fallback"
}

read_password_value() {
  var=$1
  fallback=$2
  value=$(read_kv_value "$PASSWD_FILE" "$var")
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return
  fi
  value=$(read_kv_value "$ENV_FILE" "$var")
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return
  fi
  printf '%s' "$fallback"
}

write_passwd_file() {
  if [ "$DRY_RUN" = "1" ]; then
    log "would write password file at $PASSWD_FILE"
    return
  fi
  parent=$(dirname "$PASSWD_FILE")
  mkdir -p "$parent"
  current_secret=$(read_password_value POSTGRES_PASSWORD "${POSTGRES_PASSWORD:-}")
  [ -n "$current_secret" ] || current_secret=$(generate_secret)
  tmp="$PASSWD_FILE.tmp.$$"
  umask 077
  {
    printf 'POSTGRES_PASSWORD=%s\n' "$current_secret"
  } > "$tmp"
  mv "$tmp" "$PASSWD_FILE"
  chmod 600 "$PASSWD_FILE"
}

write_env_file() {
  if [ "$DRY_RUN" = "1" ]; then
    log "would write $ENV_FILE with runtime settings"
    return
  fi
  mkdir -p "$INSTALL_DIR"
  if [ "$HOST_CONFIGURED" = "1" ]; then
    current_host=$HOST
  else
    current_host=$(read_env_value HOST "$HOST")
  fi
  if [ "$PORT_CONFIGURED" = "1" ]; then
    current_port=$PORT
  else
    current_port=$(read_env_value PORT "$PORT")
  fi
  current_pg_bind=$(read_env_value POSTGRES_BIND "$POSTGRES_BIND")
  current_redis_bind=$(read_env_value REDIS_BIND "$REDIS_BIND")
  if [ "$PASSWD_FILE_CONFIGURED" = "1" ]; then
    current_passwd_file=$PASSWD_FILE
  else
    current_passwd_file=$(read_env_value PASSWD_FILE "$PASSWD_FILE")
  fi
  tmp="$ENV_FILE.tmp.$$"
  umask 077
  {
    printf 'HOST=%s\n' "$current_host"
    printf 'PORT=%s\n' "$current_port"
    printf 'POSTGRES_BIND=%s\n' "$current_pg_bind"
    printf 'REDIS_BIND=%s\n' "$current_redis_bind"
    printf 'PASSWD_FILE=%s\n' "$current_passwd_file"
  } > "$tmp"
  mv "$tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  HOST=$current_host
  PORT=$current_port
  POSTGRES_BIND=$current_pg_bind
  REDIS_BIND=$current_redis_bind
  PASSWD_FILE=$current_passwd_file
}

load_env_file() {
  [ -f "$ENV_FILE" ] || die "missing $ENV_FILE"
  set -a
  . "$ENV_FILE"
  [ -f "$PASSWD_FILE" ] || die "missing $PASSWD_FILE"
  . "$PASSWD_FILE"
  set +a
}

compose() {
  if compose_v2_available; then
    run docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    run docker-compose "$@"
  else
    die "Docker Compose is unavailable"
  fi
}

compose_down_for_legacy_v1() {
  if compose_legacy_v1_available; then
    log "legacy docker-compose v1 detected; removing old containers before rebuild to avoid ContainerConfig compatibility errors"
    compose down --remove-orphans
  fi
}

start_stack() {
  if [ "$DRY_RUN" = "1" ]; then
    log "would start Docker Compose stack in $INSTALL_DIR"
    return 0
  fi
  load_env_file
  old_pwd=$(pwd)
  cd "$INSTALL_DIR"
  compose_down_for_legacy_v1
  compose up --build -d --remove-orphans
  cd "$old_pwd"
}

health_check() {
  [ "$DRY_RUN" = "0" ] || return 0
  url="http://127.0.0.1:${PORT}/healthz"
  i=0
  while [ "$i" -lt 60 ]; do
    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return
    fi
    if command -v wget >/dev/null 2>&1 && wget -q -T 2 -O - "$url" >/dev/null 2>&1; then
      return
    fi
    sleep 2
    i=$((i + 1))
  done
  return 1
}

rollback_to_previous_revision() {
  [ -n "$PREVIOUS_REVISION" ] || return 1
  log "install/update health check failed; rolling back to $PREVIOUS_REVISION"
  run git -C "$INSTALL_DIR" checkout "$PREVIOUS_REVISION"
  start_stack
  health_check
}

write_metadata() {
  [ "$DRY_RUN" = "0" ] || return 0
  mkdir -p "$META_DIR"
  tmp="$META_FILE.tmp.$$"
  {
    printf 'INSTALL_DIR=%s\n' "$INSTALL_DIR"
    printf 'REPO_URL=%s\n' "$REPO_URL"
    printf 'BRANCH=%s\n' "$BRANCH"
    printf 'PASSWD_FILE=%s\n' "$PASSWD_FILE"
  } > "$tmp"
  mv "$tmp" "$META_FILE"
  chmod 644 "$META_FILE"
}

write_systemd_units() {
  [ "$NO_SYSTEMD" = "0" ] || return 0
  command -v systemctl >/dev/null 2>&1 || return 0
  [ "$DRY_RUN" = "0" ] || { log "would write systemd service and update timer"; return; }
  docker_bin=$(command -v docker || printf '/usr/bin/docker')
  compose_start=""
  if "$docker_bin" compose version >/dev/null 2>&1; then
    compose_exec="$docker_bin compose"
    compose_start="ExecStart=$compose_exec up --build -d --remove-orphans"
  elif command -v docker-compose >/dev/null 2>&1; then
    compose_exec=$(command -v docker-compose)
    compose_start="ExecStart=/bin/sh -c '$compose_exec down --remove-orphans || true; $compose_exec up --build -d --remove-orphans'"
  else
    die "Docker Compose is unavailable for systemd service registration"
  fi
  cat > "/etc/systemd/system/$PROJECT_NAME.service" <<EOF
[Unit]
Description=sing-box-next-panel Docker Compose stack
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
EnvironmentFile=$PASSWD_FILE
$compose_start
ExecStop=$compose_exec down
RemainAfterExit=yes
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
  cat > "/etc/systemd/system/$PROJECT_NAME-update.service" <<EOF
[Unit]
Description=Update sing-box-next-panel from git and restart safely
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
ExecStart=/bin/sh $INSTALL_DIR/scripts/update.sh --install-dir $INSTALL_DIR --repo-url $REPO_URL --branch $BRANCH --passwd-file $PASSWD_FILE --skip-deps --no-systemd
EOF
  cat > "/etc/systemd/system/$PROJECT_NAME-update.timer" <<'EOF'
[Unit]
Description=Periodic sing-box-next-panel auto update

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
EOF
  run systemctl daemon-reload
  run systemctl enable "$PROJECT_NAME.service"
  if [ "$AUTO_UPDATE" = "1" ]; then
    run systemctl enable --now "$PROJECT_NAME-update.timer"
  fi
}

run_update() {
  if [ -f "$META_FILE" ]; then
    . "$META_FILE"
  fi
  if [ -x "$INSTALL_DIR/scripts/update.sh" ]; then
    run "$INSTALL_DIR/scripts/update.sh" --install-dir "$INSTALL_DIR" --repo-url "$REPO_URL" --branch "$BRANCH" --passwd-file "$PASSWD_FILE" --skip-deps --no-systemd
  else
    die "update script not found at $INSTALL_DIR/scripts/update.sh"
  fi
}

require_root_for_vps

case "$COMMAND" in
  install)
    install_packages
    start_docker_service
    clone_or_update_repo
    write_env_file
    write_passwd_file
    write_metadata
    start_stack
    write_systemd_units
    if health_check; then
      log "$PROJECT_NAME is running at http://$HOST:$PORT"
      exit 0
    fi
    if rollback_to_previous_revision; then
      die "new version failed health check and was rolled back to $PREVIOUS_REVISION"
    fi
    die "service did not become healthy at http://127.0.0.1:${PORT}/healthz"
    ;;
  update)
    run_update
    ;;
  *) die "unknown command $COMMAND" ;;
esac
