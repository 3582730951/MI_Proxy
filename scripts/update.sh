#!/usr/bin/env sh
set -eu

PROJECT_NAME="sing-box-next-panel"
REPO_URL="${MI_PANEL_REPO_URL:-https://github.com/3582730951/MI_Proxy.git}"
BRANCH="${MI_PANEL_BRANCH:-main}"
INSTALL_DIR="${MI_PANEL_INSTALL_DIR:-/opt/sing-box-next-panel}"
PASSWD_FILE="${PASSWD_FILE:-}"
PASSWD_FILE_CONFIGURED=0
[ -z "$PASSWD_FILE" ] || PASSWD_FILE_CONFIGURED=1
SKIP_DEPS=1
NO_SYSTEMD=1
DRY_RUN=0
RESTART_ONLY=0
CONFIG_FILE=""

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
  scripts/update.sh [options] [KEY=VALUE...]

Options:
      --repo-url URL     git repository to update from
      --branch NAME      git branch to update
      --install-dir DIR  deployed checkout directory
      --passwd-file PATH load passwords from PATH, defaults to INSTALL_DIR/passwd.txt
      --restart-only     rebuild/restart without pulling git
  -f, --file PATH        load KEY=VALUE config file
      --dry-run          print actions without changing the host
      --skip-deps        accepted for timer compatibility
      --no-systemd       accepted for timer compatibility
  -h, --help             show this help

Supported KEY=VALUE names:
  REPO_URL BRANCH INSTALL_DIR PASSWD_FILE
EOF
}

apply_kv() {
  key=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
  value=$2
  case "$key" in
    REPO_URL|MI_PANEL_REPO_URL) REPO_URL=$value ;;
    BRANCH|MI_PANEL_BRANCH) BRANCH=$value ;;
    INSTALL_DIR|MI_PANEL_INSTALL_DIR) INSTALL_DIR=$value ;;
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
    --repo-url) [ $# -ge 2 ] || die "--repo-url requires a value"; REPO_URL=$2; shift 2 ;;
    --branch) [ $# -ge 2 ] || die "--branch requires a value"; BRANCH=$2; shift 2 ;;
    --install-dir) [ $# -ge 2 ] || die "--install-dir requires a value"; INSTALL_DIR=$2; shift 2 ;;
    --passwd-file) [ $# -ge 2 ] || die "--passwd-file requires a value"; PASSWD_FILE=$2; PASSWD_FILE_CONFIGURED=1; shift 2 ;;
    --restart-only) RESTART_ONLY=1; shift ;;
    -f|--file) [ $# -ge 2 ] || die "--file requires a path"; CONFIG_FILE=$2; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --skip-deps) SKIP_DEPS=1; shift ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *=*) apply_kv "${1%%=*}" "${1#*=}"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -z "$CONFIG_FILE" ] || load_config_file "$CONFIG_FILE"

ENV_FILE="$INSTALL_DIR/.env"
[ -n "$PASSWD_FILE" ] || PASSWD_FILE="$INSTALL_DIR/passwd.txt"
LOCK_PARENT="/var/lock"
LOCK_DIR="$LOCK_PARENT/$PROJECT_NAME.update.lock"
if [ "$(id -u 2>/dev/null || printf '1')" != "0" ]; then
  LOCK_PARENT="${TMPDIR:-/tmp}"
  LOCK_DIR="$LOCK_PARENT/$PROJECT_NAME.update.lock"
fi

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

acquire_lock() {
  [ "$DRY_RUN" = "0" ] || return 0
  mkdir -p "$LOCK_PARENT"
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    die "another update is already running"
  fi
  trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT INT TERM
}

load_env_file() {
  [ -f "$ENV_FILE" ] || die "missing $ENV_FILE; run scripts/install.sh first"
  configured_passwd_file=$PASSWD_FILE
  set -a
  . "$ENV_FILE"
  if [ "$PASSWD_FILE_CONFIGURED" = "1" ]; then
    PASSWD_FILE=$configured_passwd_file
  fi
  [ -n "$PASSWD_FILE" ] || PASSWD_FILE="$INSTALL_DIR/passwd.txt"
  [ -f "$PASSWD_FILE" ] || die "missing $PASSWD_FILE; run scripts/install.sh first"
  . "$PASSWD_FILE"
  set +a
}

compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    run docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    run docker-compose "$@"
  else
    die "Docker Compose is unavailable"
  fi
}

current_revision() {
  git -C "$INSTALL_DIR" rev-parse HEAD 2>/dev/null || true
}

update_repo() {
  [ -d "$INSTALL_DIR/.git" ] || die "$INSTALL_DIR is not a git checkout"
  if [ "$RESTART_ONLY" = "1" ]; then
    return 0
  fi
  run git -C "$INSTALL_DIR" fetch --prune origin "$BRANCH"
  run git -C "$INSTALL_DIR" checkout "$BRANCH"
  run git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
}

deploy_stack() {
  if [ "$DRY_RUN" = "1" ]; then
    log "would rebuild and restart Docker Compose stack in $INSTALL_DIR"
    return 0
  fi
  load_env_file
  old_pwd=$(pwd)
  cd "$INSTALL_DIR"
  compose up --build -d --remove-orphans
  cd "$old_pwd"
}

health_check() {
  [ "$DRY_RUN" = "0" ] || return 0
  url="http://127.0.0.1:${PORT:-8080}/healthz"
  i=0
  while [ "$i" -lt 60 ]; do
    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    if command -v wget >/dev/null 2>&1 && wget -q -T 2 -O - "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    i=$((i + 1))
  done
  return 1
}

rollback_to() {
  previous=$1
  [ -n "$previous" ] || return 1
  log "deploy failed; rolling back to $previous"
  run git -C "$INSTALL_DIR" checkout "$previous"
  deploy_stack
  health_check
}

acquire_lock
previous_revision=$(current_revision)
update_repo
new_revision=$(current_revision)
if [ "$previous_revision" = "$new_revision" ] && [ "$RESTART_ONLY" != "1" ]; then
  log "$PROJECT_NAME is already up to date at $new_revision"
fi
if deploy_stack && health_check; then
  log "$PROJECT_NAME updated successfully to $(current_revision)"
  exit 0
fi
rollback_to "$previous_revision"
die "update failed and rollback was required"
