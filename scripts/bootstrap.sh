#!/usr/bin/env sh
set -eu

PROJECT_NAME="sing-box-next-panel"
REPO_URL="${MI_PANEL_REPO_URL:-https://github.com/3582730951/MI_Proxy.git}"
BRANCH="${MI_PANEL_BRANCH:-main}"
INSTALL_DIR="${MI_PANEL_INSTALL_DIR:-/opt/sing-box-next-panel}"
PASSWD_FILE="${PASSWD_FILE:-}"
CONFIG_FILE=""
META_FILE="/etc/$PROJECT_NAME/install.env"
REPO_URL_CONFIGURED=0
BRANCH_CONFIGURED=0
INSTALL_DIR_CONFIGURED=0
PASSWD_FILE_CONFIGURED=0
BIND_CONFIGURED=0
[ -z "${MI_PANEL_REPO_URL:-}" ] || REPO_URL_CONFIGURED=1
[ -z "${MI_PANEL_BRANCH:-}" ] || BRANCH_CONFIGURED=1
[ -z "${MI_PANEL_INSTALL_DIR:-}" ] || INSTALL_DIR_CONFIGURED=1
[ -z "$PASSWD_FILE" ] || PASSWD_FILE_CONFIGURED=1

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
  scripts/bootstrap.sh [install options] [KEY=VALUE...]

This bootstrapper is intended for one-command VPS installs. It installs only the
minimum tools required to clone the repository, then delegates to scripts/install.sh.
When no bind option is provided, the GitHub bootstrap path defaults to public HTTP
binding. Use -l, --local, --host, or HOST=127.0.0.1 to force localhost binding.
If an older install exists, the bootstrapper reuses /etc/sing-box-next-panel/install.env
when present, then upgrades the existing checkout with the newest installer.

Common examples:
  scripts/bootstrap.sh
  scripts/bootstrap.sh -l
  scripts/bootstrap.sh -k PORT=8080
  scripts/bootstrap.sh --passwd-file /etc/sing-box-next-panel/passwd.txt

Supported bootstrap keys:
  REPO_URL BRANCH INSTALL_DIR HOST PASSWD_FILE
EOF
}

apply_kv_for_bootstrap() {
  key=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
  value=$2
  case "$key" in
    REPO_URL|MI_PANEL_REPO_URL) REPO_URL=$value; REPO_URL_CONFIGURED=1 ;;
    BRANCH|MI_PANEL_BRANCH) BRANCH=$value; BRANCH_CONFIGURED=1 ;;
    INSTALL_DIR|MI_PANEL_INSTALL_DIR) INSTALL_DIR=$value; INSTALL_DIR_CONFIGURED=1 ;;
    PASSWD_FILE|MI_PANEL_PASSWD_FILE) PASSWD_FILE=$value; PASSWD_FILE_CONFIGURED=1; export PASSWD_FILE ;;
    HOST) BIND_CONFIGURED=1 ;;
    PORT|POSTGRES_BIND|REDIS_BIND|AUTO_UPDATE) ;;
    *) ;;
  esac
}

load_config_file_for_bootstrap() {
  file=$1
  [ -f "$file" ] || die "config file not found: $file"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue ;;
      *=*) apply_kv_for_bootstrap "${line%%=*}" "${line#*=}" ;;
      *) die "invalid config line: $line" ;;
    esac
  done < "$file"
}

scan_args_for_bootstrap() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --repo-url) [ $# -ge 2 ] || die "--repo-url requires a value"; REPO_URL=$2; REPO_URL_CONFIGURED=1; shift 2 ;;
      --branch) [ $# -ge 2 ] || die "--branch requires a value"; BRANCH=$2; BRANCH_CONFIGURED=1; shift 2 ;;
      --install-dir) [ $# -ge 2 ] || die "--install-dir requires a value"; INSTALL_DIR=$2; INSTALL_DIR_CONFIGURED=1; shift 2 ;;
      --passwd-file) [ $# -ge 2 ] || die "--passwd-file requires a value"; PASSWD_FILE=$2; PASSWD_FILE_CONFIGURED=1; export PASSWD_FILE; shift 2 ;;
      -f|--file) [ $# -ge 2 ] || die "--file requires a path"; CONFIG_FILE=$2; shift 2 ;;
      -l|--local|-k|--public) BIND_CONFIGURED=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *=*) apply_kv_for_bootstrap "${1%%=*}" "${1#*=}"; shift ;;
      --host) [ $# -ge 2 ] || die "$1 requires a value"; BIND_CONFIGURED=1; shift 2 ;;
      --port) [ $# -ge 2 ] || die "$1 requires a value"; shift 2 ;;
      *) shift ;;
    esac
  done
  [ -z "$CONFIG_FILE" ] || load_config_file_for_bootstrap "$CONFIG_FILE"
}

apply_metadata_default() {
  key=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
  value=$2
  [ -n "$value" ] || return 0
  case "$key" in
    REPO_URL|MI_PANEL_REPO_URL) [ "$REPO_URL_CONFIGURED" = "1" ] || REPO_URL=$value ;;
    BRANCH|MI_PANEL_BRANCH) [ "$BRANCH_CONFIGURED" = "1" ] || BRANCH=$value ;;
    INSTALL_DIR|MI_PANEL_INSTALL_DIR) [ "$INSTALL_DIR_CONFIGURED" = "1" ] || INSTALL_DIR=$value ;;
    PASSWD_FILE|MI_PANEL_PASSWD_FILE)
      if [ "$PASSWD_FILE_CONFIGURED" != "1" ]; then
        PASSWD_FILE=$value
        export PASSWD_FILE
      fi
      ;;
    *) ;;
  esac
}

load_existing_metadata_for_bootstrap() {
  [ -f "$META_FILE" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue ;;
      *=*) apply_metadata_default "${line%%=*}" "${line#*=}" ;;
      *) ;;
    esac
  done < "$META_FILE"
  log "detected existing install metadata at $META_FILE; target install dir is $INSTALL_DIR"
}

install_git_if_missing() {
  if command -v git >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    env DEBIAN_FRONTEND=noninteractive apt-get update
    env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates git
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates git
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates git
  else
    die "git is missing and no supported package manager was found"
  fi
}

bootstrap_checkout() {
  workdir=$(mktemp -d "${TMPDIR:-/tmp}/${PROJECT_NAME}.bootstrap.XXXXXX")
  trap 'rm -rf "$workdir"' EXIT INT TERM
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$workdir"
  if [ "$BIND_CONFIGURED" = "1" ]; then
    MI_PANEL_REPO_URL=$REPO_URL \
    MI_PANEL_BRANCH=$BRANCH \
    MI_PANEL_INSTALL_DIR=$INSTALL_DIR \
      sh "$workdir/scripts/install.sh" "$@"
  else
    MI_PANEL_REPO_URL=$REPO_URL \
    MI_PANEL_BRANCH=$BRANCH \
    MI_PANEL_INSTALL_DIR=$INSTALL_DIR \
      sh "$workdir/scripts/install.sh" --public "$@"
  fi
}

scan_args_for_bootstrap "$@"
load_existing_metadata_for_bootstrap
log "starting $PROJECT_NAME bootstrap; install dir is $INSTALL_DIR"
install_git_if_missing
log "bootstrapping $PROJECT_NAME from $REPO_URL branch $BRANCH"
bootstrap_checkout "$@"
