#!/usr/bin/env sh
set -eu

PROJECT_NAME="sing-box-next-panel"
REPO_URL="${MI_PANEL_REPO_URL:-https://github.com/3582730951/MI_Proxy.git}"
BRANCH="${MI_PANEL_BRANCH:-main}"
INSTALL_DIR="${MI_PANEL_INSTALL_DIR:-/opt/sing-box-next-panel}"
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
  scripts/bootstrap.sh [install options] [KEY=VALUE...]

This bootstrapper is intended for one-command VPS installs. It installs only the
minimum tools required to clone the repository, then delegates to scripts/install.sh.

Common examples:
  scripts/bootstrap.sh
  scripts/bootstrap.sh -l
  scripts/bootstrap.sh -k PORT=8080
  scripts/bootstrap.sh --passwd-file /etc/sing-box-next-panel/passwd.txt

Supported bootstrap keys:
  REPO_URL BRANCH INSTALL_DIR PASSWD_FILE
EOF
}

apply_kv_for_bootstrap() {
  key=$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')
  value=$2
  case "$key" in
    REPO_URL|MI_PANEL_REPO_URL) REPO_URL=$value ;;
    BRANCH|MI_PANEL_BRANCH) BRANCH=$value ;;
    INSTALL_DIR|MI_PANEL_INSTALL_DIR) INSTALL_DIR=$value ;;
    PASSWD_FILE|MI_PANEL_PASSWD_FILE) PASSWD_FILE=$value; export PASSWD_FILE ;;
    HOST|PORT|POSTGRES_BIND|REDIS_BIND|AUTO_UPDATE) ;;
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
      --repo-url) [ $# -ge 2 ] || die "--repo-url requires a value"; REPO_URL=$2; shift 2 ;;
      --branch) [ $# -ge 2 ] || die "--branch requires a value"; BRANCH=$2; shift 2 ;;
      --install-dir) [ $# -ge 2 ] || die "--install-dir requires a value"; INSTALL_DIR=$2; shift 2 ;;
      --passwd-file) [ $# -ge 2 ] || die "--passwd-file requires a value"; PASSWD_FILE=$2; export PASSWD_FILE; shift 2 ;;
      -f|--file) [ $# -ge 2 ] || die "--file requires a path"; CONFIG_FILE=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *=*) apply_kv_for_bootstrap "${1%%=*}" "${1#*=}"; shift ;;
      --host|--port) [ $# -ge 2 ] || die "$1 requires a value"; shift 2 ;;
      *) shift ;;
    esac
  done
  [ -z "$CONFIG_FILE" ] || load_config_file_for_bootstrap "$CONFIG_FILE"
}

install_git_if_missing() {
  if command -v git >/dev/null 2>&1; then
    return
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
  MI_PANEL_REPO_URL=$REPO_URL \
  MI_PANEL_BRANCH=$BRANCH \
  MI_PANEL_INSTALL_DIR=$INSTALL_DIR \
    sh "$workdir/scripts/install.sh" "$@"
}

scan_args_for_bootstrap "$@"
install_git_if_missing
log "bootstrapping $PROJECT_NAME from $REPO_URL branch $BRANCH"
bootstrap_checkout "$@"
