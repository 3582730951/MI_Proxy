# VPS deployment

## Zero-interaction install

Run this one-command bootstrapper from a root shell on a fresh VPS when direct public HTTP access is required. Re-run the same command on an older install to upgrade it with the latest installer:

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp"
```

The GitHub bootstrap path defaults the admin HTTP port to `0.0.0.0`, so the panel is reachable at `http://<VPS_PUBLIC_IP>:8080` after the host firewall and cloud security group allow TCP 8080. The control plane serves the bundled `apps/web` dashboard at `/`, while `/healthz` remains the deployment health endpoint. The bootstrapper installs only the minimum clone dependency when needed, checks out the repository into a temporary directory, and delegates to `scripts/install.sh` with the same arguments. For example:

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" -l
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" --passwd-file /etc/sing-box-next-panel/passwd.txt
```

For older installs, the bootstrapper reads `/etc/sing-box-next-panel/install.env` when present, preserves the recorded install directory and password file, fast-forwards the existing git checkout, restarts the stack, checks `/healthz`, and rolls back to the previous commit if the upgraded stack does not become healthy.

Run the installer from a checked-out repository on a fresh VPS:

```sh
scripts/install.sh
```

Default behavior is noninteractive and secure:

- installs Git, Docker, and Docker Compose through the host package manager when missing;
- clones or fast-forwards the configured repository into `/opt/sing-box-next-panel`;
- writes non-secret runtime settings to `.env`;
- writes generated passwords to `passwd.txt` in the runtime directory with mode `0600`;
- binds the admin HTTP port to `127.0.0.1:8080` by default;
- starts the Docker Compose stack;
- registers a systemd service and a periodic auto-update timer when systemd is available.

Quick modes:

```sh
scripts/install.sh -l
scripts/install.sh -k PORT=8080
scripts/install.sh -f install.conf
scripts/install.sh REPO_URL=https://github.com/3582730951/MI_Proxy.git BRANCH=main PORT=8088
scripts/install.sh --passwd-file /etc/sing-box-next-panel/passwd.txt
```

Use `-k` only behind VPN, Zero Trust, or an mTLS/TLS gateway. Admin APIs still require authentication, but the safer default is localhost binding.

Supported config keys:

```text
REPO_URL=https://github.com/3582730951/MI_Proxy.git
BRANCH=main
INSTALL_DIR=/opt/sing-box-next-panel
HOST=127.0.0.1
PORT=8080
POSTGRES_BIND=127.0.0.1
REDIS_BIND=127.0.0.1
AUTO_UPDATE=1
PASSWD_FILE=/opt/sing-box-next-panel/passwd.txt
```

Password file format:

```text
POSTGRES_PASSWORD=<generated-secret>
```

Additional generated passwords must be added to the same file as `KEY=VALUE` entries. The installer and updater load `.env` first and then `PASSWD_FILE`, so Docker Compose receives secrets through the process environment without printing them.

The project intentionally does not document pipe-to-shell installation. The bootstrapper downloads to a local temporary file before execution so the command stays inspectable and compatible with security scanning.

## Updates

Manual update:

```sh
scripts/update.sh --install-dir /opt/sing-box-next-panel --repo-url https://github.com/3582730951/MI_Proxy.git --branch main
scripts/update.sh --install-dir /opt/sing-box-next-panel --passwd-file /etc/sing-box-next-panel/passwd.txt
```

The update script:

- takes a lock so two updates cannot run at once;
- fetches the configured branch and applies only fast-forward updates;
- preserves `.env` and Docker volumes;
- rebuilds and restarts the Compose stack;
- checks `/healthz`;
- rolls back to the previous commit if deployment or health checking fails.

When `AUTO_UPDATE=1`, `scripts/install.sh` creates `sing-box-next-panel-update.timer`, which runs the same update path periodically with a randomized delay.

To switch an existing deployment to public HTTP binding:

```sh
/opt/sing-box-next-panel/scripts/install.sh -k PORT=8080
```

To switch back to localhost-only binding:

```sh
/opt/sing-box-next-panel/scripts/install.sh -l PORT=8080
```
