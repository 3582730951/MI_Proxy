# MI Proxy VPS 一键部署

这是一个面向 sing-box 运维面板、规则编译、WARP 池、订阅生成和节点 Agent 的部署仓库。根目录提供了无交互 VPS 安装脚本，用户复制一条命令到 Linux VPS 上执行即可完成安装。

## 公网 HTTP 一条命令安装

如果要安装后直接通过 `http://<VPS_PUBLIC_IP>:8080` 访问，在新的 VPS 上使用 `root` 用户执行下面这一整行。已经安装过旧版本时，也执行同一条命令，它会自动升级到新版本：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp"
```

这条命令会：

- 下载 `scripts/bootstrap.sh` 到临时文件；
- 在缺少 Git 时自动安装最小依赖；
- 拉取 `https://github.com/3582730951/MI_Proxy.git` 的 `main` 分支；
- 调用 `scripts/install.sh` 完成无交互部署；
- 默认安装到 `/opt/sing-box-next-panel`；
- GitHub bootstrap 默认监听 `0.0.0.0:8080`，允许公网 IP HTTP 访问；
- 默认把生成的密码写入 `/opt/sing-box-next-panel/passwd.txt`；
- 默认创建 systemd 服务和自动更新 timer。
- 如果检测到旧安装的 `/etc/sing-box-next-panel/install.env`，会复用旧安装目录、仓库分支和密码文件路径；
- 如果旧安装目录已经是 git checkout，会执行快进更新、保留 `.env`、`passwd.txt` 和 Docker volume、重启服务并检查 `/healthz`；
- 如果新版本启动失败，会回滚到升级前的 commit。

如果 VPS 开启了系统防火墙或云厂商安全组，还需要放行 TCP 8080 端口。Ubuntu 常见命令：

```sh
ufw allow 8080/tcp
```

安装完成后访问：

```text
http://<VPS_PUBLIC_IP>:8080
```

控制面会直接在根路径提供 `apps/web` 运维面板；健康检查继续使用 `/healthz`。

面板默认是中文界面，使用账号密码登录。安装脚本会在密码文件里生成初始管理员账号：

```text
MI_PANEL_ADMIN_USER=admin
MI_PANEL_ADMIN_PASSWORD=<generated-secret>
MI_PANEL_DEFAULT_SUBSCRIPTION_TOKEN=<generated-secret>
```

浏览器打开面板后，用户名填 `MI_PANEL_ADMIN_USER` 的值，密码填 `MI_PANEL_ADMIN_PASSWORD` 的值。`POSTGRES_PASSWORD` 只给数据库使用，不是面板登录密码。

安装脚本也会生成一条默认订阅记录。订阅 token 属于敏感信息，不会在前端显示；需要给客户端导入时，在 VPS 上读取 `MI_PANEL_DEFAULT_SUBSCRIPTION_TOKEN`，按下面格式拼接：

```text
http://<VPS_PUBLIC_IP>:8080/sub/<MI_PANEL_DEFAULT_SUBSCRIPTION_TOKEN>/sing-box
```

在面板里手动创建的新订阅，创建成功后可以点“复制订阅链接”。面板只把链接写入剪贴板，不在页面上明文显示 token。

项目不使用管道直接执行远程 shell 的安装方式。bootstrap 命令会先把脚本下载到本地临时文件，再执行本地文件。

## 常用复制命令

公网 HTTP 直连安装：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp"
```

GitHub bootstrap 默认会把 HTTP 服务绑定到 `0.0.0.0`。管理 API 仍然要求认证；生产环境建议再放到 VPN、Zero Trust、mTLS/TLS 网关或防火墙白名单后面。

本机绑定安全安装，只允许 VPS 本机、SSH 隧道、反向代理或 VPN 访问管理端口：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" -l
```

本机绑定时，可以用 SSH 隧道从自己的电脑访问：

```sh
ssh -L 8080:127.0.0.1:8080 root@<VPS_PUBLIC_IP>
```

然后在本地浏览器打开：

```text
http://127.0.0.1:8080
```

指定密码文件落盘位置：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" --passwd-file /etc/sing-box-next-panel/passwd.txt
```

指定安装目录、端口、仓库和分支：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" --install-dir /opt/mi-proxy --repo-url https://github.com/3582730951/MI_Proxy.git --branch main PORT=8088
```

从配置文件安装：

```sh
cat > install.conf <<'EOF'
REPO_URL=https://github.com/3582730951/MI_Proxy.git
BRANCH=main
INSTALL_DIR=/opt/sing-box-next-panel
HOST=0.0.0.0
PORT=8080
POSTGRES_BIND=127.0.0.1
REDIS_BIND=127.0.0.1
AUTO_UPDATE=1
PASSWD_FILE=/opt/sing-box-next-panel/passwd.txt
EOF
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" -f install.conf
```

## 密码文件

默认密码文件：

```text
/opt/sing-box-next-panel/passwd.txt
```

默认格式：

```text
POSTGRES_PASSWORD=<generated-secret>
MI_PANEL_ADMIN_USER=admin
MI_PANEL_ADMIN_PASSWORD=<generated-secret>
MI_PANEL_ADMIN_TENANT=tenant-a
MI_PANEL_DEFAULT_SUBSCRIPTION_TOKEN=<generated-secret>
MI_PANEL_DEFAULT_SUBSCRIPTION_USER=admin
MI_PANEL_DEFAULT_SUBSCRIPTION_CLIENT=sing-box
MI_PANEL_DEFAULT_SUBSCRIPTION_DEVICE=default
MI_PANEL_DEFAULT_SUBSCRIPTION_REGION=auto
MI_PANEL_DEFAULT_SUBSCRIPTION_PROTOCOL=vless
MI_PANEL_DEFAULT_SUBSCRIPTION_OUTBOUND=proxy-default
```

安装脚本会把非敏感运行配置写入 `.env`，把密码和默认订阅 token 写入 `passwd.txt`，并设置文件权限为 `0600`。前端面板默认中文，登录时使用 `MI_PANEL_ADMIN_USER` 和 `MI_PANEL_ADMIN_PASSWORD`；订阅 token 不会在面板显示。如果以后增加新的运行密码，也应该以 `KEY=VALUE` 形式追加到同一个密码文件，不要写入 `.env`。

## 自动更新

默认安装会创建 `sing-box-next-panel-update.timer`，通过 `scripts/update.sh` 周期性更新。你也可以随时重复执行 README 顶部那条 GitHub 一键命令来手动升级旧版本。

- 使用 `git pull --ff-only`，只接受快进更新；
- 保留 `.env`、`passwd.txt` 和 Docker volume；
- 重建并重启 Compose 服务；
- 如果旧机器只有 Python 版 `docker-compose` 1.x，会先移除旧容器再重建，避免旧安装升级时触发 `ContainerConfig` 兼容错误；命名数据卷会保留；
- 检查 `/healthz`；
- 健康检查失败时回滚到上一个 commit。

手动更新：

```sh
/opt/sing-box-next-panel/scripts/update.sh --install-dir /opt/sing-box-next-panel --repo-url https://github.com/3582730951/MI_Proxy.git --branch main
```

指定密码文件手动更新：

```sh
/opt/sing-box-next-panel/scripts/update.sh --install-dir /opt/sing-box-next-panel --passwd-file /etc/sing-box-next-panel/passwd.txt
```

只重启当前版本，不拉取新代码：

```sh
/opt/sing-box-next-panel/scripts/update.sh --install-dir /opt/sing-box-next-panel --restart-only
```

旧版本手动升级到最新版本，直接重新执行同一条 GitHub 命令：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp"
```

如果旧版本安装在自定义目录，且本机已有 `/etc/sing-box-next-panel/install.env`，脚本会自动识别；否则显式传安装目录：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; echo "Downloading bootstrap script: $url"; if command -v curl >/dev/null 2>&1; then curl -fL --retry 3 -o "$tmp" "$url"; elif command -v wget >/dev/null 2>&1; then wget -O "$tmp" "$url"; else echo "curl or wget is required" >&2; exit 1; fi; test -s "$tmp" || { echo "downloaded bootstrap script is empty" >&2; exit 1; }; sh "$tmp" --install-dir /opt/mi-proxy
```

已安装后切换为公网 HTTP 访问：

```sh
/opt/sing-box-next-panel/scripts/install.sh -k PORT=8080
```

已安装后切回本机绑定：

```sh
/opt/sing-box-next-panel/scripts/install.sh -l PORT=8080
```

## 本地仓库内安装

如果已经 clone 了仓库，也可以直接在仓库根目录运行：

```sh
scripts/install.sh
```

常用参数：

```sh
scripts/install.sh -l
scripts/install.sh -k PORT=8080
scripts/install.sh --passwd-file /etc/sing-box-next-panel/passwd.txt
scripts/install.sh REPO_URL=https://github.com/3582730951/MI_Proxy.git BRANCH=main PORT=8088
```

## 验证部署

安装完成后可以检查服务状态：

```sh
systemctl status sing-box-next-panel --no-pager
systemctl status sing-box-next-panel-update.timer --no-pager
```

检查健康接口：

```sh
curl -fsS http://127.0.0.1:8080/healthz
```

公网绑定后，也可以从外部访问：

```text
http://<VPS_PUBLIC_IP>:8080/healthz
```

查看密码文件：

```sh
ls -l /opt/sing-box-next-panel/passwd.txt
sed -n 's/^\([^=]*\)=.*/\1=<redacted>/p' /opt/sing-box-next-panel/passwd.txt
```

查看运行配置：

```sh
cat /opt/sing-box-next-panel/.env
```

`.env` 不应该包含生成密码；密码应保存在 `passwd.txt` 或你通过 `--passwd-file` 指定的位置。
