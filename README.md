# MI Proxy VPS 一键部署

这是一个面向 sing-box 运维面板、规则编译、WARP 池、订阅生成和节点 Agent 的部署仓库。根目录提供了无交互 VPS 安装脚本，用户复制一条命令到 Linux VPS 上执行即可完成安装。

## 一条命令安装

在新的 VPS 上使用 `root` 用户执行下面这一整行：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; (command -v curl >/dev/null 2>&1 && curl -fsSLo "$tmp" "$url" || wget -qO "$tmp" "$url") && sh "$tmp"
```

这条命令会：

- 下载 `scripts/bootstrap.sh` 到临时文件；
- 在缺少 Git 时自动安装最小依赖；
- 拉取 `https://github.com/3582730951/MI_Proxy.git` 的 `main` 分支；
- 调用 `scripts/install.sh` 完成无交互部署；
- 默认安装到 `/opt/sing-box-next-panel`；
- 默认监听 `127.0.0.1:8080`；
- 默认把生成的密码写入 `/opt/sing-box-next-panel/passwd.txt`；
- 默认创建 systemd 服务和自动更新 timer。

项目不使用管道直接执行远程 shell 的安装方式。bootstrap 命令会先把脚本下载到本地临时文件，再执行本地文件。

## 常用复制命令

默认安全安装，只允许本机访问管理端口：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; (command -v curl >/dev/null 2>&1 && curl -fsSLo "$tmp" "$url" || wget -qO "$tmp" "$url") && sh "$tmp"
```

公开绑定管理端口：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; (command -v curl >/dev/null 2>&1 && curl -fsSLo "$tmp" "$url" || wget -qO "$tmp" "$url") && sh "$tmp" -k PORT=8080
```

`-k` 会把 HTTP 服务绑定到 `0.0.0.0`。只建议在 VPN、Zero Trust、mTLS/TLS 网关或防火墙白名单后使用。管理 API 仍然要求认证，但默认本机绑定更安全。

指定密码文件落盘位置：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; (command -v curl >/dev/null 2>&1 && curl -fsSLo "$tmp" "$url" || wget -qO "$tmp" "$url") && sh "$tmp" --passwd-file /etc/sing-box-next-panel/passwd.txt
```

指定安装目录、端口、仓库和分支：

```sh
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; (command -v curl >/dev/null 2>&1 && curl -fsSLo "$tmp" "$url" || wget -qO "$tmp" "$url") && sh "$tmp" --install-dir /opt/mi-proxy --repo-url https://github.com/3582730951/MI_Proxy.git --branch main PORT=8088
```

从配置文件安装：

```sh
cat > install.conf <<'EOF'
REPO_URL=https://github.com/3582730951/MI_Proxy.git
BRANCH=main
INSTALL_DIR=/opt/sing-box-next-panel
HOST=127.0.0.1
PORT=8080
POSTGRES_BIND=127.0.0.1
REDIS_BIND=127.0.0.1
AUTO_UPDATE=1
PASSWD_FILE=/opt/sing-box-next-panel/passwd.txt
EOF
tmp=$(mktemp); url=https://raw.githubusercontent.com/3582730951/MI_Proxy/main/scripts/bootstrap.sh; (command -v curl >/dev/null 2>&1 && curl -fsSLo "$tmp" "$url" || wget -qO "$tmp" "$url") && sh "$tmp" -f install.conf
```

## 密码文件

默认密码文件：

```text
/opt/sing-box-next-panel/passwd.txt
```

默认格式：

```text
POSTGRES_PASSWORD=<generated-secret>
```

安装脚本会把非敏感运行配置写入 `.env`，把密码写入 `passwd.txt`，并设置文件权限为 `0600`。如果以后增加新的运行密码，也应该以 `KEY=VALUE` 形式追加到同一个密码文件，不要写入 `.env`。

## 自动更新

默认安装会创建 `sing-box-next-panel-update.timer`，通过 `scripts/update.sh` 周期性更新：

- 使用 `git pull --ff-only`，只接受快进更新；
- 保留 `.env`、`passwd.txt` 和 Docker volume；
- 重建并重启 Compose 服务；
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
