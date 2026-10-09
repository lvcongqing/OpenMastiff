# OpenMastiff Web（React）

## 依赖

- **Node.js 18+**（Vite 5 / 当前工具链要求；推荐 LTS 20）
- 后端 API 已启动（默认 `http://127.0.0.1:18000`，见 `backend/run_api.sh`）
- 绑定 **80 / 443** 需要 root 或 `setcap`（见下文）

### 确认 Node 版本

```bash
node -v   # 应显示 v18.x / v20.x / v22.x 等
```

若仍是 **v12 / v14** 等旧版本，说明 PATH 仍指向系统自带 Node。已安装新版本时，请用 **nvm** 或 **fnm** 切换，例如：

```bash
# nvm（仓库根目录有 .nvmrc，内容为 20）
nvm install 20
nvm use
cd web && npm install && npm run dev
```

## 开发

```bash
cd web
npm install
npm run dev
```

若提示 `EADDRINUSE`（80/443 被占用），说明上次开发进程仍在后台运行：

```bash
npm run dev:stop   # 停止旧进程
npm run dev
```

默认：

| 协议 | 端口 | 说明 |
|------|------|------|
| HTTP | 80 | 自动 301 跳转到 HTTPS |
| HTTPS | 443 | Vite 开发服务（自签名证书） |

- 本机：`https://127.0.0.1/` 或 `http://127.0.0.1/`（会跳转）
- 远程：`https://<服务器IP>/`

首次运行会自动生成 `web/certs/server.{key,crt}`。浏览器会提示证书不受信任，开发环境可继续访问。

为服务器 IP 生成含 SAN 的证书（推荐部署机执行一次）：

```bash
cd web
VITE_DEV_CERT_SAN="DNS:localhost,IP:127.0.0.1,IP:<服务器IP>" bash scripts/gen-dev-certs.sh
# 若已有旧证书需先删除 web/certs/server.* 再生成
```

`vite.config.ts` 已将 `/api` 代理到 `18000`，`.env.development` 中 `VITE_API_BASE=/api`，无需处理 CORS。

### 绑定特权端口（80 / 443）

Linux 上非 root 用户绑定 1024 以下端口需授权，任选其一：

```bash
# 方式 A：以 root 运行 npm run dev

# 方式 B：给 node 绑定低端口能力（推荐）
NODE=$(readlink -f "$(which node)")
setcap 'cap_net_bind_service=+ep' "$NODE"
```

仅 HTTP、不用 HTTPS 时：`VITE_DEV_HTTPS=false npm run dev`（仅监听 80）。

环境变量（可选）：

| 变量 | 默认 | 含义 |
|------|------|------|
| `VITE_DEV_HTTPS` | `true` | 是否启用 HTTPS（443） |
| `VITE_DEV_HTTPS_PORT` | `443` | HTTPS 端口 |
| `VITE_DEV_HTTP_PORT` | `80` | HTTP 重定向端口 |

可选：在项目根执行 `npm run typecheck` 做 TypeScript 静态检查（同样需要 Node 18+）。

## 生产构建

```bash
npm run build
```

将 `dist/` 静态资源交给 Nginx；示例配置见 `deploy/nginx/openmastiff-web.conf`（80 跳转 443，HTTPS 托管静态文件并反代 `/api`）。

若前后端不同域，设置环境变量 `VITE_API_BASE=https://你的API地址` 后重新构建，并确保后端已启用 CORS（当前 `allow_origins=["*"]`）。
