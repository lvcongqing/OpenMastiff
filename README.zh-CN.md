# OpenMastiff

<p align="center">
  <img src="web/public/logo.png" alt="OpenMastiff 标志" width="96" />
</p>

<p align="center">
  <strong>供应链安全引入审查平台</strong><br />
  面向开源依赖引入：许可证、SAST、SBOM、CVE 与上游维护性门禁，配合多角色会签、法务复核、整改复测与可审计证据包。
</p>

<p align="center">
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/release-v0.1.0-1f6feb" alt="Release v0.1.0" /></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/changelog-Keep%20a%20Changelog-E0574F" alt="Changelog" /></a>
  <img src="https://img.shields.io/badge/status-beta-yellow" alt="Status: beta" />
  <img src="https://img.shields.io/badge/python-3.8%2B-3776AB" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/node-18%2B-339933" alt="Node 18+" />
  <img src="https://img.shields.io/badge/ui-zh--CN%20%7C%20en--US-8A2BE2" alt="界面语言" />
</p>

<p align="center">
  <a href="README.md">English</a> · <b>简体中文</b>
</p>

---

## 目录

- [简介](#简介)
- [0.1.0 包含内容](#010-包含内容)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
  - [环境要求](#环境要求)
  - [一键安装](#一键安装)
  - [一键更新](#一键更新)
  - [本地开发](#本地开发)
  - [Docker Compose](#docker-compose)
- [使用流程](#使用流程)
- [Web 界面语言](#web-界面语言)
- [文档](#文档)
- [版本发布](#版本发布)
- [路线图](#路线图)
- [贡献](#贡献)
- [许可证](#许可证)

## 简介

OpenMastiff 用于落地**开源依赖引入审查闭环**。业务侧提交引入单（Git 仓库 + 引用，或源码压缩包），平台在短生命周期 Docker 沙箱中执行扫描，按策略计算门禁，并走完整闭环：

**草稿 → 扫描 → 角色评审 / 法务（仅许可证）→ 结论 → 整改复测 → 证据导出**

面向内网部署：扫描容器默认 `network=none`，证据按 SHA-256 去重落盘，审计日志只追加不改写。

### 功能

- **引入单** — 单个创建或 Excel 批量导入；Git 拉取或 zip / tar / tar.gz 上传
- **策略门禁** — 禁止许可证、gosec / cppcheck / bandit / PMD / cargo-audit / ESLint 阈值、Grype CVE 计数、按业务关键性的维护性评分
- **许可证复核** — 禁止 / 通过 / 未知或名单内许可证转法务；法务允许/拒绝同步到会签
- **SBOM** — Syft CycloneDX / SPDX / Syft JSON；可排除目录（如 `.github`、`node_modules`）
- **CVE / SCA** — 在 SBOM 上跑 Grype；本软件公告走 OSV（GitHub 源额外查 Advisory）。Trivy、osv-scanner 为预留引擎
- **发现项** — 误报 / 接受风险 / 确认有效；可按规则批量处理；本软件 Critical/High 不能靠接受风险清门禁
- **会签** — 项目 / 研发 / 产品 / 法务 / 安全（及额外角色）；豁免需接受人、补偿措施与到期日
- **证据** — 扫描报告、引入审查 PDF、证据包导出
- **认证** — LDAP 或本地 HTTP 账号；首次初始化向导
- **界面** — 简体中文与英语，以及多套配色主题

## 0.1.0 包含内容

本版本为首次面向发布的标签（`v0.1.0`）。摘要：

| 范围 | 内容 |
| --- | --- |
| 引入 | 创建 / 编辑 / 删除引入单；Excel 批量；扫描范围路径 |
| 扫描器 | Syft、gosec、cppcheck、bandit、PMD、cargo-audit、ESLint、Grype `v0.119.0` |
| 门禁 | 许可证、SAST High/Error、CVE Critical/High（依赖 + 本软件）、维护性 |
| 评审 | 多角色结论、法务许可证裁决、发现项处置、整改单 |
| 运维 | `install.sh` / `update.sh`、systemd、Docker Compose、Celery Beat（豁免到期） |
| Web | React + Ant Design 5；**zh-CN / en-US**；主题切换 |

完整条目见 [CHANGELOG.md](CHANGELOG.md)（Keep a Changelog 格式）。

## 技术栈

- **API** — FastAPI
- **任务** — Celery + Redis
- **数据** — MongoDB；本地 blob 卷（`/data/blobs`，SHA-256 去重）
- **扫描** — Docker 沙箱（只读、丢弃 capabilities、默认无网络）
- **前端** — React、Vite、Ant Design 5

## 快速开始

### 环境要求

| 模式 | 需要 |
| --- | --- |
| 本机 | Python 3.8+、Redis、MongoDB、Docker（沙箱扫描）、构建前端时还需 Node.js 18+ |
| Docker Compose | Docker Engine + Compose，以及可拉取的基础镜像（离线见 `docs/09-docker-offline-or-mirror.md`） |

本机模式扫描工具：Syft、gosec、cppcheck、bandit、PMD、cargo-audit、ESLint、Grype。本发行版可用 `install.sh --with-scanner-tools` 安装。

### 一键安装

在内网托管 `install.sh`（也可用 `bash scripts/serve-install.sh` 临时提供），然后：

```bash
export OPENMASTIFF_REPO="ssh://<user>@<gerrit>/openMastiff"   # 或 https Git 地址
curl -fsSL https://<你的域名>/openMastiff/install.sh | bash
```

常用选项：

```bash
# 已有源码，安装到 /opt/openMastiff，注册 systemd，并安装扫描 CLI
sudo bash install.sh --from-source "$(pwd)" --with-systemd --with-scanner-tools --with-web -y

# Docker Compose 部署
curl -fsSL https://<你的域名>/openMastiff/install.sh | bash -s -- --mode docker -y
```

API 默认 `http://<主机>:18000`（`OPENMASTIFF_API_PORT` / `--api-port`）。详见安装输出与 [docs/08-mvp-smoke-test.md](docs/08-mvp-smoke-test.md)。

手工启动时可把 [`.env.example`](.env.example) 复制为 `.env`。首次初始化会写入 `config/app_config.json`（模板见 [config/app_config.example.json](config/app_config.example.json)）。**不要提交** `.env`、`config/app_config.json` 或 `data/`，其中包含实例密钥与扫描产物。

### 一键更新

从 Git 拉取最新代码、更新依赖并重启服务；保留 `data/` 与现有 `.env`。

```bash
sudo bash /opt/openMastiff/update.sh -y
bash update.sh --branch master -y
bash update.sh --revision v0.1.0 -y
bash update.sh -y --with-web
curl -fsSL https://<你的域名>/openMastiff/update.sh | sudo bash -s -- -y
```

Docker Compose 实例会检测 `.env` 中 `SCANNER_MODE=docker`，也可显式传 `--docker`。

### 本地开发

默认 Redis DB 为 `8`（`REDIS_URL=redis://localhost:6379/8`），避免与同机其它 Celery 冲突。

```bash
python3 -m pip install -r backend/requirements.txt
bash backend/run_worker.sh    # 终端 1
bash backend/run_api.sh       # 终端 2
```

豁免到期等周期任务：`bash backend/run_beat.sh`。

Web 前端（`/api` 反代到 18000；开发默认 HTTP :80 → HTTPS :443）：

```bash
cd web && npm install && npm run dev
```

详见 [web/README.md](web/README.md)、[docs/10-local-install.md](docs/10-local-install.md)。

### Docker Compose

镜像源可达时：

```bash
docker compose up -d --build
```

离线 / 镜像： [docs/09-docker-offline-or-mirror.md](docs/09-docker-offline-or-mirror.md)。

## 使用流程

1. 新实例先完成初始化（认证、Mongo/Redis、JWT）。
2. 登录（LDAP 或本地账号）。需要英文界面时，在页头切换 **中 / EN**。
3. 新建引入单（或批量导入 Excel），配置 Git 源或上传源码包。
4. 提交扫描，查看摘要、许可证、SBOM、CVE、SAST 与维护性报告。
5. 在「发现项」处理误报后，完成各角色 / 法务评审。
6. 开整改、复测、下载引入审查 PDF，并导出证据包。

策略（禁止清单、CVE 引擎、并发、排除目录）在「策略配置」保存后立即作用于后续扫描。

## Web 界面语言

界面提供 **简体中文（`zh-CN`）** 与 **英语（`en-US`）**。

- 页头切换：**中** / **EN**（登录页同样提供）
- 偏好写入 `localStorage` 键 `openmastiff.locale`
- 首次访问：`navigator.language` 以 `zh` 开头则中文，否则英语
- Ant Design 与 dayjs 区域设置随语言切换

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/01-prd.md](docs/01-prd.md) | 字段级 PRD、页面、状态机 |
| [docs/02-architecture.md](docs/02-architecture.md) | FastAPI / Celery / Mongo / Redis / Docker |
| [docs/03-runner-protocol.md](docs/03-runner-protocol.md) | 扫描容器协议与退出码 |
| [docs/04-policy.md](docs/04-policy.md) | 默认门禁（许可证、SAST、CVE、维护性） |
| [docs/05-data-model.md](docs/05-data-model.md) | Mongo 集合与审计 hash 链 |
| [docs/06-api.md](docs/06-api.md) | API 草案 |
| [docs/07-wbs-by-domain.md](docs/07-wbs-by-domain.md) | 功能域 WBS |
| [docs/08-mvp-smoke-test.md](docs/08-mvp-smoke-test.md) | 冒烟测试 |
| [CHANGELOG.md](CHANGELOG.md) | 版本历史 |

## 版本发布

版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。发布说明写在 [CHANGELOG.md](CHANGELOG.md)，格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

| 版本 | 日期 | 说明 |
| --- | --- | --- |
| **[0.1.0](CHANGELOG.md#010---2026-10-09)** | 2026-10-09 | 引入审查闭环的首次对外版本 |

在 GitHub / Gerrit 打 Release 时建议：

- **Tag：** `v0.1.0`
- **标题：** `OpenMastiff v0.1.0`
- **正文：** 复制 `CHANGELOG.md` 对应章节（Added / Changed / Fixed）

远端有标签后可用 `bash update.sh --revision v0.1.0 -y` 钉死该版本。

## 路线图

- 策略中已预留的 CVE 引擎：Trivy、osv-scanner
- Gerrit change/commit 源与 Label 回写（见架构「二期」）
- 本地 blob 平滑替换为 S3 兼容对象存储

## 贡献

本仓库面向内部部署。请向项目 Gerrit 远程（`origin`）的 `master` 提交变更。用户可见文案须同时更新 `web/src/i18n/zh-CN.ts` 与 `web/src/i18n/en-US.ts`。不要提交密钥（`.env`、凭据文件）。

## 许可证

本仓库**未发布**许可证文件。向组织外分发源码或制品前，请先联系维护者。
