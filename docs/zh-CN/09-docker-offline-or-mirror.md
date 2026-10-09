<p align="right"><a href="../09-docker-offline-or-mirror.md">English</a> · <b>简体中文</b></p>

# Docker 受限网络启动指南（内网镜像/离线镜像）

当环境无法访问 Docker Hub（例如连不上 `registry-1.docker.io`）时，可以用以下任一方式启动一期服务。

## 方式 1：配置 Docker 镜像加速/内网镜像源（推荐）

在 `/etc/docker/daemon.json` 配置镜像加速或内网镜像源（示例）：

```json
{
  "registry-mirrors": ["https://<你的镜像加速器域名>"]
}
```

应用配置并重启：

```bash
systemctl restart docker
```

然后启动：

```bash
docker compose up -d --build
```

## 方式 2：使用内网镜像仓库前缀（不改 daemon）

本仓库 `docker-compose.yml` 支持通过环境变量指定镜像：

- `MONGO_IMAGE`
- `REDIS_IMAGE`
- `PYTHON_BASE_IMAGE`

示例（把 Docker Hub 镜像替换为你们内网仓库镜像）：

```bash
export MONGO_IMAGE=registry.example.com/library/mongo:7
export REDIS_IMAGE=registry.example.com/library/redis:7-alpine
export PYTHON_BASE_IMAGE=registry.example.com/library/python:3.12-slim

docker compose up -d --build
```

## 方式 3：离线导入镜像（air-gap）

在可联网机器上拉取并导出：

```bash
docker pull mongo:7
docker pull redis:7-alpine
docker pull python:3.12-slim

docker save -o images.tar mongo:7 redis:7-alpine python:3.12-slim
```

把 `images.tar` 拷贝到受限机器后导入：

```bash
docker load -i images.tar
docker compose up -d --build
```

