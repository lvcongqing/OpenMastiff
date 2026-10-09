# Docker on a restricted network (intranet mirror / offline images)

<p align="right"><b>English</b> · <a href="zh-CN/09-docker-offline-or-mirror.md">简体中文</a></p>

When the host cannot reach Docker Hub (for example `registry-1.docker.io` is blocked), use one of the following to start phase-1 services.

## Option 1: registry mirror (recommended)

Set a pull-through cache or intranet mirror in `/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["https://<your-mirror-host>"]
}
```

Apply and restart:

```bash
systemctl restart docker
```

Then start:

```bash
docker compose up -d --build
```

## Option 2: image prefix without changing the daemon

`docker-compose.yml` in this repo accepts:

- `MONGO_IMAGE`
- `REDIS_IMAGE`
- `PYTHON_BASE_IMAGE`

Example (replace Docker Hub with an internal registry):

```bash
export MONGO_IMAGE=registry.example.com/library/mongo:7
export REDIS_IMAGE=registry.example.com/library/redis:7-alpine
export PYTHON_BASE_IMAGE=registry.example.com/library/python:3.12-slim

docker compose up -d --build
```

## Option 3: air-gap import

On a machine that can pull images:

```bash
docker pull mongo:7
docker pull redis:7-alpine
docker pull python:3.12-slim

docker save -o images.tar mongo:7 redis:7-alpine python:3.12-slim
```

Copy `images.tar` to the restricted host and load:

```bash
docker load -i images.tar
docker compose up -d --build
```
