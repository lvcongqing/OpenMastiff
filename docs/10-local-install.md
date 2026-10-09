# 本机安装与启动（UOS Server 20 / yum|dnf）

## 1) Redis

你已安装并运行，确认：

```bash
redis-cli ping
```

返回 `PONG` 即可。

说明：本项目默认使用 `redis://localhost:6379/8` 作为 Celery broker/result（避免与其他 Celery 冲突）。

## 2) MongoDB（repo 源安装）

> 不同 repo 的包名可能是 `mongodb` / `mongodb-server` / `mongo` / `mongod` 等；请以 `yum search` 结果为准。

搜索：

```bash
yum search mongodb
```

安装（示例）：

```bash
yum install -y mongodb mongodb-server || yum install -y mongodb-server || yum install -y mongodb
```

启动：

```bash
systemctl enable --now mongod || systemctl enable --now mongodb || true
systemctl status mongod --no-pager || systemctl status mongodb --no-pager || true
```

验证端口：

```bash
ss -lntp | grep 27017 || true
```

## 3) Python 依赖

```bash
python3 -m pip install -r backend/requirements.txt
```

## 4) 启动

两个终端分别启动：

```bash
bash backend/run_worker.sh
```

```bash
bash backend/run_api.sh
```

默认 API 端口为 `18000`（可通过 `API_PORT` 覆盖）。

（可选）启动定时任务（豁免到期回流等）：

```bash
bash backend/run_beat.sh
```

## 5) 跑通最小闭环

见 `docs/08-mvp-smoke-test.md`。

