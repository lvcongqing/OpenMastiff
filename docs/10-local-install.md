# Local install (UOS Server 20 / yum | dnf)

<p align="right"><b>English</b> · <a href="zh-CN/10-local-install.md">简体中文</a></p>

## 1) Redis

Confirm it is running:

```bash
redis-cli ping
```

`PONG` is enough.

This project defaults to `redis://localhost:6379/8` as the Celery broker / result backend (avoids clashing with other Celery apps).

## 2) MongoDB (from a yum repo)

> Package names vary: `mongodb` / `mongodb-server` / `mongo` / `mongod`. Use `yum search`.

Search:

```bash
yum search mongodb
```

Install (example):

```bash
yum install -y mongodb mongodb-server || yum install -y mongodb-server || yum install -y mongodb
```

Start:

```bash
systemctl enable --now mongod || systemctl enable --now mongodb || true
systemctl status mongod --no-pager || systemctl status mongodb --no-pager || true
```

Check the port:

```bash
ss -lntp | grep 27017 || true
```

## 3) Python dependencies

```bash
python3 -m pip install -r backend/requirements.txt
```

## 4) Start

Two terminals:

```bash
bash backend/run_worker.sh
```

```bash
bash backend/run_api.sh
```

API port defaults to `18000` (`API_PORT` overrides).

Optional periodic jobs (waiver expiry, …):

```bash
bash backend/run_beat.sh
```

## 5) Smoke the loop

See `docs/08-mvp-smoke-test.md`.
