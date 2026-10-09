# Documentation

<p align="right"><b>English</b> · <a href="zh-CN/README.md">简体中文</a></p>

Phase-1 design notes for OpenMastiff. Specs stay in sync with the running code; if they drift, trust the code and file an issue.

| Doc | Topic |
| --- | --- |
| [01-prd.md](01-prd.md) | Product fields, pages, state machine |
| [02-architecture.md](02-architecture.md) | FastAPI / Celery / Mongo / Redis / Docker |
| [03-runner-protocol.md](03-runner-protocol.md) | Scanner container I/O and exit codes |
| [04-policy.md](04-policy.md) | Default gates (license, SAST, CVE, maintenance) |
| [05-data-model.md](05-data-model.md) | Mongo collections and audit hash chain |
| [06-api.md](06-api.md) | REST API |
| [07-wbs-by-domain.md](07-wbs-by-domain.md) | WBS and acceptance notes |
| [08-mvp-smoke-test.md](08-mvp-smoke-test.md) | Smoke test |
| [09-docker-offline-or-mirror.md](09-docker-offline-or-mirror.md) | Air-gapped / mirror Docker |
| [10-local-install.md](10-local-install.md) | Local install |

Simplified Chinese copies live in [`zh-CN/`](zh-CN/).
