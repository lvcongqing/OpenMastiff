# OpenMastiff

<p align="center">
  <img src="web/public/logo.png" alt="OpenMastiff logo" width="96" />
</p>

<p align="center">
  <strong>Supply-chain intake review platform</strong><br />
  License, SAST, SBOM, CVE, and upstream maintainability gates for open-source dependencies — with multi-role sign-off, legal review, remediation, and an auditable evidence pack.
</p>

<p align="center">
  <a href="#whats-in-010"><img src="https://img.shields.io/badge/release-v0.1.0-1f6feb" alt="Release v0.1.0" /></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/changelog-Keep%20a%20Changelog-E0574F" alt="Changelog" /></a>
  <img src="https://img.shields.io/badge/status-beta-yellow" alt="Status: beta" />
  <img src="https://img.shields.io/badge/python-3.8%2B-3776AB" alt="Python 3.8+" />
  <img src="https://img.shields.io/badge/node-18%2B-339933" alt="Node 18+" />
  <img src="https://img.shields.io/badge/ui-zh--CN%20%7C%20en--US-8A2BE2" alt="UI locales" />
</p>

<p align="center">
  <b>English</b> · <a href="README.zh-CN.md">简体中文</a>
</p>

---

## Table of contents

- [About](#about)
- [What's in 0.1.0](#whats-in-010)
- [Built with](#built-with)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [One-click install](#one-click-install)
  - [One-click update](#one-click-update)
  - [Local development](#local-development)
  - [Docker Compose](#docker-compose)
- [Usage](#usage)
- [Web UI language](#web-ui-language)
- [Documentation](#documentation)
- [Releases](#releases)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## About

OpenMastiff is an in-house **open-source dependency intake** system. Teams file a request (Git URL + ref, or a source archive), the platform runs scanners in a short-lived Docker sandbox, applies policy gates, and drives a closed loop:

**Draft → Scan → Role review / Legal (licenses) → Decision → Remediation & rescan → Evidence export**

It is designed for isolated or intranet deployments: the scanner container defaults to `network=none`, evidence is stored as content-addressed blobs, and audit logs are append-only.

### Features

- **Intake requests** — single form or Excel batch import; Git clone or zip / tar / tar.gz upload
- **Policy gates** — deny-list licenses, gosec / cppcheck / bandit / PMD / cargo-audit / ESLint thresholds, Grype CVE counts, maintainability scores by business criticality
- **License review** — deny, pass, or send unknown / listed licenses to legal; legal allow/deny syncs into role sign-off
- **SBOM** — Syft CycloneDX / SPDX / Syft JSON; directory excludes (e.g. `.github`, `node_modules`)
- **CVE / SCA** — Grype on the SBOM; first-party advisories via OSV (GitHub Advisory extra for GitHub sources). Trivy and osv-scanner are reserved
- **Findings workflow** — mark false positive, accepted risk, or confirmed; batch by rule; first-party Critical/High cannot be cleared with accepted risk
- **Sign-off** — project / R&D / product / legal / security (and extra roles); waivers with owner, compensating controls, and expiry
- **Evidence** — scan reports, PDF intake-review report, exportable evidence pack
- **Auth** — LDAP or local HTTP accounts; first-run setup wizard
- **UI** — Simplified Chinese and English, plus multiple color themes

## What's in 0.1.0

This is the first tagged release (`v0.1.0`). Highlights:

| Area | Included |
| --- | --- |
| Intake | Create / edit / delete requests; batch Excel; scan scope paths |
| Scanners | Syft, gosec, cppcheck, bandit, PMD, cargo-audit, ESLint, Grype `v0.119.0` |
| Gates | License, SAST High/Error, CVE Critical/High (dependency + first-party), maintainability |
| Review | Multi-role conclusions, legal license decision, findings dispositions, remediations |
| Ops | `install.sh` / `update.sh`, systemd, Docker Compose, Celery Beat for waiver expiry |
| Web | React + Ant Design 5; **zh-CN / en-US**; theme switcher |

See [CHANGELOG.md](CHANGELOG.md) for the full list in Keep a Changelog format.

## Built with

- **API** — FastAPI
- **Workers** — Celery + Redis broker
- **Data** — MongoDB; local blob volume (`/data/blobs`, SHA-256 dedup)
- **Scanner** — Docker sandbox (`read_only`, dropped caps, default `network=none`)
- **Web** — React, Vite, Ant Design 5

## Getting started

### Prerequisites

| Mode | Need |
| --- | --- |
| Local | Python 3.8+, Redis, MongoDB, Docker (for sandboxed scans), Node.js 18+ if you build the web UI |
| Docker Compose | Docker Engine + Compose, and reachable base images (see `docs/09-docker-offline-or-mirror.md` for air-gapped notes) |

Scanner tools for local mode: Syft, gosec, cppcheck, bandit, PMD, cargo-audit, ESLint, Grype. `install.sh --with-scanner-tools` installs the set used by this release.

### One-click install

Host `install.sh` on your intranet (or run `bash scripts/serve-install.sh`), then:

```bash
export OPENMASTIFF_REPO="ssh://<user>@<gerrit>/openMastiff"   # or an https Git URL
curl -fsSL https://<your-host>/openMastiff/install.sh | bash
```

Common options:

```bash
# Existing checkout → /opt/openMastiff, systemd units, scanner CLIs
sudo bash install.sh --from-source "$(pwd)" --with-systemd --with-scanner-tools --with-web -y

# Docker Compose
curl -fsSL https://<your-host>/openMastiff/install.sh | bash -s -- --mode docker -y
```

API listens on `http://<host>:18000` by default (`OPENMASTIFF_API_PORT` / `--api-port`). Follow the installer output and [docs/08-mvp-smoke-test.md](docs/08-mvp-smoke-test.md).

Copy [`.env.example`](.env.example) to `.env` if you start services by hand. First-run setup writes `config/app_config.json` (see [config/app_config.example.json](config/app_config.example.json)). **Do not commit** `.env`, `config/app_config.json`, or `data/` — they hold instance secrets and scan artifacts.

### One-click update

Pulls the Git tree, refreshes dependencies, and restarts services. Keeps `data/` and the existing `.env`.

```bash
sudo bash /opt/openMastiff/update.sh -y
bash update.sh --branch master -y
bash update.sh --revision v0.1.0 -y
bash update.sh -y --with-web
curl -fsSL https://<your-host>/openMastiff/update.sh | sudo bash -s -- -y
```

Compose installs are detected via `SCANNER_MODE=docker` in `.env`, or pass `--docker`.

### Local development

Redis DB defaults to `8` (`REDIS_URL=redis://localhost:6379/8`) so other Celery apps on the same host are not disturbed.

```bash
python3 -m pip install -r backend/requirements.txt
bash backend/run_worker.sh    # terminal 1
bash backend/run_api.sh       # terminal 2
```

Optional periodic jobs (waiver expiry): `bash backend/run_beat.sh`.

Web UI (dev server proxies `/api` to port 18000; HTTP :80 → HTTPS :443):

```bash
cd web && npm install && npm run dev
```

Details: [web/README.md](web/README.md), [docs/10-local-install.md](docs/10-local-install.md).

### Docker Compose

When image registries are reachable:

```bash
docker compose up -d --build
```

Air-gapped / mirror setup: [docs/09-docker-offline-or-mirror.md](docs/09-docker-offline-or-mirror.md).

## Usage

1. Complete first-run setup (auth, Mongo/Redis, JWT) if the instance is new.
2. Sign in (LDAP or local account). Switch **中 / EN** in the header if needed.
3. Create an intake request (or batch-import Excel). Attach a Git source or upload an archive.
4. Submit scan. Inspect summary, licenses, SBOM, CVE, SAST, and maintainability reports.
5. Clear false positives on **Findings** if needed; then complete role / legal review.
6. Open remediations, rescan, download the intake-review PDF, and export the evidence pack.

Policy (deny lists, CVE engines, concurrency, exclude dirs) is edited under **Policy** and applies to later scans immediately.

## Web UI language

The UI ships **Simplified Chinese (`zh-CN`)** and **English (`en-US`)**.

- Header control: **中** / **EN** (also on the login page)
- Preference is stored as `openmastiff.locale` in `localStorage`
- First visit: `navigator.language` starting with `zh` → Chinese, otherwise English
- Ant Design and dayjs locales follow the same setting

## Documentation

| Doc | Topic |
| --- | --- |
| [docs/01-prd.md](docs/01-prd.md) | Product fields, pages, state machine |
| [docs/02-architecture.md](docs/02-architecture.md) | FastAPI / Celery / Mongo / Redis / Docker |
| [docs/03-runner-protocol.md](docs/03-runner-protocol.md) | Scanner container I/O and exit codes |
| [docs/04-policy.md](docs/04-policy.md) | Default gates (license, SAST, CVE, maintenance) |
| [docs/05-data-model.md](docs/05-data-model.md) | Mongo collections and audit hash chain |
| [docs/06-api.md](docs/06-api.md) | API draft |
| [docs/07-wbs-by-domain.md](docs/07-wbs-by-domain.md) | WBS and acceptance notes |
| [docs/08-mvp-smoke-test.md](docs/08-mvp-smoke-test.md) | Smoke test |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Releases

Versioning follows [Semantic Versioning](https://semver.org/). Release notes are kept in [CHANGELOG.md](CHANGELOG.md) ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).

| Version | Date | Notes |
| --- | --- | --- |
| **[0.1.0](CHANGELOG.md#010---2026-10-09)** | 2026-10-09 | First public-facing release of the intake review loop |

When tagging a GitHub (or Gerrit) release, use:

- **Tag:** `v0.1.0`
- **Title:** `OpenMastiff v0.1.0`
- **Body:** copy the matching section from `CHANGELOG.md` (Added / Changed / Fixed)

Pin an install to this release with `bash update.sh --revision v0.1.0 -y` after the tag exists on the remote.

## Roadmap

- Additional CVE engines already reserved in policy: Trivy, osv-scanner
- Gerrit change/commit sources and label write-back (see architecture “phase 2”)
- Replace local blobs with S3-compatible object storage

## Contributing

This repository is maintained for internal deployment. Open a change on the project Gerrit remote (`origin`) against `master`. Keep user-facing strings in both `web/src/i18n/zh-CN.ts` and `web/src/i18n/en-US.ts`. Do not commit secrets (`.env`, credentials).

## License

License terms are **not published** in this tree. Ask the maintainers before redistributing binaries or source outside the owning organization.
