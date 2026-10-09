# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

How to cut a release:

1. Move items from `[Unreleased]` into a new `## [X.Y.Z] - YYYY-MM-DD` section.
2. Set `OPENMASTIFF_VERSION` in `install.sh` / `update.sh` and `version` in `web/package.json`.
3. Tag `vX.Y.Z` and paste this section into the GitHub / Gerrit release body.

## [Unreleased]

### Added

- Apache License 2.0 (`LICENSE`).
- English copies of phase-1 design docs under `docs/`, with Simplified Chinese moved to `docs/zh-CN/`.

## [0.1.0] - 2026-10-09

First tagged release of the open-source dependency **intake review loop**.

### Added

- Web UI locales: Simplified Chinese (`zh-CN`) and English (`en-US`), header language switcher, `localStorage` preference, matching Ant Design / dayjs locales.
- Bilingual repository docs: English [`README.md`](README.md) and Simplified Chinese [`README.zh-CN.md`](README.zh-CN.md).
- Intake requests: draft create/edit/delete, Git source or archive upload, optional scan-scope paths, Excel batch import with confirm-and-scan.
- Sandboxed scans via Docker (`read_only`, dropped capabilities, default `network=none`).
- License scanning and gates (deny list, legal-review list, unknown-license policy, confidence threshold).
- SAST engines: gosec (Go), cppcheck (C/C++), bandit (Python), PMD (Java), cargo-audit (Rust), ESLint (JS/TS).
- SBOM via Syft (CycloneDX, SPDX, Syft JSON), including PURL / path / declared dependencies.
- CVE / SCA: Grype (pinned `v0.119.0`) on the Syft SBOM; first-party advisories from OSV and GitHub Advisory; reserved slots for Trivy and osv-scanner.
- Upstream maintainability scoring (Git forges and package registries) with gates by business criticality.
- Findings dispositions: open, false positive, accepted risk, confirmed; batch by rule; first-party Critical/High cannot use accepted risk to clear the gate.
- Multi-role sign-off (project / R&D / product / legal / security, plus extra roles) and legal license allow/deny.
- Remediation tickets, rescan, waiver with owner / controls / expiry (Celery Beat).
- Evidence: per-scanner reports, intake-review PDF, evidence-pack export, append-only audit hash chain.
- Policy UI: license, SAST, CVE, maintainability, runner concurrency, timeouts, exclude directories.
- Auth: LDAP or local HTTP accounts; first-run setup wizard; credentials store for private Git.
- Install / update: `install.sh`, `update.sh`, systemd units, Docker Compose; web build with Node 18+.
- Web console: React + Vite + Ant Design 5, color themes, process overview, scan-report viewer.

### Security

- Scanner container isolation (non-root, no-new-privileges, resource and PID limits).
- Worker holds the Docker socket; scan jobs do not.
- JWT sessions; blob storage keyed by SHA-256.

[Unreleased]: CHANGELOG.md
[0.1.0]: CHANGELOG.md#010---2026-10-09
