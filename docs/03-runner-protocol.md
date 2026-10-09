# Runner protocol (scanner container)

<p align="right"><b>English</b> · <a href="zh-CN/03-runner-protocol.md">简体中文</a></p>

## Mounts

- `/input`: read-only source
- `/output`: write-only outputs
- `/policy/policy.json`: read-only policy snapshot

## Environment variables (phase 1)

- `SCAN_ID`: scan_run id
- `REQUEST_ID`: intake request id
- `SCOPE_MODE`: `auto` / `include_paths`
- `INCLUDE_PATHS`: semicolon-separated relative paths (`SCOPE_MODE=include_paths`)
- `EXCLUDE_DIRS`: semicolon-separated
- `NETWORK_MODE`: `none` / `allowlist` (recorded in summary)
- `TIMEOUT_LICENSE_MIN` / `TIMEOUT_GOSEC_MIN` / `TIMEOUT_CPPCHECK_MIN` / `TIMEOUT_LANG_SAST_MIN` / `TIMEOUT_CVE_MIN`
- `GRYPE_DB_CACHE_DIR`: offline Grype DB (`GRYPE_DB_AUTO_UPDATE=false` during the scan)
- `INPUT_SHA256`: source-tree hash (git commit or uploaded artifact)

## Required outputs

Under `/output/`:

- `summary.json` (required)
- `license.json` (required; Syft SBOM conversion by default, ScanCode / builtin fallback)
- `sbom.json` / `sbom.cdx.json` (CycloneDX JSON, Syft)
- `sbom.spdx.json` (SPDX JSON)
- `sbom.syft.json` (native Syft JSON)
- `gosec.json` (only if Go is detected; no stub if not)
- `cppcheck.xml` (only if C/C++ is detected)
- `eslint.json` (only if JS/TS is detected)
- `cve.json` (dependency CVE/SCA, schema `openmastiff.sca.v1`; engines from `policy.cve.engines`; implemented `grype`, reserved `trivy` / `osv-scanner`. The worker may later merge OSV/GitHub first-party advisories with `cve_scope=self|dependency`)
- `lang_sast_status.json` (language detection and skip reasons)
- `logs.txt` (recommended)

## `summary.json` (schema sketch)

`summary` is the **authoritative gate input for the worker** (the container may precompute counts).

Minimum fields:

- `meta.scan_id/request_id/started_at/ended_at/duration_ms`
- `input.input_sha256`, `input.scope`, `input.ecosystems_detected`
- `policy.policy_sha256` and threshold snapshot
- `tools.*.version/status/exit_code/duration_ms/error`
- `tools.gosec.counts`, `tools.cppcheck.counts`, `tools.bandit.counts`, `tools.pmd.counts`, `tools.cargo_audit.counts`, `tools.eslint.counts`
- `license.hits[]` and `unknown_or_low_confidence`

## Exit codes

- `0`: script finished (whether the gate passed or not)
- `10`: invalid input (`/input` unreadable, illegal scope, …)
- `20`: internal error (cannot write summary/output)

> GateFail is **not** an exit code. It lives in `summary.gate`.

## Scan queue concurrency

- Before taking a job, the worker claims a slot in the Redis set `openmastiff:scan:running`.
- Cap is `runner.max_concurrent_scans` (1–64, default 2), editable on the Policy page.
- When full, the job retries every 20 seconds and is not dropped. Batch create has no row cap; only this concurrency throttles scans.
- Celery concurrency (`CELERY_CONCURRENCY`, default 4) only sizes the worker pool; real parallel scans follow policy.
