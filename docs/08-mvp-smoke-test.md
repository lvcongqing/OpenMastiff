# Phase-1 smoke test

<p align="right"><b>English</b> · <a href="zh-CN/08-mvp-smoke-test.md">简体中文</a></p>

## Prerequisites

Running locally:

- Redis (this project defaults to `redis://localhost:6379/8`)
- MongoDB (listening on `127.0.0.1:27017` or otherwise reachable)
- API (default `0.0.0.0:18000`)
- worker (Celery)

> How to start locally: `README.md` and `docs/10-local-install.md`.

## Case: upload → submit → scan_run → Gate → status routing

1) Create an intake request (Draft)

```bash
curl -sS -X POST http://localhost:18000/requests \
  -H 'content-type: application/json' \
  -d '{
    "project":"demo",
    "environment":"dev",
    "purpose":"smoke test",
    "business_criticality":"low",
    "exposure":"internal",
    "rollback_plan":"remove dependency"
  }'
```

Record the returned `request_id`.

2) Build a tiny zip (any content is fine)

```bash
mkdir -p /tmp/sc-demo && echo "hello" > /tmp/sc-demo/README.txt
cd /tmp && zip -r sc-demo.zip sc-demo >/dev/null
```

3) Upload the archive

```bash
curl -sS -X POST "http://localhost:18000/requests/${request_id}/source/upload" \
  -F "artifact_file=@/tmp/sc-demo.zip"
```

4) Submit to start a scan

```bash
curl -sS -X POST "http://localhost:18000/requests/${request_id}/submit"
```

Record the returned `scan_run_id`.

5) Poll the `scan_run` until `status` is succeeded or failed

```bash
curl -sS "http://localhost:18000/scan-runs/${scan_run_id}"
```

6) Read request routing (should land in Reviewing / Blocked / LegalReviewing)

```bash
curl -sS "http://localhost:18000/requests/${request_id}"
```

## Expected

- `scan_runs.outputs` includes at least `summary.json` and `license.json`; with Syft installed also `sbom.cdx.json` / `sbom.spdx.json`
- Detected Python / Java / Rust / JS / TS also produce `bandit.json` / `pmd.json` / `cargo-audit.json` / `eslint.json`; High > 0 defaults to Gate Fail (same as gosec)
- Languages that were not detected do not write a stub report (a pure Rust repo must not contain gosec / bandit / pmd / eslint files)
- `scan_runs.gate_status` is set (Pass / Fail / PendingLegal)
- `review_requests.status` moves Submitted → Scanning, then routes to Reviewing / Blocked / LegalReviewing

## Tips (avoid host interference)

- If other Celery apps share Redis, keep this project on its own DB (default `/8`).
- Do not `flushdb` that Redis DB (it breaks Celery internals and result write-back).

## Batch create and scan concurrency

1) On **Policy → Scan runner → Scan queue concurrency**, set 1–64 (default 2) and save.

2) Download and parse a template (no row cap):

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:18000/requests/batch/template -o /tmp/om-batch.xlsx
curl -sS -H "Authorization: Bearer $TOKEN" \
  -F "artifact_file=@/tmp/om-batch.xlsx" \
  http://localhost:18000/requests/batch/parse
```

3) Confirm create (default: submit scans immediately):

```bash
curl -sS -X POST http://localhost:18000/requests/batch \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"submit":true,"items":[{"project":"batch-demo","purpose":"smoke","repo_url":"https://github.com/debug-js/debug.git","ref":"master"}]}'
```

Expected: `created[].status=Submitted` plus `scan_run_id`; scans beyond the concurrency cap stay `queued` and resume when a slot frees.

## Maintainability (activity) check

Refresh a test environment (merge `maintenance` policy, restart API / Worker, build a demo zip):

```bash
bash scripts/refresh-test-env.sh
```

Demo archive: `/tmp/openmastiff-test/maintenance-demo.zip` (source `test-fixtures/maintenance-demo/`, with `go.mod` + `package.json`).

### UI

1. Open `https://<host>/` (HTTP :80 redirects to HTTPS :443) and sign in (LDAP or local).
2. **Policy**: JSON should include a `maintenance` block (`enabled: true`).
3. **New request**: prefer `business_criticality` `medium` or `high`.
4. Upload `maintenance-demo.zip`, or Git `https://github.com/gorilla/mux` + `main`.
5. **Submit**, wait until status leaves `Scanning`.
6. Detail → **Scans** tab:
   - “Project maintainability (activity)”: upstream scores, Gate, risky-dependency table
   - Download `maintenance.json`
   - Risky items show “Maintainability findings”

### Expected

- `summary.json` contains `maintenance` and `gate.maintenance`
- `gate.overall` merges scanner and maintenance (stricter wins)
- The worker needs GitHub / Gitee / AtomGit / GitLab / kernel.org / PyPI / npm / crates.io / Debian (or set `maintenance.enabled: false` on an isolated network)

## CVE / dependency vulnerabilities (Grype)

1. Host has `grype` (`install.sh` pins `v0.119.0`) and a valid DB under `GRYPE_DB_CACHE_DIR`.
2. After submit, `scan_runs.outputs` includes `cve.json` (schema `openmastiff.sca.v1`) and optionally raw `cve.grype.json`.
3. `summary.json.tools.cve` has counts / engines / status; `gate.cve` is pass or fail.
4. Critical / High thresholds default to 0: any Critical or High makes `gate.overall=Fail`.
5. Detail **Overview** shows a CVE row; the **Scans** tab interprets `cve.json`. Policy can toggle engines (implemented: `grype`; `trivy` / `osv-scanner` reserved as skipped).
6. Rescan an existing request such as `openeuler/skills` with `POST /requests/{id}/trigger-scan`.
