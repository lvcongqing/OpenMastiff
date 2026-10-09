# Phase-1 REST API

<p align="right"><b>English</b> · <a href="zh-CN/06-api.md">简体中文</a></p>

> Response envelopes and auth details are simplified in phase 1. The important constraints are the state machine, scan pipeline, and evidence chain.

The local API default port is `18000` (see `backend/run_api.sh`).

## Auth

- `GET /auth/review-roles`
  - Signed-in users fetch review-role options for a new request (excludes ordinary / read-only users)
- `GET /auth/roles`
  - Role and membership admin (`auth.manage_roles` required)

## Requests

- `POST /requests`
  - Create a Draft (optional `title` / `owner` / `scan_scope`)
- `GET /requests`
  - List (filter by status / Gate / project / `created_by` / `risk_level`; non-admins see only requests they created, own, or must sign)
- `GET /requests/{request_id}`
  - Detail (latest scan summary, Gate, legal / remediation / waiver overview)
- `PATCH /requests/{request_id}`
  - Edit a request (locked while scanning; repo URL / branch / scan scope may change until the request is approved; review roles only in Draft / ReReview)
- `DELETE /requests/{request_id}`
  - Delete the request and related scans / findings / remediations / legal records (blocked while scanning)
- `POST /requests/{request_id}/submit`
  - Submit and start a scan (creates a `scan_run`; status is `Submitted` until the worker moves it to `Scanning`)
- `GET /requests/batch/template`
  - Download the batch-create Excel template (`request.manage` required)
- `POST /requests/batch/parse`
  - Upload a filled template; returns per-row validation (no persist; no row cap)
- `POST /requests/batch`
  - Batch-create requests and bind Git sources; `submit` defaults to `true` so confirm queues scans immediately
  - No per-batch row cap; live parallel scans are throttled by policy `runner.max_concurrent_scans` (1–64, default 2)

## Policy

- `GET /policy` / `PUT /policy`
  - `runner.max_concurrent_scans`: worker scan-queue concurrency (admin)

## Source (input artifact)

- `POST /requests/{request_id}/source/upload`
  - multipart source archive (zip / tar.gz)
- `POST /requests/{request_id}/source/git`
  - set repo / ref / credential_id

## Scans

- `POST /requests/{request_id}/scans`
  - Trigger a rescan (new `scan_run`)
- `GET /scan-runs/{scan_run_id}`
  - `scan_run` metadata + summary
- `GET /scan-runs/{scan_run_id}/console`
  - Tail of workspace `logs.txt` while the run is `queued` or `running`; `live=false` means the job has finished
- `GET /scan-runs/{scan_run_id}/artifacts/{name}`
  - Download or view outputs: `summary.json`, `license.json`, `sbom.*`, `cve.json`, `logs.txt`, plus language reports actually produced (Go → `gosec.json`, C/C++ → `cppcheck.xml`, Python → `bandit.json`, Java → `pmd.json`, Rust → `cargo-audit.json`, JS/TS → `eslint.json`)
  - Web path: `/requests/{request_id}/scans/{scan_run_id}`; `?report=` selects the current report file

## Legal review

- `POST /requests/{request_id}/legal-reviews`
  - Start a legal review
- `POST /legal-reviews/{legal_review_id}/decision`
  - Record Allow / Deny plus rationale
- `POST /legal-reviews/{legal_review_id}/attachment`
  - Upload supporting files

## Decision

- `POST /requests/{request_id}/decision`
  - Approve / conditional approve / reject / waive
  - Hard checks: GateFail / PendingLegal cannot approve; a waiver needs a risk owner, compensating controls, and expiry
  - Required reviewer roles (e.g. R&D manager) may record a conclusion without `review.manage`

## Findings (disposition)

- `GET /requests/{request_id}/findings`
  - Defaults to the latest scan; includes `disposition` (open / false_positive / accepted_risk / confirmed)
- `POST /requests/{request_id}/findings/disposition`
  - Batch by `fingerprints` or `rule_id`; false positive / accepted risk require `reason`
  - After disposition, remaining open High / Error findings recompute the gate (license gates ignore false-positive marks)

## Remediation

- `POST /requests/{request_id}/remediations`
- `PATCH /remediations/{remediation_id}`
- `POST /remediations/{remediation_id}/close`

## Export (evidence pack / review report)

- `GET /requests/{request_id}/review-report`
  - Download the intake-review PDF: latest scan gates, licenses / SBOM, upstream maintainability, security findings, sign-off, remediations
- `POST /requests/{request_id}/export`
  - Build a zip asynchronously
- `GET /exports/{export_id}`
  - Download the zip
