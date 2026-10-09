# Phase-1 architecture

<p align="right"><b>English</b> · <a href="zh-CN/02-architecture.md">简体中文</a></p>

## Components

- **API**: FastAPI (requests, review, policy, export, auth)
- **Jobs**: Celery (Redis broker + backend)
- **Database**: MongoDB (scan results and evidence metadata)
- **Blobs**: local volume `/data/blobs` (SHA-256 dedup); replaceable with MinIO/S3 later
- **Runner**: Docker (the worker starts short-lived scanner containers via the Docker API)

## Main data flow

1. Create an intake request (Draft)
2. Attach an input artifact (upload or git)
3. Submit (`Submitted`) → `start_scan`
4. Worker:
   - Prepare workspace (extract or git clone)
   - Compute `input_sha256`
   - Start the `scanner` container (mount `/input`, `/output`, `/policy`)
   - Collect outputs (summary + raw reports) → blobs
   - Parse summary and reports → `findings` + `gate_results`
   - Route: Fail→Blocked; PendingLegal→LegalReviewing; Pass→Reviewing
5. Role / legal decision → remediation / rescan → archive

## Isolation (phase-1 minimum)

- Scanner container:
  - `read_only`, `cap_drop=ALL`, `no-new-privileges`
  - non-root
  - default `network=none`
  - `pids_limit`, CPU / memory / disk / timeout quotas
- Worker holds the Docker socket; scanner containers do not
- Evidence and audit:
  - `audit_logs` append-only (DB role forbids update/delete)
  - hash chain is verifiable

## Extension points (phase 2: Gerrit)

- Source: pull from a change/commit
- Map gate output to a Gerrit label
- Auto-trigger on submit and write review results back
