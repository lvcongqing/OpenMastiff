# Data model (MongoDB) and indexes (phase 1)

<p align="right"><b>English</b> · <a href="zh-CN/05-data-model.md">简体中文</a></p>

## Collections

### review_requests

- `status`: state machine
- `gate_status`: Pass / Fail / PendingLegal
- `project` / `environment` / `purpose` / `criticality` / `exposure` / `rollback_plan`
- `source_id`: input artifact reference
- `latest_scan_run_id`
- `decision`: snapshot of the review conclusion (blob)
- `created_by` / `owner` / `created_at` / `updated_at`

Indexes:

- `(status, updated_at)`
- `(project, status)`
- `(gate_status, status)`

### sources

- `type`: upload / git
- upload: `filename` / `size` / `sha256` / `blob_id`
- git: `repo_url` / `ref` / `credential_id` / `commit_hash` / `workspace_sha256`

Indexes:

- upload: unique `(sha256)`
- git: `(repo_url, ref, commit_hash)`

### scan_runs

- `request_id` / `source_id`
- `status`: queued / running / succeeded / failed / timeout
- `input_hash` / `policy_hash`
- `docker`: image / container_id / limits / network_mode
- `outputs`: blob refs for each report
- `started_at` / `ended_at` / `exit_code`

Indexes:

- `(request_id, started_at desc)`
- `(status, started_at)`

### findings

- `request_id` / `scan_run_id`
- `type`: gosec / cppcheck / license
- `severity` / `rule_id` / `fingerprint`
- `location`: file / line
- `message`
- `disposition`: open / false_positive / accepted_risk / confirmed (kept across rescans by fingerprint)

Indexes:

- `(scan_run_id, severity)`
- optional unique: `(scan_run_id, fingerprint)`

### gate_results

- `request_id` / `scan_run_id`
- `license_gate` / `gosec_gate` / `cppcheck_gate` / `overall`

Indexes:

- `(request_id, scan_run_id)`

### legal_reviews / remediations / waivers

Keyed by request; details omitted here.

### evidence_blobs

- `sha256` (global dedup)
- `kind`: source / report / summary / policy / decision / legal / export / other
- `path`: local volume path
- `bytes` / `content_type` / `created_at` / `created_by`
- `request_id` / `scan_run_id` (optional)

Indexes:

- unique `(sha256)`
- `(request_id, created_at)`

### audit_logs (immutable)

- `request_id`
- `ts`, `seq`
- `actor_id`
- `event_type`
- `payload` (change summary)
- `prev_hash`, `hash`

Indexes:

- `(request_id, ts)`
- `(actor_id, ts)`
- `(event_type, ts)`

## Immutability (phase 1)

- DB privileges: the app account cannot update or delete `audit_logs`; insert only.
- Hash chain: `prev_hash -> hash` per `request_id`; verified on export.
- Snapshot refs: policy / summary / raw reports / legal conclusion / final decision are stored as blobs and referenced by SHA-256 so history is never overwritten.
