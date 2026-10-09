# Phase-1 PRD (field-level)

<p align="right"><b>English</b> · <a href="zh-CN/01-prd.md">简体中文</a></p>

## Goal and scope

- **Goal**: Turn open-source dependency intake/upgrade into a configurable gate, an auditable evidence chain, and a closed remediation loop.
- **Phase 1**: Scans run inside the platform only (no upload of externally produced reports).
- **Stack**: Python + MongoDB + Redis + Docker (scanner sandbox).

## Roles and permissions (defaults)

- **Requester**: create/edit drafts, submit, view own project requests, rescan, attach materials
- **Supply-chain security**: review decisions, edit policy, start legal review, open/close remediations, waive
- **Legal**: handle license review, record allow/deny, upload rationale
- **Audit (read-only)**: view and export evidence packs
- **Admin**: users, roles, project domains, credential store

## State machine

- `Draft` → `Submitted` → `Scanning` → `Reviewing`
- From `Reviewing`:
  - `LegalReviewing` (`PendingLegal`)
  - `Blocked` (`GateFail`)
  - `Approved` / `ConditionalApproved`
  - `Rejected` / `Waived`
- `ConditionalApproved` → `Remediating` → `ReReview` → `Approved`
- Expired `Waived`: auto-return to `ReReview` (or `Blocked` if policy says so)

**Constraints**

- `GateFail` forbids `Approved` / `ConditionalApproved`
- `PendingLegal` without legal Allow forbids `Approved` / `ConditionalApproved`
- `ConditionalApproved` requires ≥1 `remediation_item`

## Pages and fields

### 1) Requests list

- Columns: `request_id`, `title`, `status`, `gate_status` (Pass/Fail/PendingLegal), `risk_level`
- Also: `project`, `owner`, `created_by`, `updated_at`
- Filters: status, gate, risk, project, creator, time
- Actions: new, view, export (if permitted)

### 2) New request

**Required basics**

- `project`: project / system
- `environment`: dev/stage/prod/other
- `purpose`
- `business_criticality`: low/medium/high/critical
- `exposure`: internal/public
- `rollback_plan`

**Input artifact (locked after submit; pick one)**

- `source_type=upload`
  - `artifact_file`: zip/tar.gz (size cap, suffix allowlist)
- `source_type=git`
  - `repo_url`, `ref` (branch/tag/commit)
  - `credential_id` (token / SSH key reference)

**Scan scope (default `auto`)**

- `scan_scope.mode`: `auto` / `include_paths`
- `scan_scope.include_paths[]` (when `include_paths`)

**Network policy (default `none`; reviewers only may override)**

- `runner.network_mode_override`: `none` / `allowlist`
- `runner.network_allowlist_snapshot[]`

Actions: save draft / submit (starts a scan)

### 3) Request detail

Tabs:

- Overview: metadata, status, gate summary, decision
- Input: upload sha256 or git commit + workspace sha256
- Scans: latest `scan_run` summary, raw reports, history
- Legal: status, decision, attachments
- Remediation: list, owner, due date, fingerprints, rescan
- Audit: timeline, evidence objects, zip export

### 4) Review inbox

- Queue: Reviewing / Blocked / PendingLegal
- Actions: pass / conditional / reject / waive

### 5) Policy

- License: deny_list, legal_review_list, unknown_policy, score_threshold
- gosec: High threshold (default High > 0 blocks)
- cppcheck: error threshold (default error > 0 blocks)
- Waiver: max days, required fields
- Runner: default network, exclude dirs, tool timeouts

### 6) Credentials

- Types: `http_token` / `ssh_key`
- Fields: name, purpose, optional repo scope, creator, updated_at

## Evidence chain (phase-1 required)

- Each `scan_run` freezes: input hash, policy snapshot hash, tool versions, command, raw reports, summary
- Critical actions append to the audit log (immutable + hash chain)
- Evidence-pack zip export (`hashes.json` + chain verification)
