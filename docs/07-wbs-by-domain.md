# Phase-1 WBS (by domain)

<p align="right"><b>English</b> · <a href="zh-CN/07-wbs-by-domain.md">简体中文</a></p>

## A. Platform (accounts / RBAC / tenancy)

- Users, roles, permission points
- Project-scoped isolation (minimum: project scoped)
- Audit events for every critical action

Acceptance:

- Unauthorized users cannot view or export another project's evidence
- Critical actions always produce an audit event

## B. Intake requests (state machine / review / legal / waiver / remediation)

- State-machine guards (Gate / legal prerequisites)
- Decisions: approve / conditional / reject / waive
- Remediations: create / close / rescan
- Waivers: expiry and auto-return to re-review

Acceptance:

- GateFail cannot be approved; PendingLegal cannot be approved until legal Allow
- ConditionalApproved requires at least one remediation item

## C. Input artifacts (upload + git)

- upload: size cap, SHA-256, blob store
- git: repo / ref / credential, clone / checkout, commit / workspace SHA-256

Acceptance:

- Either entry can start a scan and produce evidence

## D. Scan execution (Celery + Docker)

- Pipeline: prepare → run_container → ingest → parse_gate → route
- Docker sandbox: read-only, cap drop, non-root, network none, quotas, timeout
- Observability: `scan_run` progress and logs

Acceptance:

- Every `scan_run` produces a summary; timeout policy applies as a Gate

## E. Tools (scanner image)

- Pinned `gosec` / `cppcheck` / `scancode`
- `run_scan.sh` writes protocol outputs
- Scope: exclude / include

Acceptance:

- Sample Go / C++ repos complete and emit a stable format

## F. Parse and gates (fingerprint / Gate)

- Parse the three report families
- Fingerprints, de-dupe inside a `scan_run`
- Gate evaluation and status routing

Acceptance:

- gosec High > 0 blocks; cppcheck error > 0 blocks; GPL / AGPL / SSPL trigger legal review

## G. Policy (config and snapshots)

- Policy CRUD
- Each `scan_run` freezes a `policy.json` blob + hash ref

Acceptance:

- Later policy edits do not change how a historical scan can be replayed

## H. Evidence and audit (blobs / hash chain / export)

- Blob dedup and association
- `audit_logs` append-only + hash-chain verify
- Export zip: manifest + hashes + audit_verify

Acceptance:

- The zip can verify integrity and audit-chain consistency

## I. Web (minimum usable)

- List, detail, scan progress, report download, review / legal / remediation, export
