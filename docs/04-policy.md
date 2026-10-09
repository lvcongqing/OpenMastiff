# Default policy and gates (phase 1)

<p align="right"><b>English</b> · <a href="zh-CN/04-policy.md">简体中文</a></p>

## License

- **deny_list**: any hit ⇒ `GateFail`
  - Default: `Commons-Clause`
- **legal_review_list**: any hit ⇒ `PendingLegal`
  - Default: `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `SSPL-1.0` (wildcards allowed)
- **unknown_policy**: `unknown -> legal_review` (default)
- **score_threshold**: default 80; below the threshold is treated as low confidence ⇒ `PendingLegal`

## gosec

- **Toggle**: `gosec.enabled` (default true). When false, a missing gosec binary does not block even if Go is detected.
- **Gate**: `High > 0` ⇒ `GateFail`
- Medium / Low: do not block (counted toward risk and remediation)

## cppcheck

- **Gate**: `error > 0` ⇒ `GateFail`
- warning / style / performance / information: do not block (counted toward risk and remediation)

## Timeout gates (phase-1 defaults)

- gosec / cppcheck timeout ⇒ `GateFail` (treated as scan not passed)
- license timeout ⇒ `PendingLegal` (hint: split or shrink the scan scope and retry)

## CVE / dependency vulnerabilities (SCA)

- **Toggle**: `cve.enabled` (default true)
- **engines**: default `["grype"]`. `trivy` and `osv-scanner` are reserved; unimplemented engines are recorded as skipped in `cve.json.engines` and do not block engines that are wired in.
- **Input**: prefer Syft `sbom.syft.json` / CycloneDX; do not re-walk the source tree.
- **Vulnerability DB**: before a scan, the worker may run `grype db update` into `GRYPE_DB_CACHE_DIR` (default `/opt/openMastiff/data/grype-db`). The scan process uses the cached DB and does not reach the network by default. Install Grype ≥ v0.116 (this tree pins `v0.119.0`); older builds cannot activate the current DB schema.
- **Gate (dependencies)**: package `Critical > block_if_critical_gt` or `High > block_if_high_gt` ⇒ `GateFail` (both thresholds default to 0)
- **Gate (first-party)**: `cve.self.block_if_critical_gt` / `block_if_high_gt` (default 0) are counted separately. Default `allow_accepted_risk=false`: marking first-party Critical / High as “accepted risk” **cannot** clear the gate; false positives (wrong match) may still be marked. To ship without a code fix, use a request-level waiver (`Waived`).
- **repo_advisory**: after the scanner container exits, the worker queries OSV at git HEAD and looks up first-party versions from `package.json` / `go.mod` / `pyproject.toml` / `Cargo.toml`. GitHub sources also fetch repository advisories. Results are written into `cve.json` with `cve_scope=self`. Skip when `cve.repo_advisory.enabled` or `maintenance.fetch_remote_metadata` is off.
- **ignore_unfixed**: vulnerabilities with no fixed version stay in the report but are excluded from the gate
- **fail_if_engine_missing**: whether a missing Grype binary fails the scan (default false: skip CVE only)
- **findings**: `category=cve`, grouped on the Findings page by “first-party / dependency × severity”

## Network policy

- Default: `network_mode=none`
- Override: `allowlist` (reviewers only; must be written into the evidence chain and audit log)

## maintenance (project activity / maintainability)

- **Note**: maintainability scans **do not** download or install application dependencies. They parse local manifests (`go.mod`, `package.json`, `Cargo.toml`, `requirements.txt` / `pyproject.toml`, `debian/control`, …) and optionally query public metadata over HTTP:
  - Forges: GitHub, Gitee, AtomGit / GitCode, GitLab (including salsa.debian.org), kernel.org, Apache (gitbox → GitHub apache org), Bitbucket, Codeberg
  - Registries: PyPI, npm, crates.io, Go module proxy, Debian sources / salsa
  Set `fetch_remote_metadata` to `false` on an isolated network.
- **findings**: each scan **replaces** all maintainability findings on that request; the UI / API default to the `latest_scan_run_id` set.
- **enabled**: collect data and apply the gate (default true)
- **fetch_remote_metadata**: call public metadata APIs (default true; prefer false on an intranet)
- **rules_by_criticality**: keyed by the request `business_criticality`. The maintainability gate is only `pass` / `fail`; it **never** routes to legal (`PendingLegal` is license-only).
  - `critical` / `high`: archived, stale commits/releases, low score, or unknown metadata ⇒ `fail`
  - `medium`: same as above, default `fail` (no longer downgraded to legal review)
  - `low`: `advisory_only: true` — findings only, does not block Approved
- **dependency_thresholds**: release-interval and score thresholds for direct dependencies (fail does not go to legal)
- The worker writes `summary.json.maintenance` and `maintenance.json`, and creates `findings` with `category=maintenance`
