# 数据模型（MongoDB）与索引（一期）

## 集合

### review_requests

- `status`：状态机
- `gate_status`：Pass/Fail/PendingLegal
- `project/environment/purpose/criticality/exposure/rollback_plan`
- `source_id`：输入工件引用
- `latest_scan_run_id`
- `decision`：评审结论快照引用（blob）
- `created_by/owner/created_at/updated_at`

索引：

- `(status, updated_at)`
- `(project, status)`
- `(gate_status, status)`

### sources

- `type`：upload/git
- upload：`filename/size/sha256/blob_id`
- git：`repo_url/ref/credential_id/commit_hash/workspace_sha256`

索引：

- upload：`(sha256)` 唯一
- git：`(repo_url, ref, commit_hash)`

### scan_runs

- `request_id/source_id`
- `status`：queued/running/succeeded/failed/timeout
- `input_hash/policy_hash`
- `docker`：image/container_id/limits/network_mode
- `outputs`：各报告的 blob 引用
- `started_at/ended_at/exit_code`

索引：

- `(request_id, started_at desc)`
- `(status, started_at)`

### findings

- `request_id/scan_run_id`
- `type`：gosec/cppcheck/license
- `severity/rule_id/fingerprint`
- `location`：file/line
- `message`
- `disposition`：open / false_positive / accepted_risk / confirmed（复测按 fingerprint 保留）

索引：

- `(scan_run_id, severity)`
- 可选唯一：`(scan_run_id, fingerprint)`

### gate_results

- `request_id/scan_run_id`
- `license_gate/gosec_gate/cppcheck_gate/overall`

索引：

- `(request_id, scan_run_id)`

### legal_reviews / remediations / waivers

按请求关联，略。

### evidence_blobs

- `sha256`（全局去重）
- `kind`：source/report/summary/policy/decision/legal/export/other
- `path`：本地卷路径
- `bytes/content_type/created_at/created_by`
- `request_id/scan_run_id`（可选关联）

索引：

- `(sha256)` 唯一
- `(request_id, created_at)`

### audit_logs（不可变）

- `request_id`
- `ts`、`seq`
- `actor_id`
- `event_type`
- `payload`（变更摘要）
- `prev_hash`、`hash`

索引：

- `(request_id, ts)`
- `(actor_id, ts)`
- `(event_type, ts)`

## 不可变策略（一期）

- DB 权限：应用账号对 `audit_logs` 禁止 update/delete；仅允许 insert。
- hash 链：同一 request_id 维度形成 `prev_hash -> hash` 链；导出时校验。
- 快照引用：policy/summary/原始报告/法务结论/最终结论等全部写 blob 并用 sha256 引用，避免“覆盖历史”。

