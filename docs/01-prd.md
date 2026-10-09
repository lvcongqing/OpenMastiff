# 一期 PRD（字段级）

## 目标与范围

- **目标**：将“开源依赖引入/升级”的安全合规审查做成可配置门禁、可追溯证据链、可闭环整改的系统。
- **一期范围**：仅系统内置执行扫描（不支持外部自跑报告上传）。
- **技术栈**：Python + NoSQL(MongoDB) + Redis + Docker（runner 容器沙箱）。

## 角色与权限（默认）

- **申请方**：创建/编辑草稿、提交、查看本项目单据、发起复测、补充材料
- **供应链安全**：评审结论、配置策略、发起法务复核、发起/关闭整改、豁免
- **法务**：处理法务复核、出具结论、上传依据
- **审计只读**：查看、导出证据包
- **管理员**：用户/角色/项目域/凭据库管理

## 状态机

- `Draft` → `Submitted` → `Scanning` → `Reviewing`
- `Reviewing` 分支：
  - `LegalReviewing`（PendingLegal）
  - `Blocked`（GateFail）
  - `Approved` / `ConditionalApproved`
  - `Rejected` / `Waived`
- `ConditionalApproved` → `Remediating` → `ReReview` → `Approved`
- `Waived` 到期：自动回流 `ReReview`（或策略指定 `Blocked`）

**约束**

- 存在 `GateFail`：禁止 `Approved/ConditionalApproved`
- 存在 `PendingLegal` 且法务未 Allow：禁止 `Approved/ConditionalApproved`
- `ConditionalApproved`：必须包含 ≥1 `remediation_item`

## 页面与字段

### 1）引入单列表（Requests）

- 展示：`request_id`、`title`、`status`、`gate_status`（Pass/Fail/PendingLegal）、`risk_level`
- 展示：`project`、`owner`、`created_by`、`updated_at`
- 筛选：状态、Gate、风险、项目、创建人、时间
- 操作：新建、查看、导出（有权限）

### 2）新建引入单（New Request）

**基础信息（必填）**

- `project`：项目/系统
- `environment`：dev/stage/prod/other
- `purpose`：用途说明
- `business_criticality`：low/medium/high/critical
- `exposure`：internal/public
- `rollback_plan`：回滚方案

**输入工件（提交后锁定，二选一）**

- `source_type=upload`
  - `artifact_file`：zip/tar.gz（大小上限、后缀白名单）
- `source_type=git`
  - `repo_url`、`ref`（branch/tag/commit）
  - `credential_id`（token/ssh key 引用）

**扫描范围（默认 auto）**

- `scan_scope.mode`：`auto` / `include_paths`
- `scan_scope.include_paths[]`（仅 include_paths）

**网络策略（默认 none，仅审核人可覆盖）**

- `runner.network_mode_override`：`none` / `allowlist`
- `runner.network_allowlist_snapshot[]`

操作：保存草稿 / 提交（触发扫描）

### 3）引入单详情（Request Detail）

Tab：

- 概览：基本信息、状态、Gate 总结、结论
- 输入工件：upload sha256 或 git commit + workspace sha256
- 扫描结果：最新 `scan_run` 摘要 + 原始报告下载 + 历史 runs
- 法务复核：状态、结论、附件
- 整改项：列表、责任人、截止、关联 fingerprints、复测
- 审计与证据：审计时间线、证据对象、导出 zip

### 4）评审工作台（Review Inbox）

- 待办：Reviewing / Blocked / PendingLegal
- 快捷操作：通过/条件通过/拒绝/豁免

### 5）策略配置（Policies）

- License：deny_list、legal_review_list、unknown_policy、score_threshold
- gosec：High 阈值（默认 High>0 阻断）
- cppcheck：error 阈值（默认 error>0 阻断）
- 豁免：有效期上限、必填字段
- runner：默认网络策略、默认排除目录、工具超时

### 6）凭据库（Credentials）

- 类型：`http_token` / `ssh_key`
- 字段：名称、用途、repo 范围（可选）、创建人、更新时间

## 证据链要求（一期必做）

- 每个 `scan_run` 固化：输入哈希、策略快照哈希、工具版本、命令、原始报告、summary
- 关键操作写入审计日志（不可变 + hash 链）
- 支持导出证据包 zip（含 hashes.json 与链校验）

