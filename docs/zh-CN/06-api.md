<p align="right"><a href="../06-api.md">English</a> · <b>简体中文</b></p>

# 一期 API 草案（REST）

> 返回结构与鉴权细节一期先简化；核心是状态机、扫描链路、证据链约束。

默认本机启动端口为 `18000`（见 `backend/run_api.sh`）。

## Auth

- `GET /auth/review-roles`
  - 登录用户可拉取创建引入单时的审核角色选项（不含普通用户/只读）
- `GET /auth/roles`
  - 角色与成员管理（需 `auth.manage_roles`）

## Requests（引入单）

- `POST /requests`
  - 创建 Draft（可选 `title` / `owner` / `scan_scope`）
- `GET /requests`
  - 列表（支持状态/Gate/项目/`created_by`/`risk_level` 筛选；非 admin 仅看自己创建、负责或需自己会签的单）
- `GET /requests/{request_id}`
  - 详情（含 latest scan summary 摘要、Gate、法务/整改/豁免概览）
- `PATCH /requests/{request_id}`
  - 编辑引入单（扫描中不可改；仓库 URL / 分支 / 扫描范围在未通过前可改；审核角色仅草稿/复审可改）
- `DELETE /requests/{request_id}`
  - 删除引入单及关联扫描/发现/整改/法务记录（扫描中不可删）
- `POST /requests/{request_id}/submit`
  - 提交并触发扫描（创建 scan_run，先进入 Submitted，worker 开始后转 Scanning）
- `GET /requests/batch/template`
  - 下载批量创建 Excel 模板（需 `request.manage`）
- `POST /requests/batch/parse`
  - 上传已填模板，返回逐行校验结果（不落库；无行数上限）
- `POST /requests/batch`
  - 批量创建引入单并绑定 Git 源；`submit` 默认 `true`，确认后立即排队扫描
  - 无单批行数上限；实际同时跑的扫描数由策略 `runner.max_concurrent_scans`（1–64，默认 2）控制

## Policy（策略）

- `GET /policy` / `PUT /policy`
  - `runner.max_concurrent_scans`：后台扫描队列并发数，管理员可配

## Source（输入工件）

- `POST /requests/{request_id}/source/upload`
  - multipart 上传源码包（zip/tar.gz）
- `POST /requests/{request_id}/source/git`
  - 设置 repo/ref/credential_id

## Scans（扫描）

- `POST /requests/{request_id}/scans`
  - 触发复测（创建新 scan_run）
- `GET /scan-runs/{scan_run_id}`
  - scan_run 元数据 + summary（或摘要）
- `GET /scan-runs/{scan_run_id}/artifacts/{name}`
  - 下载或在线查看输出：`summary.json`、`license.json`、`sbom.*`、`cve.json`、`logs.txt`，以及本次实际识别到的语言报告（Go→`gosec.json`，C/C++→`cppcheck.xml`，Python→`bandit.json`，Java→`pmd.json`，Rust→`cargo-audit.json`，JS/TS→`eslint.json`）
  - 前端路径：`/requests/{request_id}/scans/{scan_run_id}`，按标签切换报告；`?report=` 指定当前报告文件名

## Legal review（法务）

- `POST /requests/{request_id}/legal-reviews`
  - 发起法务复核
- `POST /legal-reviews/{legal_review_id}/decision`
  - 回填结论 Allow/Deny + 依据
- `POST /legal-reviews/{legal_review_id}/attachment`
  - 上传法务依据附件

## Decision（评审结论）

- `POST /requests/{request_id}/decision`
  - 通过/条件通过/拒绝/豁免
  - 强校验：GateFail/PendingLegal 不可通过；豁免须风险接受人、补偿措施、到期时间
  - 研发经理等必审角色可录入结论（不强制 `review.manage`）

## Findings（发现项处置）

- `GET /requests/{request_id}/findings`
  - 默认最近一次扫描；含 `disposition`（open / false_positive / accepted_risk / confirmed）
- `POST /requests/{request_id}/findings/disposition`
  - 按 `fingerprints` 或 `rule_id` 批量处置；误报/接受风险须填写 `reason`
  - 处置后按剩余待处理 High/Error 重算门禁（许可证门禁不受误报影响）

## Remediation（整改）

- `POST /requests/{request_id}/remediations`
- `PATCH /remediations/{remediation_id}`
- `POST /remediations/{remediation_id}/close`

## Export（证据包 / 审查报告）

- `GET /requests/{request_id}/review-report`
  - 下载引入审查 PDF 报告：汇总最近一次扫描的门禁、许可证/SBOM、上游维护性、安全发现项、会签与整改
- `POST /requests/{request_id}/export`
  - 异步生成 zip
- `GET /exports/{export_id}`
  - 下载 zip

