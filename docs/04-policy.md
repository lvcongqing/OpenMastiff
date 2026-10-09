# 默认策略与 Gate 规则（一期）

## License

- **deny_list**：命中任一 ⇒ `GateFail`
  - 默认：`Commons-Clause`
- **legal_review_list**：命中任一 ⇒ `PendingLegal`
  - 默认：`GPL-2.0`、`GPL-3.0`、`AGPL-3.0`、`SSPL-1.0`（可扩展通配）
- **unknown_policy**：`unknown -> legal_review`（默认）
- **score_threshold**：默认 80；低于阈值视为低置信度 ⇒ `PendingLegal`

## gosec

- **开关**：`gosec.enabled`（默认 true）。当设置为 false 时，即使检测到 Go 项目且未安装 gosec，也不会因为 gosec 缺失而阻断。
- **Gate**：`High > 0` ⇒ `GateFail`
- Medium/Low：不阻断（计入风险与整改建议）

## cppcheck

- **Gate**：`error > 0` ⇒ `GateFail`
- warning/style/performance/information：不阻断（计入风险与整改建议）

## 超时 Gate（一期默认）

- gosec/cppcheck timeout ⇒ `GateFail`（等价“未通过扫描”）
- license timeout ⇒ `PendingLegal`（提示拆分/缩小范围重扫）

## CVE / 依赖漏洞（SCA）

- **开关**：`cve.enabled`（默认 true）
- **engines**：默认 `["grype"]`。已预留 `trivy`、`osv-scanner`；未实现的引擎在 `cve.json.engines` 记为 skipped，不阻断已接入引擎。
- **输入**：优先消费 Syft 的 `sbom.syft.json` / CycloneDX，不重新遍历源码。
- **漏洞库**：Worker 扫描前按需 `grype db update` 到 `GRYPE_DB_CACHE_DIR`（默认 `/opt/openMastiff/data/grype-db`）；扫描进程使用已有库，默认不联网。安装版本需 ≥ v0.116（当前 pin `v0.119.0`），旧版无法激活现行漏洞库 schema。
- **Gate（依赖）**：依赖包 `Critical > block_if_critical_gt` 或 `High > block_if_high_gt` ⇒ `GateFail`（默认阈值均为 0）
- **Gate（本软件）**：`cve.self.block_if_critical_gt` / `block_if_high_gt`（默认 0）单独计数。默认 `allow_accepted_risk=false`：对本软件 Critical/High 标「接受风险」**不能**清门禁；误报仍可标记（匹配错误）。不修代码要放行只能走整单豁免（Waived）。
- **repo_advisory**：Worker 在扫描容器结束后按 git HEAD 查 OSV，并按本软件 `package.json` / `go.mod` / `pyproject.toml` / `Cargo.toml` 查包版本；GitHub 源额外拉仓库 Advisory。写入 `cve.json` 且 `cve_scope=self`。关闭 `cve.repo_advisory.enabled` 或 `maintenance.fetch_remote_metadata` 则跳过。
- **ignore_unfixed**：无修复版本的漏洞仍写入报告，但不计入门禁
- **fail_if_engine_missing**：Grype 未安装时是否失败（默认 false，仅跳过 CVE）
- **findings**：`category=cve`，发现项页按「本软件 / 依赖包 × 级别」归组

## 网络策略

- 默认：`network_mode=none`
- 可覆盖：`allowlist`（仅审核人可设置，必须写入证据链与审计）

## maintenance（项目活跃度 / 可维护性）

- **说明**：维护性扫描**不会**下载/安装业务依赖软件包；仅在本地解析 `go.mod`、`package.json`、`Cargo.toml`、`requirements.txt` / `pyproject.toml`、`debian/control` 等清单后，按需通过 HTTP 查询公开元数据：
  - 代码托管：GitHub、Gitee、AtomGit / GitCode、GitLab（含 salsa.debian.org）、kernel.org、Apache（gitbox → GitHub apache org）、Bitbucket、Codeberg
  - 软件仓库：PyPI、npm、crates.io、Go module proxy、Debian sources / salsa
  内网环境可将 `fetch_remote_metadata` 设为 `false`。
- **findings**：每次扫描会**替换**该单据下全部维护性 findings，前端/API 默认只展示 `latest_scan_run_id` 对应结果。
- **enabled**：是否启用维护性采集与门禁（默认 true）
- **fetch_remote_metadata**：是否访问外网元数据 API（默认 true；内网建议 false）
- **rules_by_criticality**：按引入单 `business_criticality` 分级。维护性门禁只有 `pass` / `fail`，**不会**转法务复核（`PendingLegal` 仅用于许可证）。
  - `critical` / `high`：归档、久未提交/发布、低评分、元数据未知 ⇒ `fail`
  - `medium`：同上，默认 `fail`（不再降级为待法务）
  - `low`：`advisory_only: true`，仅写入 findings，不阻断 Approved
- **dependency_thresholds**：直接依赖的发布间隔与评分阈值（不通过，不转法务）
- 扫描时由 worker 拉取上述社区元数据，写入 `summary.json.maintenance` 与 `maintenance.json`，并生成 `findings`（category=maintenance）

