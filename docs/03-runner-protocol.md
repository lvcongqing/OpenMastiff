# Runner 协议（scanner 容器）

## 目录挂载

- `/input`：只读源码
- `/output`：只写输出
- `/policy/policy.json`：只读策略快照

## 环境变量（一期）

- `SCAN_ID`：scan_run 标识
- `REQUEST_ID`：引入单标识
- `SCOPE_MODE`：`auto` / `include_paths`
- `INCLUDE_PATHS`：分号分隔（仅 include_paths）
- `EXCLUDE_DIRS`：分号分隔
- `NETWORK_MODE`：`none` / `allowlist`（用于 summary 记录）
- `TIMEOUT_LICENSE_MIN` / `TIMEOUT_GOSEC_MIN` / `TIMEOUT_CPPCHECK_MIN` / `TIMEOUT_LANG_SAST_MIN` / `TIMEOUT_CVE_MIN`
- `GRYPE_DB_CACHE_DIR`：Grype 离线漏洞库目录（扫描时 `GRYPE_DB_AUTO_UPDATE=false`）
- `INCLUDE_PATHS`：分号分隔的相对路径（`SCOPE_MODE=include_paths` 时生效）
- `INPUT_SHA256`：源码树哈希（git commit 或上传工件）

## 输出文件（强制）

`/output/`：

- `summary.json`（必需）
- `license.json`（必需；默认由 syft SBOM 转换，缺失时回退 scancode / 内置检测）
- `sbom.json` / `sbom.cdx.json`（CycloneDX JSON，默认由 syft 生成）
- `sbom.spdx.json`（SPDX JSON）
- `sbom.syft.json`（syft 原生 JSON）
- `gosec.json`（仅识别到 Go 时生成；未识别不写占位文件）
- `cppcheck.xml`（仅识别到 C/C++ 时生成）
- `eslint.json`（仅识别到 JS/TS 时生成）
- `cve.json`（依赖 CVE/SCA 规范结果，schema `openmastiff.sca.v1`；由 policy.cve.engines 选择引擎，当前实现 `grype`，预留 `trivy` / `osv-scanner`。Worker 随后可合并 OSV/GitHub 本软件公告，匹配项带 `cve_scope=self|dependency`）
- `lang_sast_status.json`（记录各语言检测与跳过状态）
- `logs.txt`（建议）

## summary.json（Schema 摘要）

summary 是 **worker 侧 Gate 判定的权威输入**（也可在容器内先计算 counts）。

最小必需字段：

- `meta.scan_id/request_id/started_at/ended_at/duration_ms`
- `input.input_sha256`、`input.scope`、`input.ecosystems_detected`
- `policy.policy_sha256` 与阈值快照
- `tools.*.version/status/exit_code/duration_ms/error`
- `tools.gosec.counts`、`tools.cppcheck.counts`、`tools.bandit.counts`、`tools.pmd.counts`、`tools.cargo_audit.counts`、`tools.eslint.counts`
- `license.hits[]` 与 `unknown_or_low_confidence`

## 退出码约定

- `0`：脚本执行完成（无论 Gate 是否通过）
- `10`：输入无效（/input 不可读、scope 非法等）
- `20`：内部错误（无法生成 summary、无法写输出等）

> GateFail 不通过退出码表达，而由 summary.gate 输出表达。

## 扫描队列并发

- Worker 领取任务前通过 Redis 集合 `openmastiff:scan:running` 占用槽位。
- 上限读取当前策略 `runner.max_concurrent_scans`（1–64，默认 2），管理员可在策略页修改。
- 槽位已满时任务按 20 秒间隔重试，不丢单。批量创建不设行数上限，只受该并发限制节流。
- Worker 默认以线程池领取任务（`CELERY_CONCURRENCY`，默认 4）；真正并行扫描数仍以策略并发为准。

