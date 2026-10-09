# 一期最小闭环验收（Smoke Test）

## 前置

- 本机已启动：
  - Redis（本项目默认使用 `redis://localhost:6379/8`）
  - MongoDB（监听 `127.0.0.1:27017` 或本机可达）
  - API（默认 `0.0.0.0:18000`）
  - worker（Celery）

> 本机启动方式见 `README.md` 与 `docs/10-local-install.md`。

## 用例：upload → submit → scan_run → Gate → 状态路由

1）创建引入单（Draft）

```bash
curl -sS -X POST http://localhost:18000/requests \
  -H 'content-type: application/json' \
  -d '{
    "project":"demo",
    "environment":"dev",
    "purpose":"smoke test",
    "business_criticality":"low",
    "exposure":"internal",
    "rollback_plan":"remove dependency"
  }'
```

记录返回的 `request_id`。

2）准备一个最小 zip（任意内容即可）

```bash
mkdir -p /tmp/sc-demo && echo "hello" > /tmp/sc-demo/README.txt
cd /tmp && zip -r sc-demo.zip sc-demo >/dev/null
```

3）上传源码包

```bash
curl -sS -X POST "http://localhost:18000/requests/${request_id}/source/upload" \
  -F "artifact_file=@/tmp/sc-demo.zip"
```

4）提交触发扫描

```bash
curl -sS -X POST "http://localhost:18000/requests/${request_id}/submit"
```

记录返回的 `scan_run_id`。

5）查询 scan_run（直到 `status` 变为 succeeded/failed）

```bash
curl -sS "http://localhost:18000/scan-runs/${scan_run_id}"
```

6）查询引入单路由结果（应进入 Reviewing / Blocked / LegalReviewing）

```bash
curl -sS "http://localhost:18000/requests/${request_id}"
```

## 预期

- `scan_runs.outputs` 至少包含 `summary.json` 与 `license.json`；安装 syft 后还应包含 `sbom.cdx.json` / `sbom.spdx.json`
- 识别到 Python/Java/Rust/JS/TS 时还应有 `bandit.json` / `pmd.json` / `cargo-audit.json` / `eslint.json`，且 High>0 默认 Gate Fail（与 gosec 一致）
- 未识别到的语言不落盘对应报告（纯 Rust 仓库不应出现 gosec/bandit/pmd/eslint 文件）
- `scan_runs.gate_status` 出现（Pass/Fail/PendingLegal）
- `review_requests.status` 从 Submitted → Scanning，再路由到 Reviewing/Blocked/LegalReviewing

## 提示（避免环境干扰）

- 若机器上有其他 Celery 也在用 Redis，请确保本项目使用独立 DB（默认 `/8`）。
- 不建议对 Redis DB 执行 `flushdb`（会影响 Celery 内部状态与结果回写）。

## 批量创建与扫描并发

1）管理员在 **策略配置 → 扫描运行 → 扫描队列并发数** 设为 1–64（默认 2）并保存。

2）下载模板并解析（无行数上限）：

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://localhost:18000/requests/batch/template -o /tmp/om-batch.xlsx
curl -sS -H "Authorization: Bearer $TOKEN" \
  -F "artifact_file=@/tmp/om-batch.xlsx" \
  http://localhost:18000/requests/batch/parse
```

3）确认创建（默认立即提交扫描）：

```bash
curl -sS -X POST http://localhost:18000/requests/batch \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"submit":true,"items":[{"project":"batch-demo","purpose":"smoke","repo_url":"https://github.com/debug-js/debug.git","ref":"master"}]}'
```

预期：返回 `created[].status=Submitted` 与 `scan_run_id`；超出并发的扫描保持 `queued`，槽位释放后自动续跑。

## 维护性审查（活跃度）验证

一键刷新测试环境（合并 `maintenance` 策略、重启 API/Worker、生成演示 zip）：

```bash
bash scripts/refresh-test-env.sh
```

演示包路径：`/tmp/openmastiff-test/maintenance-demo.zip`（源目录 `test-fixtures/maintenance-demo/`，含 `go.mod` + `package.json`）。

### UI 查看

1. 打开前端 `https://<主机>/`（HTTP :80 会跳转至 HTTPS :443），使用 LDAP 账号登录。
2. **策略配置**：JSON 中应包含 `maintenance` 段（`enabled: true`）。
3. **新建引入单**：`business_criticality` 建议选 `medium` 或 `high`。
4. 上传 `maintenance-demo.zip`，或 Git 源 `https://github.com/gorilla/mux` + `main`。
5. **提交**触发扫描，等待状态离开 `Scanning`。
6. 进入详情 → **扫描** Tab：
   - 「项目维护性（活跃度）」：上游评分、Gate、风险依赖表
   - 可下载 `maintenance.json`
   - 若有风险项，会出现「维护性 Findings」

### 预期

- `summary.json` 含 `maintenance` 与 `gate.maintenance`
- `gate.overall` 会合并 scanner 与 maintenance 结果（取更严）
- Worker 需能访问 GitHub / Gitee / AtomGit / GitLab / kernel.org / PyPI / npm / crates.io / Debian 等（内网无外网时可暂时在策略中设 `maintenance.enabled: false`）

## CVE / 依赖漏洞（Grype）

1. 本机已安装 `grype`（`install.sh` pin `v0.119.0`）且 `GRYPE_DB_CACHE_DIR` 下有有效漏洞库。
2. 提交扫描后，`scan_runs.outputs` 应包含 `cve.json`（schema `openmastiff.sca.v1`），可选原始 `cve.grype.json`。
3. `summary.json.tools.cve` 有 counts / engines / status；`gate.cve` 为 pass 或 fail。
4. Critical/High 默认阈值均为 0：任一 Critical 或 High 会使 `gate.overall=Fail`。
5. 详情 **概览** 有 CVE 行；**扫描** Tab 可解读 `cve.json`。策略页可开关引擎（当前实现 `grype`，`trivy` / `osv-scanner` 预留为 skipped）。
6. 复测可对 `openeuler/skills` 等已有引入单触发 `POST /requests/{id}/trigger-scan`。

