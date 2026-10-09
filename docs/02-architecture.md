# 一期架构设计

## 组件

- **API 服务**：FastAPI（单据、评审、策略、导出、鉴权）
- **异步任务**：Celery（Redis 作为 broker + backend）
- **数据库**：MongoDB（文档模型适配扫描结果与证据元数据）
- **Blob 存储**：一期本地卷 `/data/blobs`（sha256 去重），可平滑替换为 MinIO(S3)
- **Runner 执行器**：Docker（worker 通过 Docker API 启动短生命周期扫描容器）

## 数据流（主链）

1. 创建引入单（Draft）
2. 设置输入工件（upload 或 git）
3. 提交（Submitted）→ 触发 `start_scan`
4. worker：
   - 准备 workspace（解压或 git 拉取）
   - 计算 `input_sha256`
   - 启动 `scanner` 容器（挂载 /input、/output、/policy）
   - 收集输出（summary + 原始报告）→ 写入 blobs
   - 解析 summary 与报告 → 生成 `findings` + `gate_results`
   - 状态路由：Fail→Blocked；PendingLegal→LegalReviewing；Pass→Reviewing
5. 评审/法务出结论 → 进入整改/复测 → 最终归档

## 隔离与安全（一期最低要求）

- 扫描容器：
  - `read_only`、`cap_drop=ALL`、`no-new-privileges`
  - 非 root 用户
  - 默认 `network=none`
  - `pids_limit`、CPU/内存/磁盘/超时配额
- worker：
  - 独占 Docker socket（扫描容器不可接触）
- 证据与审计：
  - `audit_logs` append-only（DB 权限禁止 update/delete）
  - hash 链可校验

## 可扩展点（二期接 Gerrit）

- Source 扩展：从 change/commit 拉取
- Gate 输出映射：阻断/告警 → Gerrit label
- 自动触发：提交即扫描、回写评审结果

