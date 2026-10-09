<p align="right"><a href="../07-wbs-by-domain.md">English</a> · <b>简体中文</b></p>

# 一期 WBS（按功能域）

## A. 基础平台域（账号/RBAC/数据域）

- 用户、角色、权限点
- 项目域隔离（最小：project scoped）
- 审计事件落库（所有关键操作）

验收：

- 未授权无法查看/导出他项目证据
- 关键操作均产生审计事件

## B. 引入单域（状态机/评审/法务/豁免/整改）

- 状态机约束（Gate/法务前置）
- 评审结论：通过/条件/拒绝/豁免
- 整改项：创建/关闭/复测
- 豁免：有效期、到期回流复审

验收：

- GateFail 不可通过；PendingLegal 未完成不可通过
- ConditionalApproved 必有整改项

## C. 输入工件域（upload + git）

- upload：大小限制、sha256、落 blob
- git：repo/ref/credential、clone/checkout、commit/workspace sha256

验收：

- 双入口均可触发扫描并产出证据

## D. 扫描执行域（Celery + Docker）

- 任务链：prepare → run_container → ingest → parse_gate → route
- Docker 沙箱：只读、cap drop、非 root、network none、资源配额、超时
- 进度与日志：scan_run 可观测

验收：

- 每次 scan_run 均产出 summary；超时策略按 Gate 生效

## E. 工具域（scanner 镜像）

- `gosec/cppcheck/scancode` 固定版本
- `run_scan.sh` 按协议输出
- 范围控制：exclude/include

验收：

- Go/C++ 样例仓库可跑通并输出一致格式

## F. 解析与门禁域（fingerprint/Gate）

- 三类报告解析
- fingerprint 生成、scan_run 内去重
- Gate 判定与状态路由

验收：

- gosec High>0 阻断；cppcheck error>0 阻断；GPL/AGPL/SSPL 触发法务

## G. 策略域（policy 配置与快照）

- policy 配置 CRUD
- scan_run 固化 policy.json 快照 blob + hash 引用

验收：

- 策略变更不影响历史扫描可复盘

## H. 证据与审计域（blob/hash 链/导出）

- blob 去重、关联
- audit_logs append-only + hash 链校验
- 导出 zip：manifest + hashes + audit_verify

验收：

- zip 可校验完整性与审计链一致性

## I. 前端域（最小可用）

- 列表、详情、扫描进度、下载报告、评审/法务/整改、导出

