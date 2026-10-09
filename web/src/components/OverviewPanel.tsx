import { type CSSProperties, type ReactNode } from "react";
import {
  Alert,
  Button,
  Card,
  Space,
  Tag,
  Typography,
  Upload,
  message,
} from "antd";
import {
  ExportOutlined,
  FilePdfOutlined,
  PlayCircleOutlined,
  UploadOutlined,
} from "@ant-design/icons";
import { GATE_STATUS_LABELS, MAINT_SOURCE_LABELS } from "../constants/display";
import { decodeRollbackPlan, getRollbackPlan } from "../constants/rollbackPlans";
import { useI18n } from "../i18n/LocaleContext";

type Brief = Record<string, unknown> | null;

type InfoItem = { label: string; value: ReactNode; span?: 1 | 2 | 3 };

function InfoGrid({ items, style }: { items: InfoItem[]; style?: CSSProperties }) {
  return (
    <div className="info-grid" style={style}>
      {items.map((it, i) => (
        <div key={`${it.label}-${i}`} className={`info-grid-cell span-${it.span || 1}`}>
          <div className="info-grid-label">{it.label}</div>
          <div className="info-grid-value">{it.value}</div>
        </div>
      ))}
    </div>
  );
}

function rollbackDisplay(raw: string): ReactNode {
  const { key, notes } = decodeRollbackPlan(raw);
  const meta = getRollbackPlan(key);
  if (!meta || key === "other") {
    return notes || raw || "—";
  }
  return (
    <div>
      <div>{meta.label}</div>
      <Typography.Text type="secondary" style={{ fontSize: 12, lineHeight: 1.55 }}>
        {meta.detail}
      </Typography.Text>
    </div>
  );
}

function gateTag(status?: string) {
  const raw = String(status || "");
  const s = raw.toLowerCase();
  const color = s === "pass" ? "success" : s === "fail" ? "error" : s === "pending_legal" ? "warning" : "default";
  const norm =
    s === "pass" ? "Pass" : s === "fail" ? "Fail" : s === "pending_legal" ? "PendingLegal" : raw;
  return <Tag color={color}>{GATE_STATUS_LABELS[norm] || raw || "—"}</Tag>;
}

type Props = {
  req: Record<string, unknown>;
  brief: Brief;
  isDraft: boolean;
  hasSource: boolean;
  canRescan: boolean;
  onSubmitScan: () => void;
  onRescan: () => void;
  onExport: () => void;
  onDownloadReport?: () => void;
  reportBusy?: boolean;
  source?: Record<string, unknown> | null;
  canEditSource?: boolean;
  onUploadSource?: (file: File) => Promise<void>;
};

export default function OverviewPanel({
  req,
  brief,
  isDraft,
  hasSource,
  canRescan,
  onSubmitScan,
  onRescan,
  onExport,
  onDownloadReport,
  reportBusy,
  source,
  canEditSource,
  onUploadSource,
}: Props) {
  const { t } = useI18n();

  const gates = ((brief?.gates || {}) as Record<string, { status?: string; reason?: string }>) || {};
  const lic = ((brief?.license || {}) as {
    top_licenses?: { license: string; count: number }[];
    deny_hits?: string[];
    legal_review_hits?: string[];
    unknown_or_low_confidence?: boolean;
    note?: string;
    engine?: string;
    package_count?: number;
  }) || {};
  const maint = ((brief?.maintenance || {}) as {
    overall?: { status?: string; reason?: string };
    upstream?: Record<string, unknown>;
  }) || {};
  const upstream = (maint.upstream || {}) as Record<string, unknown>;
  const upGate = (upstream.gate || {}) as { status?: string; reason?: string };
  const maintGate = (maint.overall || gates.maintenance || {}) as { status?: string; reason?: string };
  const gosec = ((brief?.gosec as { counts?: Record<string, number> }) || {}).counts || {};
  const cpp = ((brief?.cppcheck as { counts?: Record<string, number> }) || {}).counts || {};
  const bandit = ((brief?.bandit as { counts?: Record<string, number> }) || {}).counts || {};
  const pmd = ((brief?.pmd as { counts?: Record<string, number> }) || {}).counts || {};
  const cargo = ((brief?.cargo_audit as { counts?: Record<string, number> }) || {}).counts || {};
  const eslint = ((brief?.eslint as { counts?: Record<string, number> }) || {}).counts || {};
  const cve = ((brief?.cve as { counts?: Record<string, number>; engine?: string; match_count?: number }) || {});
  const cveCounts = cve.counts || {};
  const ecosystems = ((brief?.ecosystems_detected as string[]) || []).map((x) => String(x).toLowerCase());
  const toolStatus = (name: string) =>
    String((((brief?.tools as Record<string, { status?: string }>) || {})[name] || {}).status || "").toLowerCase();
  const cveSt = toolStatus("cve");
  const showCve = cveSt ? cveSt !== "skipped" : Boolean((brief?.cve as { available?: boolean } | undefined)?.available);
  const showLangTool = (name: string, eco: string) => {
    const st = toolStatus(name);
    if (st === "skipped") return false;
    if (st === "succeeded" || st === "failed" || st === "missing") return true;
    return ecosystems.includes(eco);
  };

  const topLic = (lic.top_licenses || [])
    .slice(0, 8)
    .map((x) => `${x.license}（${x.count}）`)
    .join(t("common.listSep"));

  const updatedAt = String(req.updated_at || "").replace("T", " ").slice(0, 19);
  const scoreText =
    upstream.score != null
      ? `${String(upstream.score)} / 100`
      : upstream.status === "unknown"
        ? t("overview.notCollected")
        : t("common.none");
  const maintReason = String(maintGate.reason || upGate.reason || "").trim();

  const git = (source?.git || {}) as Record<string, unknown>;
  const blob = (source?.blob || {}) as Record<string, unknown>;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card className="panel-card" size="small" bodyStyle={{ padding: "12px 16px" }}>
        <Space wrap size="middle">
          {isDraft && (
            <Button type="primary" icon={<PlayCircleOutlined />} disabled={!hasSource} onClick={onSubmitScan}>
              {t("overview.submitScan")}
            </Button>
          )}
          {!isDraft && canRescan && (
            <Button icon={<PlayCircleOutlined />} onClick={onRescan}>
              {t("overview.rescan")}
            </Button>
          )}
          {!isDraft && (
            <Button icon={<FilePdfOutlined />} loading={reportBusy} disabled={!brief} onClick={onDownloadReport}>
              {t("overview.downloadReport")}
            </Button>
          )}
          {!isDraft && (
            <Button icon={<ExportOutlined />} onClick={onExport}>
              {t("overview.exportEvidence")}
            </Button>
          )}
        </Space>
      </Card>

      <Card className="panel-card" title={t("overview.software")}>
        <InfoGrid
          items={[
            ...(source
              ? ([
                  {
                    label: source.type === "git" ? t("overview.repo") : t("overview.filename"),
                    value: source.type === "git" ? String(git.repo_url || t("common.none")) : String(blob.filename || t("common.none")),
                  },
                  {
                    label: source.type === "git" ? t("overview.ref") : t("overview.size"),
                    value:
                      source.type === "git"
                        ? String(git.ref || t("common.none"))
                        : blob.bytes != null
                          ? `${String(blob.bytes)} bytes`
                          : t("common.none"),
                  },
                  {
                    label: source.type === "git" ? t("overview.commit") : "SHA256",
                    value: source.type === "git" ? String(git.commit_hash || t("common.none")) : String(blob.sha256 || t("common.none")),
                  },
                  { label: t("overview.type"), value: String(source.type || t("common.none")) },
                  { label: t("overview.credId"), value: git.credential_id ? String(git.credential_id) : t("common.none") },
                  { label: t("overview.workspaceHash"), value: String(source.workspace_sha256 || t("common.none")) },
                ] as InfoItem[])
              : []),
            { label: t("common.title"), value: String(req.title || req.project || t("common.none")) },
            { label: t("common.project"), value: String(req.project) },
            { label: t("common.owner"), value: String(req.owner || t("common.none")) },
            { label: t("common.createdBy"), value: String(req.created_by || t("common.none")) },
            { label: t("overview.riskLevel"), value: String(req.risk_level || t("common.none")) },
            { label: t("common.environment"), value: String(req.environment) },
            { label: t("common.exposure"), value: String(req.exposure) },
            { label: t("common.criticality"), value: String(req.business_criticality) },
            { label: t("common.purpose"), value: String(req.purpose || t("common.none")) },
            { label: t("common.updatedAt"), value: updatedAt || t("common.none") },
            { label: t("common.rollback"), value: rollbackDisplay(String(req.rollback_plan || "")), span: 3 },
          ]}
        />
        {!source && (
          <Alert type="warning" showIcon message={t("overview.noSource")} style={{ marginTop: 12 }} />
        )}
        {canEditSource && (
          <div style={{ marginTop: 16 }}>
            <Typography.Text type="secondary" style={{ display: "block", marginBottom: 8 }}>
              {isDraft ? t("overview.zipHint") : t("overview.reupload")}
            </Typography.Text>
            <Upload
              maxCount={1}
              beforeUpload={() => false}
              onChange={async ({ fileList }) => {
                const f = fileList[0]?.originFileObj as File | undefined;
                if (!f || !onUploadSource) return;
                try {
                  await onUploadSource(f);
                  message.success(t("overview.uploadOk"));
                } catch (e: unknown) {
                  message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("overview.uploadFail"));
                }
              }}
            >
              <Button icon={<UploadOutlined />}>{t("overview.pickFile")}</Button>
            </Upload>
          </div>
        )}
        {!canEditSource && source && (
          <Typography.Paragraph type="secondary" style={{ margin: "12px 0 0" }}>
            {t("overview.sourceLocked")}
          </Typography.Paragraph>
        )}
      </Card>

      {!isDraft && (
        <Card className="panel-card" title={t("overview.gateCheck")}>
          {!brief ? (
            <Typography.Text type="secondary">{t("overview.emptyHint")}</Typography.Text>
          ) : (
            <Space direction="vertical" size={20} style={{ width: "100%" }}>
              {brief.scanner_gate_status === "PendingLegal" && brief.effective_gate_status === "Pass" && (
                <Alert
                  type="success"
                  showIcon
                  message={t("overview.legalPassNote")}
                />
              )}
              <Typography.Text type="secondary">{t("overview.afterScan")}</Typography.Text>

              <InfoGrid
                items={[
                  { label: t("overview.gateStatus"), value: gateTag(String(brief.effective_gate_status || brief.gate_status || "")) },
                  { label: t("overview.ecosystems"), value: ((brief.ecosystems_detected as string[]) || []).join(t("common.listSep")) || t("common.none") },
                  { label: t("overview.openRemediation"), value: t("overview.openRemediationN", { n: String(brief.open_remediations ?? 0) }) },
                ]}
              />

              <div>
                <Typography.Text strong>{t("overview.license")}</Typography.Text>
                <InfoGrid
                  style={{ marginTop: 8 }}
                  items={[
                    {
                      label: t("overview.licenseScan"),
                      value: (
                        <>
                          {gateTag(gates.license?.status)}
                          {gates.license?.reason && (
                            <Typography.Text type="secondary">{String(gates.license.reason)}</Typography.Text>
                          )}
                        </>
                      ),
                    },
                    {
                      label: t("overview.engine"),
                      value:
                        `${lic.engine || t("common.none")}${lic.package_count != null && lic.package_count > 0 ? t("overview.packagesN", { n: lic.package_count }) : ""}`,
                    },
                    { label: t("overview.topLicenses"), value: topLic || lic.note || t("common.none") },
                    {
                      label: t("overview.deny"),
                      value:
                        (lic.deny_hits || []).length > 0 ? (
                          <Typography.Text type="danger">{(lic.deny_hits || []).join(t("common.listSep"))}</Typography.Text>
                        ) : (
                          t("common.none")
                        ),
                    },
                    {
                      label: t("overview.legalList"),
                      value:
                        (lic.legal_review_hits || []).length > 0 ? (
                          <Typography.Text type="warning">{(lic.legal_review_hits || []).join(t("common.listSep"))}</Typography.Text>
                        ) : (
                          t("common.none")
                        ),
                    },
                    {
                      label: t("overview.confidence"),
                      value: lic.unknown_or_low_confidence ? <Tag color="warning">{t("overview.unknownLow")}</Tag> : t("overview.normal"),
                    },
                  ]}
                />
              </div>

              <div>
                <Typography.Text strong>{t("overview.maintenance")}</Typography.Text>
                <Typography.Paragraph type="secondary" style={{ margin: "6px 0 8px", fontSize: 12 }}>
                  {t("overview.maintHint")}
                </Typography.Paragraph>
                <InfoGrid
                  items={[
                    {
                      label: t("overview.maintScore"),
                      value: (
                        <>
                          {gateTag(maintGate.status)}
                          <Typography.Text>{scoreText}</Typography.Text>
                          {maintReason && (
                            <Typography.Text type="secondary">{maintReason}</Typography.Text>
                          )}
                        </>
                      ),
                    },
                    { label: t("overview.upstream"), value: upstream.repo ? String(upstream.repo) : t("overview.unidentified") },
                    {
                      label: t("overview.metaSource"),
                      value: (
                        <>
                          {MAINT_SOURCE_LABELS[String(upstream.source || "")] ||
                            String(upstream.source_label || upstream.source || t("common.none"))}
                          {String(upstream.activity_source || "") === "local_git" ? (
                            <Typography.Text type="secondary">{t("overview.localHint")}</Typography.Text>
                          ) : null}
                        </>
                      ),
                    },
                    {
                      label: t("overview.archived"),
                      value: upstream.archived === true ? t("overview.isArchived") : upstream.archived === false ? t("common.no") : t("common.none"),
                    },
                    {
                      label: t("overview.lastRelease"),
                      value: upstream.last_release_days != null ? t("overview.daysAgo", { n: String(upstream.last_release_days) }) : t("common.none"),
                    },
                    {
                      label: t("overview.lastCommit"),
                      value: upstream.last_commit_days != null ? t("overview.daysAgo", { n: String(upstream.last_commit_days) }) : t("common.none"),
                    },
                    {
                      label: t("overview.commits90"),
                      value: upstream.commits_90d != null ? t("overview.commitsN", { n: String(upstream.commits_90d) }) : t("common.none"),
                    },
                    { label: t("overview.stars"), value: upstream.stars != null ? String(upstream.stars) : t("common.none") },
                    {
                      label: t("overview.issues"),
                      value: upstream.open_issues_count != null ? String(upstream.open_issues_count) : t("common.none"),
                    },
                    {
                      label: t("overview.contributors"),
                      value: upstream.contributors_count != null ? String(upstream.contributors_count) : t("common.none"),
                    },
                  ]}
                />
              </div>

              <div>
                <Typography.Text strong>{t("overview.security")}</Typography.Text>
                <InfoGrid
                  style={{ marginTop: 8 }}
                  items={[
                    ...(showCve
                      ? [
                          {
                            label: t("overview.cve"),
                            value: (
                              <>
                                {gateTag(gates.cve?.status)}
                                <Typography.Text type="secondary">
                                  Critical {cveCounts.critical ?? 0} / High {cveCounts.high ?? 0} / Medium{" "}
                                  {cveCounts.medium ?? 0} / Low {cveCounts.low ?? 0}
                                  {cve.engine ? ` · ${String(cve.engine)}` : ""}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    ...(showLangTool("gosec", "go")
                      ? [
                          {
                            label: "gosec",
                            value: (
                              <>
                                {gateTag(gates.gosec?.status)}
                                <Typography.Text type="secondary">
                                  High {gosec.high ?? 0} / Medium {gosec.medium ?? 0} / Low {gosec.low ?? 0}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    ...(showLangTool("cppcheck", "cpp")
                      ? [
                          {
                            label: "cppcheck",
                            value: (
                              <>
                                {gateTag(gates.cppcheck?.status)}
                                <Typography.Text type="secondary">
                                  Error {cpp.error ?? 0} / Warning {cpp.warning ?? 0}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    ...(showLangTool("bandit", "python")
                      ? [
                          {
                            label: "bandit (Python)",
                            value: (
                              <>
                                {gateTag(gates.bandit?.status)}
                                <Typography.Text type="secondary">
                                  High {bandit.high ?? 0} / Medium {bandit.medium ?? 0} / Low {bandit.low ?? 0}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    ...(showLangTool("pmd", "java")
                      ? [
                          {
                            label: "pmd (Java)",
                            value: (
                              <>
                                {gateTag(gates.pmd?.status)}
                                <Typography.Text type="secondary">
                                  High {pmd.high ?? 0} / Medium {pmd.medium ?? 0} / Low {pmd.low ?? 0}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    ...(showLangTool("cargo_audit", "rust")
                      ? [
                          {
                            label: "cargo-audit (Rust)",
                            value: (
                              <>
                                {gateTag(gates.cargo_audit?.status)}
                                <Typography.Text type="secondary">
                                  High {cargo.high ?? 0} / Medium {cargo.medium ?? 0} / Low {cargo.low ?? 0}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    ...(showLangTool("eslint", "javascript")
                      ? [
                          {
                            label: "eslint (JS/TS)",
                            value: (
                              <>
                                {gateTag(gates.eslint?.status)}
                                <Typography.Text type="secondary">
                                  High {eslint.high ?? 0} / Medium {eslint.medium ?? 0} / Low {eslint.low ?? 0}
                                </Typography.Text>
                              </>
                            ),
                          },
                        ]
                      : []),
                    {
                      label: t("overview.scanScope"),
                      value: ecosystems.join(t("common.listSep")) || t("overview.noLang"),
                    },
                  ]}
                />
              </div>
            </Space>
          )}
        </Card>
      )}

    </Space>
  );
}
