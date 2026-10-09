import {
  Alert,
  Breadcrumb,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";
import { CodeOutlined } from "@ant-design/icons";
import ScanReportsMenu from "../components/ScanReportsMenu";
import ScanConsoleDrawer, { isLiveScanStatus } from "../components/ScanConsoleDrawer";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  apiErrorMessage,
  closeRemediation,
  createRemediation,
  downloadExport,
  downloadReviewReport,
  exportEvidence,
  getRequest,
  getReviewBrief,
  listAuditEvents,
  listFindings,
  listLegalReviews,
  listRemediations,
  listScanRuns,
  deleteRequest,
  submitRequest,
  triggerScan,
  uploadSource,
} from "../api/client";
import { GATE_STATUS_LABELS, REQUEST_STATUS_LABELS, displayGateStatus } from "../constants/display";
import { ROLE_LABELS } from "../constants/display";
import { getAuthUser } from "../auth";
import RequestFlowSteps from "../components/RequestFlowSteps";
import ReviewTab from "../components/ReviewTab";
import FindingsTab from "../components/FindingsTab";
import OverviewPanel from "../components/OverviewPanel";
import RequestEditModal from "../components/RequestEditModal";
import { useI18n } from "../i18n/LocaleContext";
import { canDeleteRequest, canEditRequest, canManageRequests } from "../utils/requestActions";
import {
  mergeRoleReviews,
  roleReviewStatusColor,
  roleReviewStatusLabel,
  type LegalReviewItem,
  type RoleReviewEntry,
} from "../utils/roleReviews";

const statusColors: Record<string, string> = {
  Draft: "default",
  Scanning: "processing",
  Reviewing: "blue",
  LegalReviewing: "orange",
  Blocked: "error",
  Approved: "success",
  ConditionalApproved: "cyan",
  Remediating: "purple",
  ReReview: "geekblue",
  Rejected: "magenta",
  Waived: "gold",
};

type FailureDetail = { reason?: string };

function collectProjectHints(req: Record<string, unknown> | null, source: Record<string, unknown> | null): string[] {
  const names: string[] = [];
  const push = (raw: unknown) => {
    const s = String(raw || "").trim();
    if (!s) return;
    names.push(s);
  };
  push(req?.title);
  push(req?.project);
  const git = ((source?.git || {}) as Record<string, unknown>) || {};
  const url = String(git.repo_url || source?.url || "");
  push(url);
  try {
    const u = new URL(url);
    const parts = u.pathname.replace(/\.git$/i, "").split("/").filter(Boolean);
    if (parts.length) {
      push(parts[parts.length - 1]);
      if (parts.length >= 2) push(`${parts[parts.length - 2]}/${parts[parts.length - 1]}`);
    }
  } catch {
    const tail = url.replace(/\.git$/i, "").split("/").filter(Boolean);
    if (tail.length) push(tail[tail.length - 1]);
  }
  return [...new Set(names)];
}

export default function RequestDetail() {
  const { t } = useI18n();
  const { requestId = "" } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get("tab") || "overview";
  const [loading, setLoading] = useState(true);
  const [req, setReq] = useState<Record<string, unknown> | null>(null);
  const [source, setSource] = useState<Record<string, unknown> | null>(null);
  const [runs, setRuns] = useState<Record<string, unknown>[]>([]);
  const [legal, setLegal] = useState<Record<string, unknown>[]>([]);
  const [remediations, setRemediations] = useState<Record<string, unknown>[]>([]);
  const [audits, setAudits] = useState<Record<string, unknown>[]>([]);

  const [remModal, setRemModal] = useState(false);
  const [findings, setFindings] = useState<Record<string, unknown>[]>([]);
  const [reviewBrief, setReviewBrief] = useState<Record<string, unknown> | null>(null);

  const [rForm] = Form.useForm();
  const [editOpen, setEditOpen] = useState(false);
  const [reportBusy, setReportBusy] = useState(false);
  const [consoleRunId, setConsoleRunId] = useState<string | null>(null);

  const refresh = useCallback(async (opts?: { quiet?: boolean }) => {
    if (!requestId) return;
    if (!opts?.quiet) setLoading(true);
    try {
      const bundle = await getRequest(requestId);
      setReq(bundle.request);
      setSource(bundle.source);
      const latestScanRunId = String((bundle.latest_scan_run as { scan_run_id?: string } | null)?.scan_run_id || "");
      const [r, l, m, a, f, brief] = await Promise.all([
        listScanRuns(requestId),
        listLegalReviews(requestId),
        listRemediations(requestId),
        listAuditEvents(requestId),
        listFindings(requestId, latestScanRunId || undefined),
        getReviewBrief(requestId).catch(() => null),
      ]);
      setRuns(r.items);
      setLegal(l.items);
      setRemediations(m.items);
      setAudits(a.items);
      setFindings(f.items);
      setReviewBrief(brief);
    } catch {
      message.error(t("request.loadFail"));
    } finally {
      if (!opts?.quiet) setLoading(false);
    }
  }, [requestId, t]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (req?.status !== "Scanning") return;
    const timer = window.setInterval(() => {
      void refresh({ quiet: true });
    }, 3000);
    return () => clearInterval(timer);
  }, [req?.status, refresh]);

  if (!req) {
    return loading ? <Typography.Text>{t("common.loading")}</Typography.Text> : <Typography.Text type="danger">{t("request.notFound")}</Typography.Text>;
  }

  const isDraft = req.status === "Draft";
  const canManage = canManageRequests();
  const showEdit = canManage && canEditRequest(String(req.status));
  const showDelete = canManage && canDeleteRequest(String(req.status));
  const canEditSource = req.status !== "Scanning" && req.status !== "Approved";
  const gate = displayGateStatus(req as { effective_gate_status?: string; gate_status?: string });
  const scannerGate = String((req as { scanner_gate_status?: string }).scanner_gate_status || req.gate_status || "");
  const requiredReviewRoles = ((req.required_review_roles as string[]) || []).map((x) => String(x));
  const roleReviewsRaw = (req.role_reviews as Record<string, RoleReviewEntry>) || {};
  const mergedRoleReviews = mergeRoleReviews(
    requiredReviewRoles,
    roleReviewsRaw,
    legal as LegalReviewItem[],
    gate
  );
  const meRoles = getAuthUser()?.roles || (getAuthUser()?.role ? [String(getAuthUser()?.role)] : []);
  const myReviewRoles = requiredReviewRoles.filter((r) => meRoles.includes(r));
  const canDisposeFindings = canManage || myReviewRoles.length > 0 || meRoles.includes("quality_manager");
  const hasLiveScan = runs.some((row) => isLiveScanStatus(row.status));
  const roleTagKeys = [
    ...new Set([
      ...requiredReviewRoles,
      ...(gate === "PendingLegal" || mergedRoleReviews.legal ? ["legal"] : []),
    ]),
  ];
  return (
    <div className="page-shell">
      <Breadcrumb
        items={[
          { title: <Link to="/requests">{t("nav.requests")}</Link> },
          { title: String(req.request_id || requestId).slice(0, 8) + "…" },
        ]}
        style={{ marginBottom: 12 }}
      />
      <Space align="center" wrap style={{ marginBottom: 8 }}>
        <h1 className="page-title" style={{ margin: 0 }}>
          {String(req.title || req.project || t("request.detail"))}
        </h1>
        <Tag color={statusColors[String(req.status)] || "default"}>{REQUEST_STATUS_LABELS[String(req.status)] || String(req.status)}</Tag>
        <Tag color={gate === "Pass" ? "success" : gate === "Fail" ? "error" : gate === "PendingLegal" ? "warning" : "default"}>
          Gate {GATE_STATUS_LABELS[gate] || gate}
        </Tag>
        {scannerGate === "PendingLegal" && gate === "Pass" && (
          <Tag color="success">{t("request.legalReleased")}</Tag>
        )}
        {showEdit && (
          <Button onClick={() => setEditOpen(true)}>{t("common.edit")}</Button>
        )}
        {showDelete && (
          <Button
            danger
            onClick={() => {
              Modal.confirm({
                title: t("request.deleteTitle"),
                content: t("request.deleteContent"),
                okText: t("common.delete"),
                okType: "danger",
                onOk: async () => {
                  await deleteRequest(requestId);
                  message.success(t("requests.deleted"));
                  navigate("/requests");
                },
              });
            }}
          >
            {t("common.delete")}
          </Button>
        )}
      </Space>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("request.subtitle")}
      </Typography.Paragraph>
      <RequestFlowSteps
        status={String(req.status)}
        gate={gate}
        scannerGate={scannerGate}
        requiredRoles={roleTagKeys}
        roleReviews={mergedRoleReviews}
        hasSource={!!source}
      />
      {!isDraft && roleTagKeys.length > 0 && (
        <Card size="small" className="panel-card" style={{ marginBottom: 12 }}>
          <Space wrap size={[8, 8]}>
            {roleTagKeys.map((r) => {
              const rv = mergedRoleReviews[r];
              return (
                <Tag key={r} color={roleReviewStatusColor(rv)}>
                  {(ROLE_LABELS[r] || r) + "：" + roleReviewStatusLabel(rv)}
                </Tag>
              );
            })}
          </Space>
        </Card>
      )}

      <Tabs
        activeKey={activeTab}
        onChange={(key) => {
          const next = new URLSearchParams(searchParams);
          next.set("tab", key);
          setSearchParams(next, { replace: true });
        }}
        items={[
          {
            key: "overview",
            label: t("request.tabOverview"),
            children: (
              <OverviewPanel
                req={req}
                brief={reviewBrief}
                isDraft={isDraft}
                hasSource={!!source}
                source={source}
                canEditSource={canEditSource}
                canRescan={!isDraft && req.status !== "Scanning"}
                onUploadSource={(file) => uploadSource(requestId, file).then(() => { refresh(); })}
                onSubmitScan={async () => {
                  try {
                    await submitRequest(requestId);
                    message.success(t("request.submitted"));
                    refresh();
                  } catch (e: unknown) {
                    message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("request.submitFail"));
                  }
                }}
                onRescan={async () => {
                  try {
                    await triggerScan(requestId);
                    message.success(t("request.queued"));
                    refresh();
                  } catch (e: unknown) {
                    message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("request.rescanFail"));
                  }
                }}
                reportBusy={reportBusy}
                onDownloadReport={async () => {
                  setReportBusy(true);
                  try {
                    await downloadReviewReport(requestId, String(req.title || req.project || requestId), t("request.reportPrefix"));
                    message.success(t("request.reportStarted"));
                  } catch (e: unknown) {
                    message.error(apiErrorMessage(e, t("request.reportFail")));
                  } finally {
                    setReportBusy(false);
                  }
                }}
                onExport={async () => {
                  try {
                    const { export_id } = await exportEvidence(requestId);
                    await downloadExport(export_id);
                  } catch {
                    message.error(t("request.exportFail"));
                  }
                }}
              />
            ),
          },
          {
            key: "review",
            label: t("request.tabReview"),
            children: !isDraft ? (
              <ReviewTab
                requestId={requestId}
                gateStatus={gate}
                requiredRoles={requiredReviewRoles}
                roleReviews={roleReviewsRaw}
                legalItems={legal as LegalReviewItem[]}
                myReviewRoles={myReviewRoles}
                onRefresh={refresh}
                onOpenFindings={() => {
                  const next = new URLSearchParams(searchParams);
                  next.set("tab", "findings");
                  setSearchParams(next);
                }}
              />
            ) : (
              <Alert type="info" showIcon message={t("request.draftReviewHint")} />
            ),
          },
          {
            key: "findings",
            label: findings.length ? t("request.tabFindingsN", { n: findings.length }) : t("request.tabFindings"),
            children: (
              <FindingsTab
                requestId={requestId}
                findings={findings}
                gateStatus={gate}
                canDispose={canDisposeFindings}
                onRefresh={refresh}
                projectHints={collectProjectHints(req, source)}
              />
            ),
          },
          {
            key: "scans",
            label: t("request.tabScans"),
            children: (
              <Card className="panel-card">
                <Table
                  rowKey="scan_run_id"
                  loading={loading}
                  dataSource={runs}
                  pagination={false}
                  scroll={{ x: "max-content" }}
                  onRow={(row) => ({
                    onClick: () => navigate(`/requests/${requestId}/scans/${String(row.scan_run_id)}`),
                    className: "scan-run-row",
                  })}
                  columns={[
                    {
                      title: "scan_run_id",
                      dataIndex: "scan_run_id",
                      ellipsis: true,
                      render: (v: string) => (
                        <Link to={`/requests/${requestId}/scans/${v}`} onClick={(e) => e.stopPropagation()}>
                          {v}
                        </Link>
                      ),
                    },
                    { title: t("common.status"), dataIndex: "status", width: 100 },
                    { title: t("common.gate"), dataIndex: "gate_status", width: 120 },
                    { title: t("request.exitCode"), dataIndex: "exit_code", width: 80 },
                    { title: t("common.createdAt"), dataIndex: "created_at", width: 180, render: (v) => String(v || "") },
                    {
                      title: t("request.failReason"),
                      dataIndex: "error",
                      ellipsis: true,
                      render: (_: unknown, row: Record<string, unknown>) =>
                        String(row.status || "").toLowerCase() === "failed"
                          ? String(((row.failure_detail as FailureDetail)?.reason || row.error || t("request.scanFailed"))).slice(0, 180)
                          : "—",
                    },
                    {
                      title: t("request.reports"),
                      render: (_: unknown, row: Record<string, unknown>) => (
                        <span onClick={(e) => e.stopPropagation()}>
                          <ScanReportsMenu
                            scanRunId={String(row.scan_run_id)}
                            outputs={(row.outputs || {}) as Record<string, { path?: string; bytes?: number }>}
                            includeLogs={String(row.status || "").toLowerCase() === "failed"}
                          />
                        </span>
                      ),
                    },
                    ...(hasLiveScan
                      ? [
                          {
                            title: t("request.console"),
                            key: "console",
                            width: 108,
                            fixed: "right" as const,
                            render: (_: unknown, row: Record<string, unknown>) =>
                              isLiveScanStatus(row.status) ? (
                                <Button
                                  size="small"
                                  icon={<CodeOutlined />}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setConsoleRunId(String(row.scan_run_id));
                                  }}
                                >
                                  {t("request.console")}
                                </Button>
                              ) : null,
                          },
                        ]
                      : []),
                  ]}
                />
              </Card>
            ),
          },
          {
            key: "rem",
            label: t("request.tabRemediation"),
            children: (
              <Card className="panel-card">
                <div className="page-toolbar" style={{ marginBottom: 12 }}>
                <Button type="primary" onClick={() => { rForm.resetFields(); setRemModal(true); }}>
                  {t("request.newRemediation")}
                </Button>
                </div>
                <Table
                  rowKey="remediation_id"
                  dataSource={remediations}
                  pagination={false}
                  scroll={{ x: "max-content" }}
                  columns={[
                    { title: t("common.title"), dataIndex: "title" },
                    { title: t("request.severity"), dataIndex: "severity", width: 100 },
                    { title: t("request.assignee"), dataIndex: "owner" },
                    {
                      title: t("request.due"),
                      dataIndex: "due_at",
                      width: 160,
                      render: (v: string) => (v ? String(v).replace("T", " ").slice(0, 16) : "—"),
                    },
                    { title: t("common.status"), dataIndex: "status", width: 90 },
                    {
                      title: t("common.actions"),
                      width: 100,
                      render: (_: unknown, row: Record<string, unknown>) =>
                        row.status === "open" ? (
                          <Button
                            type="link"
                            size="small"
                            onClick={async () => {
                              try {
                                await closeRemediation(String(row.remediation_id));
                                message.success(t("request.closed"));
                                refresh();
                              } catch {
                                message.error(t("request.closeFail"));
                              }
                            }}
                          >
                            {t("common.close")}
                          </Button>
                        ) : (
                          "—"
                        ),
                    },
                  ]}
                />
                <Modal
                  title={t("request.newRemediation")}
                  open={remModal}
                  onCancel={() => setRemModal(false)}
                  onOk={async () => {
                    try {
                      const v = await rForm.validateFields();
                      await createRemediation(requestId, {
                        title: v.title,
                        severity: v.severity,
                        owner: v.owner,
                        due_at: v.due_at || null,
                        finding_fingerprints: v.finding_fingerprints || [],
                      });
                      message.success(t("request.created"));
                      setRemModal(false);
                      refresh();
                    } catch (e: unknown) {
                      if ((e as { errorFields?: unknown })?.errorFields) return;
                      message.error(t("common.failed"));
                    }
                  }}
                >
                  <Form form={rForm} layout="vertical">
                    <Form.Item name="title" label={t("common.title")} rules={[{ required: true }]}>
                      <Input />
                    </Form.Item>
                    <Form.Item name="severity" label={t("common.severity")} initialValue="medium">
                      <Select options={["low", "medium", "high", "critical"].map((x) => ({ label: x, value: x }))} />
                    </Form.Item>
                    <Form.Item name="owner" label={t("request.assignee")}>
                      <Input />
                    </Form.Item>
                    <Form.Item name="due_at" label={t("request.dueDate")}>
                      <Input type="datetime-local" />
                    </Form.Item>
                    <Form.Item name="finding_fingerprints" label={t("request.findingFp")}>
                      <Select
                        mode="multiple"
                        allowClear
                        placeholder={t("request.findingPick")}
                        options={findings.map((f) => ({
                          label: `${String(f.fingerprint || "")} — ${String(f.title || "")}`,
                          value: String(f.fingerprint || ""),
                        }))}
                      />
                    </Form.Item>
                  </Form>
                </Modal>
              </Card>
            ),
          },
          {
            key: "audit",
            label: t("request.tabAudit"),
            children: (
              <Card className="panel-card">
                <Table
                  rowKey="audit_id"
                  dataSource={audits}
                  pagination={{ pageSize: 50 }}
                  scroll={{ x: 900 }}
                  columns={[
                    { title: "seq", dataIndex: "seq", width: 60 },
                    { title: t("request.time"), dataIndex: "ts", width: 180, render: (v) => String(v) },
                    { title: t("request.event"), dataIndex: "event_type", width: 160 },
                    { title: "payload", dataIndex: "payload", ellipsis: true, render: (p) => JSON.stringify(p) },
                    { title: "hash", dataIndex: "hash", ellipsis: true, width: 120 },
                  ]}
                />
              </Card>
            ),
          },
        ]}
      />
      <RequestEditModal
        open={editOpen}
        request={req}
        source={source}
        onCancel={() => setEditOpen(false)}
        onSaved={() => {
          setEditOpen(false);
          refresh();
        }}
      />
      <ScanConsoleDrawer
        scanRunId={consoleRunId}
        open={Boolean(consoleRunId)}
        onClose={() => setConsoleRunId(null)}
        onEnded={() => {
          void refresh({ quiet: true });
        }}
      />
    </div>
  );
}
