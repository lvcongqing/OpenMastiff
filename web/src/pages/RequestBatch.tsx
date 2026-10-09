import {
  Alert,
  Button,
  Card,
  Checkbox,
  Input,
  Select,
  Space,
  Steps,
  Table,
  Tag,
  Typography,
  Upload,
  message,
} from "antd";
import { DownloadOutlined, PlusOutlined, UploadOutlined } from "@ant-design/icons";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { createBatchRequests, downloadBatchTemplate, listCredentials, parseBatchRequests } from "../api/client";
import { REQUEST_STATUS_LABELS } from "../constants/display";
import { rollbackPlans } from "../constants/rollbackPlans";
import { useI18n } from "../i18n/LocaleContext";
import { t as translate } from "../i18n";
import type { TFunction } from "../i18n/types";
import { DEFAULT_REVIEW_ROLES, loadReviewRoleOptions, mergeRequiredReviewRoles, reviewRoleTagRender } from "../utils/reviewRoles";

type BatchRow = {
  key: string;
  row?: number;
  project: string;
  title: string;
  owner: string;
  repo_url: string;
  ref: string;
  purpose: string;
  environment: string;
  exposure: string;
  business_criticality: string;
  rollback_plan: string;
  credential_id: string;
  credential_input: string;
  include_paths: string[];
  extra_review_roles: string[];
  errors: string[];
  warnings: string[];
};

function asRow(raw: Record<string, unknown>, idx: number): BatchRow {
  const include = Array.isArray(raw.include_paths)
    ? (raw.include_paths as unknown[]).map((x) => String(x).trim()).filter(Boolean)
    : String(raw.include_paths || "")
        .split(/[,，;；\n]/)
        .map((x) => x.trim())
        .filter(Boolean);
  const extras = Array.isArray(raw.extra_review_roles)
    ? (raw.extra_review_roles as unknown[]).map((x) => String(x).trim()).filter(Boolean)
    : [];
  return {
    key: String(raw.row || `row-${idx}`),
    row: Number(raw.row || idx + 2),
    project: String(raw.project || ""),
    title: String(raw.title || ""),
    owner: String(raw.owner || ""),
    repo_url: String(raw.repo_url || ""),
    ref: String(raw.ref || "main"),
    purpose: String(raw.purpose || ""),
    environment: String(raw.environment || "dev"),
    exposure: String(raw.exposure || "internal"),
    business_criticality: String(raw.business_criticality || "low"),
    rollback_plan: String(raw.rollback_plan || "version_downgrade"),
    credential_id: String(raw.credential_id || ""),
    credential_input: String(raw.credential_input || raw.credential_id || ""),
    include_paths: include,
    extra_review_roles: extras.filter((x) => !DEFAULT_REVIEW_ROLES.includes(x)),
    errors: Array.isArray(raw.errors) ? (raw.errors as unknown[]).map((x) => String(x)) : [],
    warnings: Array.isArray(raw.warnings) ? (raw.warnings as unknown[]).map((x) => String(x)) : [],
  };
}

function localErrors(row: BatchRow, t: TFunction = translate): string[] {
  const errors: string[] = [];
  if (!row.project.trim()) errors.push(t("batch.projectEmpty"));
  if (!row.purpose.trim()) errors.push(t("batch.purposeEmpty"));
  if (!row.repo_url.trim()) errors.push(t("batch.repoEmpty"));
  else if (!/^https?:\/\//i.test(row.repo_url.trim())) errors.push(t("batch.repoHttp"));
  return errors;
}

function emptyRow(idx: number): BatchRow {
  return {
    key: `manual-${Date.now()}-${idx}`,
    row: idx + 2,
    project: "",
    title: "",
    owner: "",
    repo_url: "",
    ref: "main",
    purpose: "",
    environment: "dev",
    exposure: "internal",
    business_criticality: "low",
    rollback_plan: "version_downgrade",
    credential_id: "",
    credential_input: "",
    include_paths: [],
    extra_review_roles: [],
    errors: [],
    warnings: [],
  };
}

export default function RequestBatch({ embedded = false }: { embedded?: boolean }) {
  const { t } = useI18n();
  const nav = useNavigate();
  const [step, setStep] = useState(0);
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [submitNow, setSubmitNow] = useState(true);
  const [parsing, setParsing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{
    created: Array<Record<string, unknown>>;
    failed: Array<Record<string, unknown>>;
    submit: boolean;
  } | null>(null);
  const [roleOptions, setRoleOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [credOptions, setCredOptions] = useState<Array<{ label: string; value: string }>>([]);

  useEffect(() => {
    (async () => {
      try {
        setRoleOptions(await loadReviewRoleOptions());
      } catch {
        setRoleOptions([]);
      }
      try {
        const c = await listCredentials();
        setCredOptions(
          (c.items || [])
            .map((x) => ({
              label: t("requestNew.credNamed", {
                name: String(x.name || x.credential_id),
                type: String(x.type || t("requestNew.credFallback")),
              }),
              value: String(x.credential_id || ""),
            }))
            .filter((x) => x.value),
        );
      } catch {
        setCredOptions([]);
      }
    })();
  }, [t]);

  const patched = useMemo(
    () =>
      rows.map((row) => {
        const errors = localErrors(row, t);
        return { ...row, errors };
      }),
    [rows, t],
  );
  const errorCount = patched.filter((x) => x.errors.length).length;

  const patch = (key: string, next: Partial<BatchRow>) => {
    setRows((prev) => prev.map((row) => (row.key === key ? { ...row, ...next } : row)));
  };

  const downloadTemplate = async () => {
    try {
      const blob = await downloadBatchTemplate();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "openmastiff-batch-requests.xlsx";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("batch.tplFail"));
    }
  };

  const onUpload = async (file: File) => {
    setParsing(true);
    try {
      const parsed = await parseBatchRequests(file);
      const items = (parsed.items || []).map((x, i) => asRow(x, i));
      if (!items.length) {
        message.warning(t("batch.empty"));
        return false;
      }
      setRows(items);
      setResult(null);
      setStep(1);
      if (parsed.error_count) {
        message.warning(t("batch.importedFix", { total: parsed.total, errors: parsed.error_count }));
      } else {
        message.success(t("batch.imported", { total: parsed.total }));
      }
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("batch.parseFail"));
    } finally {
      setParsing(false);
    }
    return false;
  };

  const confirm = async () => {
    const items = patched.map((row, idx) => ({
      row: row.row || idx + 2,
      project: row.project,
      title: row.title || row.project,
      owner: row.owner,
      purpose: row.purpose,
      repo_url: row.repo_url,
      ref: row.ref || "main",
      environment: row.environment,
      exposure: row.exposure,
      business_criticality: row.business_criticality,
      rollback_plan: row.rollback_plan,
      credential_id: row.credential_id,
      credential_input: row.credential_input || row.credential_id,
      include_paths: row.include_paths,
      extra_review_roles: mergeRequiredReviewRoles(row.extra_review_roles).filter((x) => !DEFAULT_REVIEW_ROLES.includes(x)),
    }));
    if (!items.length) {
      message.error(t("batch.nothing"));
      return;
    }
    if (errorCount) {
      message.error(t("batch.fixFirst"));
      return;
    }
    setSaving(true);
    try {
      const res = await createBatchRequests({ items, submit: submitNow });
      setResult({ created: res.created || [], failed: res.failed || [], submit: res.submit });
      setStep(2);
      if (res.failed_count) {
        message.warning(t("batch.createdScanFail", { ok: res.created_count, fail: res.failed_count }));
      } else {
        message.success(submitNow ? t("batch.createdScan", { n: res.created_count }) : t("batch.createdDraft", { n: res.created_count }));
      }
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("batch.createFail"));
    } finally {
      setSaving(false);
    }
  };

  const body = (
    <>
      {!embedded && (
        <>
          <h1 className="page-title">{t("batch.title")}</h1>
          <Typography.Paragraph type="secondary" className="page-subtitle">
            {t("requestNew.batchSubtitle")}
          </Typography.Paragraph>
        </>
      )}
      <Steps
        current={step}
        style={{ marginBottom: 16 }}
        items={[{ title: t("batch.stepImport") }, { title: t("batch.stepReview") }, { title: t("batch.stepResult") }]}
      />

      {step === 0 && (
        <Card className="panel-card">
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            <Alert
              type="info"
              showIcon
              message={t("batch.defaultRoles")}
            />
            <Space wrap>
              <Button icon={<DownloadOutlined />} onClick={downloadTemplate}>
                {t("batch.downloadTpl")}
              </Button>
              <Upload accept=".xlsx,.xlsm" showUploadList={false} beforeUpload={onUpload}>
                <Button type="primary" icon={<UploadOutlined />} loading={parsing}>
                  {t("batch.uploadTpl")}
                </Button>
              </Upload>
              <Button
                onClick={() => {
                  setRows([emptyRow(0)]);
                  setResult(null);
                  setStep(1);
                }}
              >
                {t("batch.skipManual")}
              </Button>
              <Button onClick={() => nav("/requests")}>{t("batch.back")}</Button>
            </Space>
          </Space>
        </Card>
      )}

      {step === 1 && (
        <Card className="panel-card">
          <Space style={{ marginBottom: 12 }} wrap>
            <Button
              icon={<PlusOutlined />}
              onClick={() => setRows((prev) => [...prev, emptyRow(prev.length)])}
            >
              {t("batch.addRow")}
            </Button>
            <Checkbox checked={submitNow} onChange={(e) => setSubmitNow(e.target.checked)}>
              {t("batch.submitNow")}
            </Checkbox>
            <Typography.Text type="secondary">
              {t("batch.totalRows", { n: patched.length })}{errorCount ? t("batch.needFix", { n: errorCount }) : ""}
            </Typography.Text>
          </Space>
          <Table
            rowKey="key"
            size="small"
            dataSource={patched}
            scroll={{ x: 1800 }}
            pagination={false}
            rowClassName={(row) => (row.errors.length ? "batch-row-error" : "")}
            columns={[
              { title: t("common.line"), dataIndex: "row", width: 60 },
              {
                title: t("requestNew.project"),
                dataIndex: "project",
                width: 140,
                render: (v: string, row) => (
                  <Input value={v} onChange={(e) => patch(row.key, { project: e.target.value })} />
                ),
              },
              {
                title: t("common.title"),
                dataIndex: "title",
                width: 140,
                render: (v: string, row) => (
                  <Input value={v} onChange={(e) => patch(row.key, { title: e.target.value })} />
                ),
              },
              {
                title: t("requestNew.repoUrl"),
                dataIndex: "repo_url",
                width: 260,
                render: (v: string, row) => (
                  <Input value={v} onChange={(e) => patch(row.key, { repo_url: e.target.value })} />
                ),
              },
              {
                title: t("batch.branch"),
                dataIndex: "ref",
                width: 110,
                render: (v: string, row) => (
                  <Input value={v} onChange={(e) => patch(row.key, { ref: e.target.value })} />
                ),
              },
              {
                title: t("common.purpose"),
                dataIndex: "purpose",
                width: 160,
                render: (v: string, row) => (
                  <Input value={v} onChange={(e) => patch(row.key, { purpose: e.target.value })} />
                ),
              },
              {
                title: t("common.environment"),
                dataIndex: "environment",
                width: 110,
                render: (v: string, row) => (
                  <Select
                    value={v}
                    style={{ width: "100%" }}
                    options={["dev", "stage", "prod", "other"].map((x) => ({ label: x, value: x }))}
                    onChange={(environment) => patch(row.key, { environment })}
                  />
                ),
              },
              {
                title: t("common.exposure"),
                dataIndex: "exposure",
                width: 110,
                render: (v: string, row) => (
                  <Select
                    value={v}
                    style={{ width: "100%" }}
                    options={[
                      { label: t("common.internal"), value: "internal" },
                      { label: t("common.public"), value: "public" },
                    ]}
                    onChange={(exposure) => patch(row.key, { exposure })}
                  />
                ),
              },
              {
                title: t("batch.criticality"),
                dataIndex: "business_criticality",
                width: 110,
                render: (v: string, row) => (
                  <Select
                    value={v}
                    style={{ width: "100%" }}
                    options={["low", "medium", "high", "critical"].map((x) => ({ label: x, value: x }))}
                    onChange={(business_criticality) => patch(row.key, { business_criticality })}
                  />
                ),
              },
              {
                title: t("batch.rollback"),
                dataIndex: "rollback_plan",
                width: 160,
                render: (v: string, row) => (
                  <Select
                    value={v.split(":")[0]}
                    style={{ width: "100%" }}
                    options={rollbackPlans().map((x) => ({ label: x.label, value: x.value }))}
                    onChange={(rollback_plan) => patch(row.key, { rollback_plan })}
                  />
                ),
              },
              {
                title: t("common.credential"),
                dataIndex: "credential_id",
                width: 160,
                render: (v: string, row) =>
                  credOptions.length ? (
                    <Select
                      allowClear
                      value={v || undefined}
                      style={{ width: "100%" }}
                      options={credOptions}
                      onChange={(credential_id) =>
                        patch(row.key, { credential_id: credential_id || "", credential_input: credential_id || "" })
                      }
                    />
                  ) : (
                    <Input
                      value={row.credential_input}
                      placeholder={t("batch.credName")}
                      onChange={(e) =>
                        patch(row.key, { credential_input: e.target.value, credential_id: e.target.value })
                      }
                    />
                  ),
              },
              {
                title: t("batch.extraRoles"),
                dataIndex: "extra_review_roles",
                width: 200,
                render: (v: string[], row) => (
                  <Select
                    mode="multiple"
                    value={mergeRequiredReviewRoles(v)}
                    style={{ width: "100%" }}
                    options={roleOptions}
                    tagRender={reviewRoleTagRender}
                    onChange={(vals) =>
                      patch(row.key, {
                        extra_review_roles: mergeRequiredReviewRoles(vals).filter((x) => !DEFAULT_REVIEW_ROLES.includes(x)),
                      })
                    }
                  />
                ),
              },
              {
                title: t("overview.scanScope"),
                dataIndex: "include_paths",
                width: 160,
                render: (v: string[], row) => (
                  <Input
                    value={v.join(", ")}
                    onChange={(e) =>
                      patch(row.key, {
                        include_paths: e.target.value.split(/[,，;；\n]/).map((x) => x.trim()).filter(Boolean),
                      })
                    }
                  />
                ),
              },
              {
                title: t("batch.issue"),
                width: 220,
                render: (_, row) => (
                  <Space direction="vertical" size={2}>
                    {row.errors.map((x) => (
                      <Tag key={x} color="red">
                        {x}
                      </Tag>
                    ))}
                    {row.warnings.map((x) => (
                      <Tag key={x} color="gold">
                        {x}
                      </Tag>
                    ))}
                  </Space>
                ),
              },
              {
                title: "",
                width: 70,
                fixed: "right",
                render: (_, row) => (
                  <Button type="link" danger onClick={() => setRows((prev) => prev.filter((x) => x.key !== row.key))}>
                    {t("common.delete")}
                  </Button>
                ),
              },
            ]}
          />
          <div className="page-toolbar">
            <Button type="primary" onClick={confirm} loading={saving} disabled={!patched.length || !!errorCount}>
              {t("batch.confirm")}
            </Button>
            <Button
              onClick={() => {
                setStep(0);
                setResult(null);
              }}
            >
              {t("batch.backUpload")}
            </Button>
          </div>
        </Card>
      )}

      {step === 2 && result && (
        <Card className="panel-card">
          <Alert
            type={result.failed.length ? "warning" : "success"}
            showIcon
            style={{ marginBottom: 16 }}
            message={
              result.submit
                ? t("batch.resultScan", { ok: result.created.length, fail: result.failed.length })
                : t("batch.resultDraft", { ok: result.created.length, fail: result.failed.length })
            }
          />
          <Table
            rowKey={(r) => String(r.request_id || r.row || r.error)}
            size="small"
            pagination={false}
            dataSource={[
              ...result.created.map((x) => ({ ...x, kind: "ok" as const })),
              ...result.failed.map((x) => ({ ...x, kind: "fail" as const })),
            ] as Array<Record<string, unknown> & { kind: "ok" | "fail" }>}
            columns={[
              { title: t("common.line"), dataIndex: "row", width: 70 },
              {
                title: t("nav.requests"),
                render: (_, row) =>
                  row.request_id ? (
                    <Link to={`/requests/${String(row.request_id)}`}>{String(row.title || row.project || row.request_id)}</Link>
                  ) : (
                    String(row.project || t("common.none"))
                  ),
              },
              {
                title: t("common.status"),
                render: (_, row) =>
                  row.kind === "fail" ? (
                    <Tag color="red">{String(row.error || t("common.failed"))}</Tag>
                  ) : (
                    <Tag color="blue">{REQUEST_STATUS_LABELS[String(row.status || "")] || String(row.status || t("batch.created"))}</Tag>
                  ),
              },
            ]}
          />
          <div className="page-toolbar">
            <Button type="primary" onClick={() => nav("/requests")}>
              {t("batch.viewList")}
            </Button>
            <Button
              onClick={() => {
                setRows([]);
                setResult(null);
                setStep(0);
              }}
            >
              {t("batch.again")}
            </Button>
          </div>
        </Card>
      )}
    </>
  );
  return embedded ? body : <div className="page-shell">{body}</div>;
}
