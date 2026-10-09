import { Breadcrumb, Button, Card, Space, Spin, Tabs, Tag, Typography, message } from "antd";
import { CloudDownloadOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { downloadArtifact, getArtifactText, getRequest, getScanRun } from "../api/client";
import ScanReportViewer, { type ScanFailureInfo } from "../components/ScanReportViewer";
import { GATE_STATUS_LABELS } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";
import { listVisibleReports } from "../utils/scanReports";

const statusColors: Record<string, string> = {
  queued: "default",
  running: "processing",
  succeeded: "success",
  failed: "error",
};

export default function ScanRunDetail() {
  const { t, locale } = useI18n();
  const { requestId = "", scanRunId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [req, setReq] = useState<Record<string, unknown> | null>(null);
  const [run, setRun] = useState<Record<string, unknown> | null>(null);
  const [cache, setCache] = useState<Record<string, { text: string; error?: string }>>({});
  const [loadingArt, setLoadingArt] = useState(false);

  const failed = String(run?.status || "").toLowerCase() === "failed";
  const reports = useMemo(() => {
    const listed = listVisibleReports((run?.outputs || {}) as Record<string, { path?: string; bytes?: number }>, {
      includeLogs: failed,
    });
    if (!failed) return listed;
    if (listed.some((r) => r.name === "logs.txt")) {
      return [...listed.filter((r) => r.name === "logs.txt"), ...listed.filter((r) => r.name !== "logs.txt")];
    }
    return [{ name: "logs.txt", label: t("scan.logs"), group: "overview" as const, bytes: 0 }, ...listed];
  }, [run, failed, t, locale]);
  const reportParam = searchParams.get("report") || "";
  const fallback = failed && reports.some((r) => r.name === "logs.txt") ? "logs.txt" : reports[0]?.name || "";
  const active = reports.some((r) => r.name === reportParam) ? reportParam : fallback;
  const failure: ScanFailureInfo | undefined = failed
    ? {
        error: String(run?.error || ""),
        ...(typeof run?.failure_detail === "object" && run?.failure_detail ? (run.failure_detail as ScanFailureInfo) : {}),
      }
    : undefined;

  const load = useCallback(async () => {
    if (!requestId || !scanRunId) return;
    setLoading(true);
    try {
      const [bundle, sr] = await Promise.all([getRequest(requestId), getScanRun(scanRunId)]);
      if (String(sr.request_id || "") && String(sr.request_id) !== requestId) {
        message.error(t("scan.mismatch"));
        setRun(null);
        return;
      }
      setReq(bundle.request);
      setRun(sr);
    } catch {
      message.error(t("scan.loadFail"));
      setRun(null);
    } finally {
      setLoading(false);
    }
  }, [requestId, scanRunId, t]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!scanRunId || !run) return;
    const outs = (run.outputs || {}) as Record<string, unknown>;
    if (!failed && !outs["logs.txt"]) return;
    if (cache["logs.txt"]) return;
    getArtifactText(scanRunId, "logs.txt")
      .then((text) => setCache((c) => ({ ...c, ["logs.txt"]: { text } })))
      .catch(() => setCache((c) => ({ ...c, ["logs.txt"]: { text: "" } })));
  }, [scanRunId, run, cache, failed]);

  useEffect(() => {
    if (!scanRunId || !active || cache[active]) return;
    let cancelled = false;
    setLoadingArt(true);
    getArtifactText(scanRunId, active)
      .then((text) => {
        if (!cancelled) setCache((c) => ({ ...c, [active]: { text } }));
      })
      .catch(() => {
        if (!cancelled) setCache((c) => ({ ...c, [active]: { text: "", error: t("scan.reportFail") } }));
      })
      .finally(() => {
        if (!cancelled) setLoadingArt(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanRunId, active, cache]);

  if (loading) {
    return (
      <div className="page-shell" style={{ padding: 48, textAlign: "center" }}>
        <Spin />
      </div>
    );
  }
  if (!run) {
    return <Typography.Text type="danger">{t("scan.notFound")}</Typography.Text>;
  }

  const gate = String(run.gate_status || "");
  const status = String(run.status || "");
  const title = String(req?.title || req?.project || requestId);

  return (
    <div className="page-shell">
      <Breadcrumb
        items={[
          { title: <Link to="/requests">{t("nav.requests")}</Link> },
          { title: <Link to={`/requests/${requestId}?tab=scans`}>{title}</Link> },
          { title: t("scan.title") },
        ]}
        style={{ marginBottom: 12 }}
      />
      <Space align="center" wrap style={{ marginBottom: 8 }}>
        <h1 className="page-title" style={{ margin: 0 }}>
          {t("scan.title")}
        </h1>
        <Tag color={statusColors[status.toLowerCase()] || "default"}>{status || "—"}</Tag>
        <Tag color={gate === "Pass" ? "success" : gate === "Fail" ? "error" : gate === "PendingLegal" ? "warning" : "default"}>
          Gate {GATE_STATUS_LABELS[gate] || gate || "—"}
        </Tag>
      </Space>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {scanRunId}
        {run.created_at ? ` · ${String(run.created_at)}` : ""}
        {run.exit_code != null ? ` · ${t("scan.exitCode", { n: String(run.exit_code) })}` : ""}
      </Typography.Paragraph>

      <Card className="panel-card">
        {reports.length === 0 ? (
          <Typography.Text type="secondary">{t("scan.noReports")}</Typography.Text>
        ) : (
          <Tabs
            activeKey={active}
            onChange={(key) => {
              const next = new URLSearchParams(searchParams);
              next.set("report", key);
              setSearchParams(next, { replace: true });
            }}
            tabBarExtraContent={
              active ? (
                <Button
                  size="small"
                  icon={<CloudDownloadOutlined />}
                  onClick={async () => {
                    try {
                      await downloadArtifact(scanRunId, active);
                    } catch {
                      message.error(t("scan.downloadFail"));
                    }
                  }}
                >
                  {t("scan.downloadCurrent")}
                </Button>
              ) : null
            }
            items={reports.map((r) => ({
              key: r.name,
              label: r.label,
              children: (
                <ScanReportViewer
                  name={r.name}
                  text={cache[r.name]?.text}
                  logText={cache["logs.txt"]?.text}
                  error={cache[r.name]?.error}
                  loading={active === r.name && loadingArt && !cache[r.name]}
                  failure={r.name === "logs.txt" ? failure : undefined}
                />
              ),
            }))}
          />
        )}
      </Card>
    </div>
  );
}
