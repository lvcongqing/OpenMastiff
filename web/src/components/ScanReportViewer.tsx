import { Alert, Collapse, Descriptions, Empty, Spin, Table, Tag, Typography } from "antd";
import { t } from "../i18n";
import { useI18n } from "../i18n/LocaleContext";
import {
  asRecord,
  cppcheckRows,
  extractLogForReport,
  issueRows,
  licenseInventory,
  licensePackages,
  sbomItems,
} from "../utils/scanReports";

const PREVIEW_CHARS = 400000;

export type ScanFailureInfo = {
  reason?: string;
  detail?: string;
  error?: string;
  log_tail?: string;
  next_steps?: string[];
  category?: string;
};

function gateLabel(status?: string) {
  const s = String(status || "").toLowerCase();
  if (s === "pass") return { text: t("gate.pass"), color: "success" as const };
  if (s === "fail") return { text: t("gate.fail"), color: "error" as const };
  if (s === "pending_legal") return { text: t("gate.pending_legal"), color: "warning" as const };
  if (s === "skipped") return { text: t("gate.skipped"), color: "default" as const };
  return { text: status || t("common.unknown"), color: "default" as const };
}

function previewText(text: string) {
  if (text.length <= PREVIEW_CHARS) return { text, truncated: false };
  return { text: `${text.slice(0, PREVIEW_CHARS)}\n\n${t("scan.previewCut")}`, truncated: true };
}

function countIssues(rows: { severity: string }[]) {
  const out = { high: 0, medium: 0, low: 0, error: 0, warning: 0, other: 0 };
  for (const r of rows) {
    const s = r.severity.toUpperCase();
    if (s === "HIGH") out.high += 1;
    else if (s === "MEDIUM") out.medium += 1;
    else if (s === "LOW") out.low += 1;
    else if (s === "ERROR") out.error += 1;
    else if (s === "WARNING") out.warning += 1;
    else out.other += 1;
  }
  return out;
}

function IssueTable({ rows }: { rows: ReturnType<typeof issueRows> }) {
  const { t } = useI18n();
  if (!rows.length) return null;
  return (
    <Table
      size="small"
      style={{ marginTop: 8 }}
      pagination={rows.length > 20 ? { pageSize: 20, showSizeChanger: true } : false}
      dataSource={rows}
      columns={[
        { title: t("common.severity"), dataIndex: "severity", width: 100 },
        { title: t("common.rule"), dataIndex: "rule_id", width: 140, ellipsis: true },
        { title: t("common.file"), dataIndex: "file", ellipsis: true },
        { title: t("common.line"), dataIndex: "line", width: 70 },
        { title: t("common.detail"), dataIndex: "message", ellipsis: true },
      ]}
    />
  );
}

function PackageTable({
  rows,
  title,
  sbom,
}: {
  rows: ReturnType<typeof sbomItems>;
  title: string;
  sbom?: boolean;
}) {
  const { t } = useI18n();
  const dash = t("common.none");
  const columns = [
    { title: t("common.name"), dataIndex: "name", ellipsis: true, render: (v: string) => v || dash },
    { title: t("scan.version"), dataIndex: "version", width: 140, render: (v: string) => v || dash },
    { title: t("common.type"), dataIndex: "type", width: 120, render: (v: string) => v || dash },
    { title: t("overview.license"), dataIndex: "license", ellipsis: true, render: (v: string) => v || dash },
    ...(sbom
      ? [
          { title: "PURL", dataIndex: "purl", ellipsis: true, render: (v: string) => v || dash },
          { title: t("scan.path"), dataIndex: "path", ellipsis: true, render: (v: string) => v || dash },
          { title: t("scan.direct"), dataIndex: "dependsOn", ellipsis: true, render: (v: string) => v || dash },
        ]
      : [{ title: t("scan.path"), dataIndex: "path", ellipsis: true, render: (v: string) => v || dash }]),
  ];
  return (
    <div style={{ marginTop: 12 }}>
      <Typography.Text strong>
        {t("scan.titleN", { title, n: rows.length })}
      </Typography.Text>
      {rows.length === 0 ? (
        <div className="muted" style={{ marginTop: 8 }}>
          {t("scan.noBom")}
        </div>
      ) : (
        <Table
          size="small"
          style={{ marginTop: 8 }}
          scroll={{ x: sbom ? 1100 : undefined }}
          pagination={rows.length > 20 ? { pageSize: 20, showSizeChanger: true, showTotal: (n) => t("common.totalN", { n }) } : false}
          dataSource={rows}
          columns={columns}
        />
      )}
    </div>
  );
}

function InterpretLogs({ text, failure }: { text?: string; failure?: ScanFailureInfo }) {
  const { t } = useI18n();
  const reason = String(failure?.reason || failure?.error || "").trim();
  const raw = String(failure?.detail || failure?.error || "").trim();
  const showRaw = raw && raw !== reason;
  const steps = Array.isArray(failure?.next_steps) ? failure!.next_steps! : [];
  const body = String(text || failure?.log_tail || "").trim();
  return (
    <>
      <Typography.Paragraph>
        {reason ? (
          <>
            {t("scan.failReason")}
            <Typography.Text strong>{reason}</Typography.Text>
          </>
        ) : (
          t("scan.processLog")
        )}
      </Typography.Paragraph>
      {showRaw ? (
        <Typography.Paragraph>
          <Typography.Text type="secondary">{t("scan.rawError")}</Typography.Text>
          <Typography.Text code copyable>
            {raw}
          </Typography.Text>
        </Typography.Paragraph>
      ) : null}
      {steps.length > 0 ? (
        <div style={{ marginBottom: 12 }}>
          {t("scan.nextSteps")}
          <ul style={{ margin: "6px 0 0 18px", padding: 0 }}>
            {steps.map((s, i) => (
              <li key={`${i}-${s}`}>{s}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {body ? (
        <Collapse
          bordered={false}
          defaultActiveKey={[]}
          style={{ background: "transparent" }}
          items={[
            {
              key: "log",
              label: t("scan.logs"),
              children: <pre className="report-viewer-pre">{previewText(body).text}</pre>,
            },
          ]}
        />
      ) : (
        <Typography.Paragraph type="secondary">{t("scan.noLog")}</Typography.Paragraph>
      )}
    </>
  );
}

function InterpretSummary({ data }: { data: Record<string, unknown> }) {
  const { t } = useI18n();
  const gate = asRecord(asRecord(data.gate)?.overall) || {};
  const g = gateLabel(String(gate.status || ""));
  const input = asRecord(data.input) || {};
  const ecos = Array.isArray(input.ecosystems_detected) ? input.ecosystems_detected.map(String) : [];
  const tools = asRecord(data.tools) || {};
  const gates = asRecord(data.gate) || {};
  const license = asRecord(data.license) || {};
  const sep = t("common.listSep");
  return (
    <>
      <Typography.Paragraph>
        {t("scan.summaryLead")} <Tag color={g.color}>{g.text}</Tag>
        {gate.reason ? `${t("common.colon")}${String(gate.reason)}` : "."}
        {ecos.length ? ` ${t("scan.ecos", { list: ecos.join(sep) })}` : ` ${t("scan.noEcos")}`}
        {license.hits && Array.isArray(license.hits) && license.hits.length
          ? ` ${t("scan.licenseHits", { list: license.hits.map(String).join(sep) })}`
          : ""}
      </Typography.Paragraph>
      <Descriptions size="small" column={2} bordered>
        {["license", "gosec", "cppcheck", "bandit", "pmd", "cargo_audit", "eslint", "maintenance"].map((key) => {
          const tg = asRecord(gates[key]);
          const tool = asRecord(tools[key]);
          if (!tg && !tool) return null;
          const st = gateLabel(String(tg?.status || tool?.status || ""));
          const counts = asRecord(tool?.counts);
          const countText = counts
            ? Object.entries(counts)
                .map(([k, v]) => `${k} ${v}`)
                .join(" / ")
            : "";
          return (
            <Descriptions.Item key={key} label={key}>
              <Tag color={st.color}>{st.text}</Tag>
              {tg?.reason ? String(tg.reason) : ""}
              {countText ? `（${countText}）` : ""}
            </Descriptions.Item>
          );
        })}
      </Descriptions>
    </>
  );
}

function InterpretLicense({ data }: { data: Record<string, unknown> }) {
  const { t } = useI18n();
  const gate = asRecord(data.gate) || {};
  const g = gateLabel(String(gate.status || ""));
  const inventory = licenseInventory(data);
  const packages = licensePackages(data);
  const deny = Array.isArray(data.deny_hits) ? data.deny_hits.map(String) : [];
  const legal = Array.isArray(data.legal_review_hits) ? data.legal_review_hits.map(String) : [];
  const hits = Array.isArray(data.hits) ? data.hits.map(String) : inventory.map((x) => x.name);
  const sep = t("common.listSep");
  const dash = t("common.none");
  return (
    <>
      <Typography.Paragraph>
        {t("scan.licenseGate")} <Tag color={g.color}>{g.text}</Tag>
        {gate.reason ? `${t("common.colon")}${String(gate.reason)}` : "."}
        {hits.length ? ` ${t("scan.licenseKinds", { n: hits.length, list: hits.join(sep) })}` : ` ${t("scan.noLicense")}`}
        {deny.length ? ` ${t("scan.denyHits", { list: deny.join(sep) })}` : ""}
        {legal.length ? ` ${t("scan.legalHits", { list: legal.join(sep) })}` : ""}
        {packages.length ? ` ${t("scan.packages", { n: packages.length })}` : ""}
      </Typography.Paragraph>
      {inventory.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <Typography.Text strong>{t("scan.licenseList", { n: inventory.length })}</Typography.Text>
          <Table
            size="small"
            style={{ marginTop: 8 }}
            pagination={false}
            dataSource={inventory}
            columns={[
              { title: t("scan.licenseName"), dataIndex: "name", render: (v: string) => v || dash },
              { title: t("scan.count"), dataIndex: "count", width: 120 },
            ]}
          />
        </div>
      )}
      <PackageTable rows={packages} title={t("scan.pkgLicense")} />
      {Array.isArray(data.files) && data.files.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <Typography.Text strong>{t("scan.fileLicense", { n: data.files.length })}</Typography.Text>
          <Table
            size="small"
            style={{ marginTop: 8 }}
            pagination={data.files.length > 20 ? { pageSize: 20 } : false}
            dataSource={(data.files as unknown[]).map((raw, i) => {
              const it = asRecord(raw) || {};
              return {
                key: `${i}`,
                path: String(it.path || it.file || ""),
                license: Array.isArray(it.licenses)
                  ? it.licenses
                      .map((x) => (typeof x === "string" ? x : String(asRecord(x)?.spdx_license_key || asRecord(x)?.key || "")))
                      .filter(Boolean)
                      .join("；")
                  : String(it.license || it.detected_license_expression || ""),
              };
            })}
            columns={[
              { title: t("common.file"), dataIndex: "path", ellipsis: true, render: (v: string) => v || dash },
              { title: t("scan.licenseName"), dataIndex: "license", ellipsis: true, render: (v: string) => v || dash },
            ]}
          />
        </div>
      )}
    </>
  );
}

function InterpretSast({
  name,
  data,
  xml,
}: {
  name: string;
  data: Record<string, unknown> | null;
  xml?: string;
}) {
  const { t } = useI18n();
  const rows = data ? issueRows(data) : xml ? cppcheckRows(xml) : [];
  const c = countIssues(rows);
  const note = data ? String(data.note || "") : "";
  const engine = data ? String(data.engine || data.tool || "") : "";
  const stats = asRecord(data?.Stats || data?.stats);
  const countText = name.endsWith(".xml")
    ? t("scan.cppCounts", { error: c.error, warning: c.warning, other: c.other })
    : t("scan.sastCounts", { high: c.high, medium: c.medium, low: c.low });
  return (
    <>
      <Typography.Paragraph>
        {engine ? t("scan.engine", { engine }) : ""}
        {rows.length
          ? t("scan.issues", { n: rows.length, counts: countText })
          : t("scan.noIssues")}
        {stats?.files != null ? ` ${t("scan.filesN", { n: String(stats.files) })}` : ""}
        {note ? ` ${note}` : ""}
      </Typography.Paragraph>
      <IssueTable rows={rows} />
    </>
  );
}

function InterpretMaintenance({ data }: { data: Record<string, unknown> }) {
  const { t } = useI18n();
  const overall = asRecord(data.overall) || {};
  const g = gateLabel(String(overall.status || ""));
  const upstream = asRecord(data.upstream) || {};
  const deps = Array.isArray(data.dependencies) ? data.dependencies : [];
  return (
    <>
      <Typography.Paragraph>
        {t("scan.maintGate")} <Tag color={g.color}>{g.text}</Tag>
        {overall.reason ? `${t("common.colon")}${String(overall.reason)}` : "."}
        {upstream.repo ? ` ${t("scan.upstreamRepo", { repo: String(upstream.repo) })}` : ""}
        {upstream.score != null ? ` ${t("scan.upstreamScore", { score: String(upstream.score) })}` : ""}
        {deps.length ? ` ${t("scan.directDeps", { n: deps.length })}` : ""}
      </Typography.Paragraph>
    </>
  );
}

function extractCveIds(it: Record<string, unknown>): string[] {
  const raw = [it.id, ...((Array.isArray(it.aliases) ? it.aliases : []) as unknown[])];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    const id = String(item || "").trim().toUpperCase();
    if (!/^CVE-\d{4}-\d+$/.test(id) || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

function formatCvss(value: unknown): string {
  if (value == null || value === "") return "—";
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return n % 1 === 0 ? String(n) : n.toFixed(1);
}

function InterpretCve({ data }: { data: Record<string, unknown> }) {
  const { t } = useI18n();
  const counts = asRecord(data.counts) || {};
  const gate = asRecord(data.gate) || {};
  const g = gateLabel(String(gate.status || ""));
  const engines = Array.isArray(data.engines) ? data.engines : [];
  const matches = Array.isArray(data.matches) ? data.matches : [];
  const sep = t("common.listSep");
  const dash = t("common.none");
  const rows = matches.map((raw, i) => {
    const it = asRecord(raw) || {};
    const fixes = Array.isArray(it.fix_versions) ? it.fix_versions.map(String).filter(Boolean).join(sep) : "";
    const cveIds = extractCveIds(it);
    return {
      key: `${i}`,
      id: String(it.id || ""),
      cve: cveIds.join(sep) || dash,
      cvss: formatCvss(it.cvss),
      severity: String(it.severity || ""),
      pkg: `${String(it.package || "")}${it.version ? `@${it.version}` : ""}`,
      ecosystem: String(it.ecosystem || ""),
      fix: fixes || String(it.fix_state || dash),
      engine: String(it.engine || ""),
    };
  });
  const scored = rows.filter((r) => r.cvss !== "—");
  const maxCvss = scored.length
    ? Math.max(...scored.map((r) => Number(r.cvss)))
    : null;
  return (
    <>
      <Typography.Paragraph>
        {t("scan.cveGate")} <Tag color={g.color}>{g.text}</Tag>
        {gate.reason ? `${t("common.colon")}${String(gate.reason)}` : "."}
        {" "}
        Critical {Number(counts.critical || 0)} / High {Number(counts.high || 0)} / Medium {Number(counts.medium || 0)} / Low{" "}
        {Number(counts.low || 0)}. {t("common.totalN", { n: rows.length })}
        {maxCvss != null ? t("scan.maxCvss", { n: formatCvss(maxCvss) }) : ""}.
      </Typography.Paragraph>
      {engines.length ? (
        <Typography.Paragraph type="secondary">
          {t("scan.enginesLabel")}
          {engines
            .map((raw) => {
              const e = asRecord(raw) || {};
              return `${String(e.name || dash)}（${String(e.status || dash)}）`;
            })
            .join(sep)}
        </Typography.Paragraph>
      ) : null}
      {rows.length ? (
        <Table
          size="small"
          scroll={{ x: 1100 }}
          pagination={rows.length > 20 ? { pageSize: 20, showSizeChanger: true, showTotal: (n) => t("common.totalN", { n }) } : false}
          dataSource={rows}
          columns={[
            { title: t("common.severity"), dataIndex: "severity", width: 90 },
            { title: "CVE", dataIndex: "cve", width: 170, ellipsis: true },
            { title: "CVSS", dataIndex: "cvss", width: 80 },
            { title: t("scan.id"), dataIndex: "id", width: 200, ellipsis: true },
            { title: t("common.component"), dataIndex: "pkg", ellipsis: true },
            { title: t("scan.eco"), dataIndex: "ecosystem", width: 90 },
            { title: t("scan.fix"), dataIndex: "fix", ellipsis: true },
            { title: t("scan.engineCol"), dataIndex: "engine", width: 90 },
          ]}
        />
      ) : (
        <Typography.Paragraph type="secondary">{t("scan.noCve")}</Typography.Paragraph>
      )}
    </>
  );
}

export default function ScanReportViewer({
  name,
  text,
  logText,
  loading,
  error,
  failure,
}: {
  name: string;
  text?: string;
  logText?: string;
  loading?: boolean;
  error?: string;
  failure?: ScanFailureInfo;
}) {
  const { t } = useI18n();
  if (loading) {
    return (
      <div style={{ padding: 48, textAlign: "center" }}>
        <Spin />
      </div>
    );
  }
  if (name === "logs.txt") {
    return (
      <div>
        <Typography.Text strong>{t("scan.interpret")}</Typography.Text>
        <div style={{ marginTop: 8 }}>
          <InterpretLogs text={text} failure={failure} />
        </div>
      </div>
    );
  }
  if (error) return <Alert type="error" showIcon message={error} />;
  if (!text) return <Empty description={t("scan.empty")} />;

  const parsed = (() => {
    if (!name.endsWith(".json")) return null;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return null;
    }
  })();
  const rec = asRecord(parsed);
  const pretty = parsed != null ? JSON.stringify(parsed, null, 2) : text;
  const shown = previewText(pretty);
  const scannerLog = extractLogForReport(logText || "", name);

  let interpret: JSX.Element | null = null;
  if (name === "summary.json" && rec) interpret = <InterpretSummary data={rec} />;
  else if (name === "license.json" && rec) interpret = <InterpretLicense data={rec} />;
  else if (name === "maintenance.json" && rec) interpret = <InterpretMaintenance data={rec} />;
  else if (name === "cve.json" && rec) interpret = <InterpretCve data={rec} />;
  else if (name.startsWith("sbom") && rec) {
    const items = sbomItems(parsed);
    interpret = (
      <>
        <Typography.Paragraph>{t("scan.sbomHint")}</Typography.Paragraph>
        <Typography.Paragraph>
          {t("scan.sbomParsed", { n: items.length })}
          {items.filter((x) => x.dependsOn).length
            ? t("scan.declaredDeps", { n: items.filter((x) => x.dependsOn).length })
            : ""}
          . {t("scan.sbomUnify")}
        </Typography.Paragraph>
        <PackageTable rows={items} title={t("scan.bom")} sbom />
      </>
    );
  } else if (name.endsWith(".xml")) interpret = <InterpretSast name={name} data={null} xml={text} />;
  else if (rec && Array.isArray(rec.Issues)) interpret = <InterpretSast name={name} data={rec} />;
  else {
    interpret = <Typography.Paragraph>{t("scan.unstructured")}</Typography.Paragraph>;
  }

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Typography.Text strong>{t("scan.interpret")}</Typography.Text>
        <div style={{ marginTop: 8 }}>{interpret}</div>
      </div>
      <Collapse
        bordered={false}
        defaultActiveKey={[]}
        style={{ background: "transparent" }}
        items={[
          {
            key: "raw",
            label: t("scan.raw"),
            children: (
              <>
                {shown.truncated ? (
                  <Alert type="info" showIcon style={{ marginBottom: 8 }} message={t("scan.truncated")} />
                ) : null}
                <pre className="report-viewer-pre">{shown.text}</pre>
              </>
            ),
          },
          ...(scannerLog
            ? [
                {
                  key: "log",
                  label: t("scan.logs"),
                  children: <pre className="report-viewer-pre">{scannerLog}</pre>,
                },
              ]
            : []),
        ]}
      />
    </div>
  );
}
