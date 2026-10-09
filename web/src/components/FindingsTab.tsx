import { Alert, Button, Card, Dropdown, Form, Input, Modal, Select, Space, Table, Tag, Tooltip, Typography, message } from "antd";
import { useMemo, useState, type ReactNode } from "react";
import { apiErrorMessage, disposeFindings } from "../api/client";
import {
  DISPOSITION_COLORS,
  DISPOSITION_LABELS,
  FINDING_CATEGORY_LABELS,
  GATE_STATUS_LABELS,
} from "../constants/display";
import { t } from "../i18n";
import { useI18n } from "../i18n/LocaleContext";

type Finding = Record<string, unknown>;

type Props = {
  requestId: string;
  findings: Finding[];
  gateStatus: string;
  canDispose: boolean;
  onRefresh: () => void;
  /** 用于旧扫描记录推断 CVE 是本软件还是依赖包 */
  projectHints?: string[];
};

const CVE_SEV_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"];
function sevLabel(s: string) {
  return t(`severity.${s}`);
}

function scopeLabel(s: string) {
  return t(`cveScope.${s}`);
}

type QuickGroup = {
  key: string;
  kind: "cve" | "rule";
  category: string;
  rule_id: string;
  cveScope?: "self" | "dependency";
  severity?: string;
  label: string;
  total: number;
  openHigh: number;
  open: number;
};

type PendingAction = {
  disposition: "open" | "false_positive" | "accepted_risk" | "confirmed";
  fingerprints: string[];
  title: string;
};

function findingFp(row: Finding): string {
  return String(row.fingerprint || "");
}

async function copyText(text: string) {
  const value = String(text || "").trim();
  if (!value || value === "—") {
    message.warning(t("common.nothingToCopy"));
    return;
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      const el = document.createElement("textarea");
      el.value = value;
      el.style.position = "fixed";
      el.style.left = "-9999px";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
    }
    message.success(t("common.copied"));
  } catch {
    message.error(t("common.copyFailed"));
  }
}

function findingFile(row: Finding): string {
  const loc = (row.location || {}) as Record<string, unknown>;
  return String(loc.file || row.file || "—");
}

function findingLine(row: Finding): string {
  const loc = (row.location || {}) as Record<string, unknown>;
  const line = loc.line ?? row.line;
  return line === 0 || line ? String(line) : "—";
}

function normalizeCveSev(raw: unknown): string {
  const s = String(raw || "").toLowerCase().trim();
  if (s === "error" || s === "fatal") return "high";
  if (s === "warning" || s === "warn") return "medium";
  if (s === "info" || s === "informational") return "low";
  if (CVE_SEV_ORDER.includes(s)) return s;
  return s || "unknown";
}

function packageName(row: Finding): string {
  const pkg = String(row.package || "").trim();
  if (pkg) return pkg;
  const purl = String(row.purl || "");
  const m = purl.match(/^pkg:[^/]+\/(?:[^/]+\/)*([^@/?#]+)/i);
  return m ? decodeURIComponent(m[1].replace(/%40/g, "@")) : "";
}

function inferCveScope(row: Finding, hints: string[]): "self" | "dependency" {
  const stored = String(row.cve_scope || "").toLowerCase().trim();
  if (stored === "self" || stored === "dependency") return stored;
  const pkg = packageName(row).toLowerCase();
  if (!pkg) return "dependency";
  for (const raw of hints) {
    const t = String(raw || "").trim().toLowerCase();
    if (!t) continue;
    if (pkg === t) return "self";
    if (pkg.endsWith("/" + t)) return "self";
    if (pkg.startsWith("@" + t + "/")) return "self";
    if (t.startsWith("@") && t.includes("/") && pkg.startsWith(t.slice(0, t.lastIndexOf("/") + 1))) return "self";
  }
  return "dependency";
}

function cveIdLabel(row: Finding): string {
  const rule = String(row.rule_id || "");
  const extras: string[] = [];
  if (Array.isArray(row.cve_ids)) extras.push(...row.cve_ids.map(String));
  if (Array.isArray(row.aliases)) extras.push(...row.aliases.map(String));
  const cve = extras.find((x) => x.toUpperCase().startsWith("CVE-"));
  if (cve && rule && !rule.toUpperCase().startsWith("CVE-")) return cve;
  return cve || rule || "—";
}

function componentLabel(row: Finding): string {
  const pkg = packageName(row);
  const ver = String(row.version || "").trim();
  if (pkg && ver) return `${pkg}@${ver}`;
  return pkg || "—";
}

function isSelfBlockingCve(row: Finding, hints: string[]): boolean {
  if (String(row.category || "") !== "cve") return false;
  if (inferCveScope(row, hints) !== "self") return false;
  const sev = normalizeCveSev(row.severity);
  return sev === "critical" || sev === "high";
}

function findingRowText(row: Finding, hints: string[]): string {
  const cat = String(row.category || "");
  const catLabel = FINDING_CATEGORY_LABELS[cat] || cat || "—";
  const scope = cat === "cve" ? scopeLabel(inferCveScope(row, hints)) : "";
  const disp = String(row.disposition || "open");
  const colon = t("common.colon");
  const lines = [
    `${t("findings.rowSeverity")}${colon}${String(row.severity || t("common.none"))}`,
    `${t("findings.rowRule")}${colon}${cat === "cve" ? cveIdLabel(row) : String(row.rule_id || t("common.none"))}`,
    `${t("findings.rowCategory")}${colon}${catLabel}${scope ? ` / ${scope}` : ""}`,
  ];
  if (cat === "cve") lines.push(`${t("findings.rowComponent")}${colon}${componentLabel(row)}`);
  lines.push(`${t("findings.rowFile")}${colon}${findingFile(row)}`);
  lines.push(`${t("findings.rowLine")}${colon}${findingLine(row)}`);
  lines.push(`${t("findings.rowDetail")}${colon}${String(row.detail || row.title || t("common.none"))}`);
  lines.push(`${t("findings.rowDisposition")}${colon}${DISPOSITION_LABELS[disp] || disp}`);
  return lines.join("\n");
}

function CopyableCell({ field, rowText, children }: { field: string; rowText: string; children: ReactNode }) {
  const { t } = useI18n();
  return (
    <Dropdown
      trigger={["contextMenu"]}
      menu={{
        items: [
          { key: "field", label: t("findings.copyField") },
          { key: "row", label: t("findings.copyRow") },
        ],
        onClick: ({ key }) => {
          void copyText(key === "row" ? rowText : field);
        },
      }}
    >
      <span className="copyable-cell" title={field && field !== t("common.none") ? t("findings.copyTitle", { field }) : undefined}>
        {children}
      </span>
    </Dropdown>
  );
}

export default function FindingsTab({
  requestId,
  findings,
  gateStatus,
  canDispose,
  onRefresh,
  projectHints = [],
}: Props) {
  const { t } = useI18n();
  const [category, setCategory] = useState<string>();
  const [severity, setSeverity] = useState<string>();
  const [disposition, setDisposition] = useState<string>();
  const [ruleId, setRuleId] = useState<string>();
  const [cveScope, setCveScope] = useState<"self" | "dependency" | undefined>();
  const [keyword, setKeyword] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm();

  const hasCve = findings.some((f) => String(f.category || "") === "cve");

  const ruleStats = useMemo(() => {
    const map = new Map<string, QuickGroup>();
    for (const f of findings) {
      const cat = String(f.category || "");
      const disp = String(f.disposition || "open");
      const sevRaw = String(f.severity || "").toLowerCase();
      const isOpen = disp === "open" || disp === "confirmed";
      const isOpenHigh = isOpen && ["high", "critical", "error"].includes(sevRaw);
      let key: string;
      let cur: QuickGroup | undefined;
      if (cat === "cve") {
        const scope = inferCveScope(f, projectHints);
        const sev = normalizeCveSev(f.severity);
        key = `cve::${scope}::${sev}`;
        cur = map.get(key) || {
          key,
          kind: "cve",
          category: "cve",
          rule_id: "",
          cveScope: scope,
          severity: sev,
          label: `CVE · ${scopeLabel(scope)} · ${sevLabel(sev)}`,
          total: 0,
          openHigh: 0,
          open: 0,
        };
      } else {
        const rule = String(f.rule_id || "unknown");
        key = `${cat}::${rule}`;
        cur = map.get(key) || {
          key,
          kind: "rule",
          category: cat,
          rule_id: rule,
          label: rule,
          total: 0,
          openHigh: 0,
          open: 0,
        };
      }
      cur.total += 1;
      if (isOpen) cur.open += 1;
      if (isOpenHigh) cur.openHigh += 1;
      map.set(key, cur);
    }
    const scopeRank = (s?: string) => (s === "self" ? 0 : 1);
    const sevRank = (s?: string) => {
      const i = CVE_SEV_ORDER.indexOf(s || "");
      return i < 0 ? 99 : i;
    };
    return [...map.values()].sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "cve" ? -1 : 1;
      if (a.kind === "cve" && b.kind === "cve") {
        const sr = scopeRank(a.cveScope) - scopeRank(b.cveScope);
        if (sr) return sr;
        const sv = sevRank(a.severity) - sevRank(b.severity);
        if (sv) return sv;
      }
      return b.openHigh - a.openHigh || b.total - a.total;
    });
  }, [findings, projectHints]);

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase();
    return findings.filter((f) => {
      const cat = String(f.category || "");
      if (category && cat !== category) return false;
      if (severity) {
        const raw = String(f.severity || "").toLowerCase();
        if (raw !== severity && normalizeCveSev(raw) !== severity) return false;
      }
      if (disposition && String(f.disposition || "open") !== disposition) return false;
      if (cveScope) {
        if (cat !== "cve" || inferCveScope(f, projectHints) !== cveScope) return false;
      }
      if (ruleId && String(f.rule_id || "") !== ruleId) return false;
      if (!kw) return true;
      const hay = [f.rule_id, f.title, f.detail, findingFile(f), f.category, f.package, f.purl, ...(Array.isArray(f.aliases) ? f.aliases : []), ...(Array.isArray(f.cve_ids) ? f.cve_ids : [])]
        .map((x) => String(x || "").toLowerCase())
        .join(" ");
      return hay.includes(kw);
    });
  }, [findings, category, severity, disposition, ruleId, cveScope, keyword, projectHints]);

  const openHigh = findings.filter((f) => {
    const disp = String(f.disposition || "open");
    const sev = String(f.severity || "").toLowerCase();
    return (disp === "open" || disp === "confirmed") && ["high", "critical", "error"].includes(sev);
  }).length;
  const cleared = findings.filter((f) => ["false_positive", "accepted_risk"].includes(String(f.disposition || ""))).length;

  const openAction = (action: PendingAction) => {
    if (!canDispose) {
      message.warning(t("findings.noPerm"));
      return;
    }
    if (!action.fingerprints.length) {
      message.warning(t("findings.pickFirst"));
      return;
    }
    form.resetFields();
    setPending(action);
  };

  const apply = async () => {
    if (!pending) return;
    try {
      const v = await form.validateFields();
      setBusy(true);
      const res = await disposeFindings(requestId, {
        disposition: pending.disposition,
        fingerprints: pending.fingerprints,
        reason: v.reason,
      });
      const gateLabel = GATE_STATUS_LABELS[String(res.gate_status || "")] || res.gate_status || "";
      message.success(t("findings.processed", { n: res.updated, gate: gateLabel, high: res.open_high ?? t("common.none") }));
      setPending(null);
      setSelected([]);
      onRefresh();
    } catch (e: unknown) {
      if ((e as { errorFields?: unknown })?.errorFields) return;
      message.error(apiErrorMessage(e, t("findings.processFail")));
    } finally {
      setBusy(false);
    }
  };

  const filteredFps = filtered.map(findingFp).filter(Boolean);
  const needReason = pending && (pending.disposition === "false_positive" || pending.disposition === "accepted_risk");
  const filteredSelfHigh = filtered.filter((f) => isSelfBlockingCve(f, projectHints));
  const selectedRows = findings.filter((f) => selected.includes(findingFp(f)));
  const selectedSelfHigh = selectedRows.filter((f) => isSelfBlockingCve(f, projectHints));
  const blockAcceptedRisk = filteredSelfHigh.length > 0;
  const fpHintSelf = pending?.disposition === "false_positive" && filteredSelfHigh.length + selectedSelfHigh.length > 0;

  return (
    <Card className="panel-card">
      <Alert
        type={gateStatus === "Fail" ? "warning" : "info"}
        showIcon
        style={{ marginBottom: 12 }}
        message={t("findings.banner")}
        description={t("findings.stats", { total: findings.length, cleared, openHigh })}
      />

      {ruleStats.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <Typography.Text type="secondary">
            {hasCve ? t("findings.quickCve") : t("findings.quickRule")}
          </Typography.Text>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
            {ruleStats.map((r) => {
              const active =
                r.kind === "cve"
                  ? category === "cve" && cveScope === r.cveScope && severity === r.severity && !ruleId
                  : ruleId === r.rule_id && (!category || category === r.category) && !cveScope;
              return (
                <Button
                  key={r.key}
                  size="small"
                  type={active ? "primary" : "default"}
                  onClick={() => {
                    if (r.kind === "cve") {
                      setCategory("cve");
                      setCveScope(r.cveScope);
                      setSeverity(r.severity);
                      setRuleId(undefined);
                    } else {
                      setCategory(r.category || undefined);
                      setRuleId(r.rule_id);
                      setCveScope(undefined);
                    }
                  }}
                >
                  {r.label} · {t("findings.itemsN", { n: r.total })}
                  {r.openHigh > 0 ? t("findings.openHigh", { n: r.openHigh }) : ""}
                </Button>
              );
            })}
          </div>
        </div>
      )}

      <Space wrap style={{ marginBottom: 12 }}>
        <Select
          allowClear
          placeholder={t("common.category")}
          style={{ width: 160 }}
          value={category}
          onChange={(v) => {
            setCategory(v);
            if (v !== "cve") setCveScope(undefined);
            else setRuleId(undefined);
          }}
          options={[...new Set(findings.map((f) => String(f.category || "")).filter(Boolean))].map((x) => ({
            label: FINDING_CATEGORY_LABELS[x] || x,
            value: x,
          }))}
        />
        <Select
          allowClear
          placeholder={t("common.severity")}
          style={{ width: 120 }}
          value={severity}
          onChange={setSeverity}
          options={["critical", "high", "medium", "low", "error", "warning", "negligible"].map((x) => ({ label: sevLabel(x), value: x }))}
        />
        {hasCve && (
          <Select
            allowClear
            placeholder={t("findings.cveScope")}
            style={{ width: 140 }}
            value={cveScope}
            onChange={(v) => {
              setCveScope(v);
              if (v) {
                setCategory("cve");
                setRuleId(undefined);
              }
            }}
            options={[
              { label: t("cveScope.self"), value: "self" },
              { label: t("cveScope.dependency"), value: "dependency" },
            ]}
          />
        )}
        <Select
          allowClear
          placeholder={t("common.disposition")}
          style={{ width: 140 }}
          value={disposition}
          onChange={setDisposition}
          options={Object.entries(DISPOSITION_LABELS).map(([value, label]) => ({ value, label }))}
        />
        <Input.Search
          allowClear
          placeholder={t("findings.searchPh")}
          style={{ width: 260 }}
          onSearch={setKeyword}
          onChange={(e) => {
            if (!e.target.value) setKeyword("");
          }}
        />
        <Button
          onClick={() => {
            setCategory(undefined);
            setSeverity(undefined);
            setDisposition(undefined);
            setRuleId(undefined);
            setCveScope(undefined);
            setKeyword("");
          }}
        >
          {t("findings.clear")}
        </Button>
        <Typography.Text type="secondary">{t("findings.copyHint")}</Typography.Text>
      </Space>

      {canDispose && (
        <Space wrap style={{ marginBottom: 12 }}>
          <Button
            type="primary"
            disabled={!filteredFps.length}
            onClick={() =>
              openAction({
                disposition: "false_positive",
                fingerprints: filteredFps,
                title: t("findings.titleFilteredFp", { n: filteredFps.length }),
              })
            }
          >
            {t("findings.markFilteredFp")}
          </Button>
          <Tooltip title={blockAcceptedRisk ? t("findings.blockRisk") : undefined}>
            <span>
              <Button
                disabled={!filteredFps.length || blockAcceptedRisk}
                onClick={() =>
                  openAction({
                    disposition: "accepted_risk",
                    fingerprints: filteredFps,
                    title: t("findings.titleFilteredRisk", { n: filteredFps.length }),
                  })
                }
              >
                {t("findings.markFilteredRisk")}
              </Button>
            </span>
          </Tooltip>
          <Button
            disabled={!selected.length}
            onClick={() =>
              openAction({
                disposition: "false_positive",
                fingerprints: selected,
                title: t("findings.titleSelectedFp", { n: selected.length }),
              })
            }
          >
            {t("findings.markSelectedFp")}
          </Button>
          <Button
            disabled={!selected.length}
            onClick={() =>
              openAction({
                disposition: "confirmed",
                fingerprints: selected,
                title: t("findings.titleSelectedOk", { n: selected.length }),
              })
            }
          >
            {t("findings.markSelectedOk")}
          </Button>
          <Button
            disabled={!selected.length}
            onClick={() =>
              openAction({
                disposition: "open",
                fingerprints: selected,
                title: t("findings.titleUndo", { n: selected.length }),
              })
            }
          >
            {t("findings.undoSelected")}
          </Button>
        </Space>
      )}

      <Table
        size="small"
        rowKey={(row) => findingFp(row) || String(row.finding_id || "")}
        dataSource={filtered}
        scroll={{ x: 1100 }}
        pagination={{ pageSize: 50, showSizeChanger: true, pageSizeOptions: [20, 50, 100, 200] }}
        rowSelection={
          canDispose
            ? {
                selectedRowKeys: selected,
                onChange: (keys) => setSelected(keys.map(String)),
              }
            : undefined
        }
        columns={[
          {
            title: t("findings.rowSeverity"),
            dataIndex: "severity",
            width: 80,
            render: (v: string, row: Finding) => {
              const s = String(v || "").toLowerCase();
              const color = s === "high" || s === "critical" || s === "error" ? "red" : s === "medium" || s === "warning" ? "orange" : "default";
              return (
                <CopyableCell field={String(v || "—")} rowText={findingRowText(row, projectHints)}>
                  <Tag color={color}>{v || "—"}</Tag>
                </CopyableCell>
              );
            },
          },
          {
            title: t("findings.rowRule"),
            dataIndex: "rule_id",
            width: 140,
            ellipsis: true,
            render: (_: string, row: Finding) => {
              const text = String(row.category || "") === "cve" ? cveIdLabel(row) : String(row.rule_id || "—");
              return (
                <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                  {text}
                </CopyableCell>
              );
            },
          },
          {
            title: t("findings.rowCategory"),
            dataIndex: "category",
            width: 160,
            render: (v: string, row: Finding) => {
              const label = FINDING_CATEGORY_LABELS[v] || v || "—";
              const scope = v === "cve" ? inferCveScope(row, projectHints) : "";
              const text = scope ? `${label} / ${scopeLabel(scope)}` : label;
              return (
                <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                  {v !== "cve" ? (
                    label
                  ) : (
                    <span>
                      {label}
                      <Tag style={{ marginLeft: 6 }} color={scope === "self" ? "purple" : "default"}>
                        {scopeLabel(scope)}
                      </Tag>
                    </span>
                  )}
                </CopyableCell>
              );
            },
          },
          ...(hasCve
            ? [
                {
                  title: t("findings.rowComponent"),
                  width: 200,
                  ellipsis: true as const,
                  render: (_: unknown, row: Finding) => {
                    const text = String(row.category || "") === "cve" ? componentLabel(row) : "—";
                    return (
                      <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                        {text}
                      </CopyableCell>
                    );
                  },
                },
              ]
            : []),
          {
            title: t("findings.rowFile"),
            width: 220,
            ellipsis: true,
            render: (_: unknown, row: Finding) => {
              const text = findingFile(row);
              return (
                <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                  {text}
                </CopyableCell>
              );
            },
          },
          {
            title: t("findings.rowLine"),
            width: 70,
            render: (_: unknown, row: Finding) => {
              const text = findingLine(row);
              return (
                <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                  {text}
                </CopyableCell>
              );
            },
          },
          {
            title: t("findings.rowDetail"),
            dataIndex: "detail",
            ellipsis: true,
            render: (v: string, row: Finding) => {
              const text = v || String(row.title || "—");
              return (
                <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                  {text}
                </CopyableCell>
              );
            },
          },
          {
            title: t("findings.rowDisposition"),
            dataIndex: "disposition",
            width: 110,
            render: (v: string, row: Finding) => {
              const key = v || "open";
              const text = DISPOSITION_LABELS[key] || key;
              return (
                <CopyableCell field={text} rowText={findingRowText(row, projectHints)}>
                  <Tag color={DISPOSITION_COLORS[key]}>{text}</Tag>
                </CopyableCell>
              );
            },
          },
        ]}
      />

      <Modal
        title={pending?.title || t("findings.batchTitle")}
        open={!!pending}
        confirmLoading={busy}
        onCancel={() => setPending(null)}
        onOk={apply}
        okText={t("common.confirm")}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="reason"
            label={t("findings.reason")}
            rules={needReason ? [{ required: true, message: t("findings.reasonRequired") }] : []}
          >
            <Input.TextArea
              rows={4}
              placeholder={fpHintSelf ? t("findings.reasonSelf") : t("findings.reasonPh")}
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
