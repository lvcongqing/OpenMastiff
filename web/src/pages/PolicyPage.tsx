import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  InputNumber,
  Row,
  Select,
  Switch,
  Typography,
  message,
} from "antd";
import { useEffect, useState } from "react";
import { getPolicy, putPolicy } from "../api/client";
import { useI18n } from "../i18n/LocaleContext";

const LICENSE_OPTIONS = [
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MPL-2.0",
  "LGPL-2.1",
  "LGPL-3.0",
  "GPL-2.0",
  "GPL-3.0",
  "AGPL-3.0",
  "SSPL-1.0",
  "Commons-Clause",
  "BUSL-1.1",
  "Elastic-2.0",
  "Unlicense",
  "CC0-1.0",
  "Proprietary",
  "UNKNOWN",
].map((x) => ({ label: x, value: x }));

const UNKNOWN_LICENSE_OPTIONS = [
  { labelKey: "policy.legalReview", value: "legal_review" },
  { labelKey: "policy.pass", value: "pass" },
  { labelKey: "policy.fail", value: "fail" },
];

const GATE_OPTIONS = [
  { labelKey: "policy.pass", value: "pass" },
  { labelKey: "policy.fail", value: "fail" },
];

const NETWORK_OPTIONS = [
  { labelKey: "policy.netNone", value: "none" },
  { labelKey: "policy.netBridge", value: "bridge" },
  { labelKey: "policy.netHost", value: "host" },
];

const CVE_ENGINE_OPTIONS = [
  { labelKey: "policy.engineGrype", value: "grype" },
  { labelKey: "policy.engineTrivy", value: "trivy" },
  { labelKey: "policy.engineOsv", value: "osv-scanner" },
];

const DEFAULT_EXCLUDE_DIRS = [
  "vendor",
  "third_party",
  "3rdparty",
  "external",
  ".git",
  "node_modules",
  "build",
  "dist",
  "out",
  "bin",
  "obj",
  ".idea",
  ".vscode",
  ".cache",
  ".github",
];

const CRITICALITY_LABELS: Record<string, string> = {
  critical: "policy.critCritical",
  high: "policy.critHigh",
  medium: "policy.critMedium",
  low: "policy.critLow",
};

function asObj(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function mergePolicy(base: Record<string, unknown>, form: Record<string, unknown>): Record<string, unknown> {
  const next = { ...base, ...form };
  for (const key of ["license", "gosec", "cppcheck", "bandit", "pmd", "cargo_audit", "eslint", "cve", "waiver", "maintenance", "runner"]) {
    next[key] = { ...asObj(base[key]), ...asObj(form[key]) };
  }
  const baseMaint = asObj(base.maintenance);
  const formMaint = asObj(form.maintenance);
  const weights = { ...asObj(baseMaint.score_weights), ...asObj(formMaint.score_weights) };
  const dep = { ...asObj(baseMaint.dependency_thresholds), ...asObj(formMaint.dependency_thresholds) };
  const baseRules = asObj(baseMaint.rules_by_criticality);
  const formRules = asObj(formMaint.rules_by_criticality);
  const rules: Record<string, unknown> = { ...baseRules };
  for (const level of ["critical", "high", "medium", "low"]) {
    rules[level] = { ...asObj(baseRules[level]), ...asObj(formRules[level]) };
  }
  const runner = asObj(next.runner);
  next.maintenance = {
    ...asObj(next.maintenance),
    score_weights: weights,
    dependency_thresholds: dep,
    rules_by_criticality: rules,
  };
  next.runner = {
    ...runner,
    timeouts_min: { ...asObj(asObj(base.runner).timeouts_min), ...asObj(runner.timeouts_min) },
  };
  return next;
}

function CritRules({ level }: { level: string }) {
  const { t } = useI18n();
  return (
    <Card size="small" className="panel-card" title={t(CRITICALITY_LABELS[level] || level)} style={{ marginBottom: 12 }}>
      <Row gutter={16}>
        {level === "low" && (
          <Col xs={24} md={8}>
            <Form.Item
              name={["maintenance", "rules_by_criticality", level, "advisory_only"]}
              label={t("policy.advisoryOnly")}
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          </Col>
        )}
        <Col xs={24} md={8}>
          <Form.Item
            name={["maintenance", "rules_by_criticality", level, "fail_if_archived"]}
            label={t("policy.failIfArchived")}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Col>
        <Col xs={24} md={8}>
          <Form.Item name={["maintenance", "rules_by_criticality", level, "unknown_gate"]} label={t("policy.unknownMeta")}>
            <Select options={GATE_OPTIONS.map((x) => ({ value: x.value, label: t(x.labelKey) }))} />
          </Form.Item>
        </Col>
        <Col xs={24} md={8}>
          <Form.Item
            name={["maintenance", "rules_by_criticality", level, "fail_if_last_commit_days_gt"]}
            label={t("policy.staleCommit")}
          >
            <InputNumber min={1} max={3650} style={{ width: "100%" }} />
          </Form.Item>
        </Col>
        <Col xs={24} md={8}>
          <Form.Item
            name={["maintenance", "rules_by_criticality", level, "fail_if_last_release_days_gt"]}
            label={t("policy.staleRelease")}
          >
            <InputNumber min={1} max={3650} style={{ width: "100%" }} />
          </Form.Item>
        </Col>
        <Col xs={24} md={8}>
          <Form.Item name={["maintenance", "rules_by_criticality", level, "fail_if_score_lt"]} label={t("policy.minScore")}>
            <InputNumber min={0} max={100} style={{ width: "100%" }} />
          </Form.Item>
        </Col>
      </Row>
    </Card>
  );
}

export default function PolicyPage() {
  const { t } = useI18n();
  const [form] = Form.useForm();
  const [sha, setSha] = useState("");
  const [baseRaw, setBaseRaw] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const p = await getPolicy();
      setSha(p.sha256);
      setBaseRaw(p.raw || {});
      form.setFieldsValue(p.raw || {});
    } catch {
      message.error(t("policy.loadFail"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    const values = await form.validateFields();
    const raw = mergePolicy(baseRaw, values as Record<string, unknown>);
    setLoading(true);
    try {
      const p = await putPolicy(raw);
      setSha(p.sha256);
      setBaseRaw(p.raw || raw);
      form.setFieldsValue(p.raw || raw);
      message.success(t("policy.saved"));
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("policy.saveFail"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("policy.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("policy.subtitle")}
      </Typography.Paragraph>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 4 }}
        message={t("policy.hint")}
      />
      <Typography.Text type="secondary">{t("policy.sha", { sha: sha || "—" })}</Typography.Text>

      <Form form={form} layout="vertical" className="policy-form" disabled={loading}>
        <Card className="panel-card" title={t("policy.license")} style={{ marginTop: 8 }}>
          <Row gutter={16}>
            <Col xs={24} lg={12}>
              <Form.Item name={["license", "deny_list"]} label={t("policy.denyList")}>
                <Select mode="tags" allowClear options={LICENSE_OPTIONS} placeholder={t("policy.spdxPh")} />
              </Form.Item>
            </Col>
            <Col xs={24} lg={12}>
              <Form.Item name={["license", "legal_review_list"]} label={t("policy.legalList")}>
                <Select mode="tags" allowClear options={LICENSE_OPTIONS} placeholder={t("policy.spdxPh")} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12} xl={8}>
              <Form.Item name={["license", "unknown_policy"]} label={t("policy.unknownPolicy")}>
                <Select options={UNKNOWN_LICENSE_OPTIONS.map((x) => ({ value: x.value, label: t(x.labelKey) }))} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12} xl={8}>
              <Form.Item name={["license", "score_threshold"]} label={t("policy.confidence")}>
                <InputNumber min={0} max={100} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Card>

        <Card className="panel-card" title={t("policy.security")} style={{ marginTop: 12 }}>
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name={["gosec", "enabled"]} label={t("policy.enableGosec")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["gosec", "block_if_high_gt"]} label={t("policy.gosecHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cppcheck", "block_if_error_gt"]} label={t("policy.cppcheckErr")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["bandit", "enabled"]} label={t("policy.enableBandit")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["bandit", "block_if_high_gt"]} label={t("policy.banditHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["pmd", "enabled"]} label={t("policy.enablePmd")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["pmd", "block_if_high_gt"]} label={t("policy.pmdHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cargo_audit", "enabled"]} label={t("policy.enableCargo")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cargo_audit", "block_if_high_gt"]} label={t("policy.cargoHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["eslint", "enabled"]} label={t("policy.enableEslint")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["eslint", "block_if_high_gt"]} label={t("policy.eslintHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Card>

        <Card className="panel-card" title={t("policy.cve")} style={{ marginTop: 12 }}>
          <Typography.Paragraph type="secondary" style={{ marginTop: 0 }}>
            {t("policy.cveIntro")}
          </Typography.Paragraph>
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name={["cve", "enabled"]} label={t("policy.enableCve")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={16}>
              <Form.Item
                name={["cve", "engines"]}
                label={t("policy.engines")}
                extra={t("policy.enginesHint")}
              >
                <Select mode="multiple" allowClear options={CVE_ENGINE_OPTIONS.map((x) => ({ value: x.value, label: t(x.labelKey) }))} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cve", "block_if_critical_gt"]} label={t("policy.depCrit")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cve", "block_if_high_gt"]} label={t("policy.depHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["cve", "ignore_unfixed"]}
                label={t("policy.noFixSkip")}
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["cve", "fail_if_engine_missing"]}
                label={t("policy.engineMissingFail")}
                extra={t("policy.engineMissingHint")}
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["cve", "repo_advisory", "enabled"]}
                label={t("policy.repoAdvisory")}
                extra={t("policy.repoAdvisoryHint")}
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cve", "self", "block_if_critical_gt"]} label={t("policy.selfCrit")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["cve", "self", "block_if_high_gt"]} label={t("policy.selfHigh")}>
                <InputNumber min={0} max={999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["cve", "self", "allow_accepted_risk"]}
                label={t("policy.allowSelfRisk")}
                extra={t("policy.allowSelfRiskHint")}
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["runner", "timeouts_min", "cve"]} label={t("policy.cveTimeout")}>
                <InputNumber min={1} max={180} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Card>

        <Card className="panel-card" title={t("policy.maintenance")} style={{ marginTop: 12 }}>
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "enabled"]} label={t("policy.enableMaint")} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["maintenance", "fetch_remote_metadata"]}
                label={t("policy.fetchRemote")}
                extra={t("policy.fetchRemoteHint")}
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "cache_ttl_hours"]} label={t("policy.cacheHours")}>
                <InputNumber min={1} max={720} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "max_dependencies"]} label={t("policy.maxDeps")}>
                <InputNumber min={1} max={200} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "score_weights", "release"]} label={t("policy.wRelease")}>
                <InputNumber min={0} max={1} step={0.05} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "score_weights", "commit"]} label={t("policy.wCommit")}>
                <InputNumber min={0} max={1} step={0.05} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "score_weights", "maintainer"]} label={t("policy.wMaintainer")}>
                <InputNumber min={0} max={1} step={0.05} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "score_weights", "community"]} label={t("policy.wCommunity")}>
                <InputNumber min={0} max={1} step={0.05} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "score_weights", "security"]} label={t("policy.wSecurity")}>
                <InputNumber min={0} max={1} step={0.05} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["maintenance", "dependency_thresholds", "fail_if_score_lt"]} label={t("policy.depScore")}>
                <InputNumber min={0} max={100} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["maintenance", "dependency_thresholds", "fail_if_last_release_days_gt"]}
                label={t("policy.depReleaseDays")}
              >
                <InputNumber min={1} max={3650} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
          <Typography.Text strong>{t("policy.critRules")}</Typography.Text>
          <div style={{ marginTop: 12 }}>
            {["critical", "high", "medium", "low"].map((level) => (
              <CritRules key={level} level={level} />
            ))}
          </div>
        </Card>

        <Card className="panel-card" title={t("policy.runner")} style={{ marginTop: 12 }}>
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name={["runner", "network_mode_default"]} label={t("policy.netMode")}>
                <Select options={NETWORK_OPTIONS.map((x) => ({ value: x.value, label: t(x.labelKey) }))} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name={["runner", "max_concurrent_scans"]}
                label={t("policy.concurrency")}
                extra={t("policy.concurrencyHint")}
              >
                <InputNumber min={1} max={64} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["runner", "timeouts_min", "license"]} label={t("policy.licenseTimeout")}>
                <InputNumber min={1} max={180} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["runner", "timeouts_min", "gosec"]} label={t("policy.gosecTimeout")}>
                <InputNumber min={1} max={180} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["runner", "timeouts_min", "cppcheck"]} label={t("policy.cppTimeout")}>
                <InputNumber min={1} max={180} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name={["waiver", "max_days"]} label={t("policy.waiverDays")}>
                <InputNumber min={1} max={365} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24}>
              <Form.Item
                name={["runner", "exclude_dirs"]}
                label={t("policy.excludeDirs")}
                extra={t("policy.excludeHint")}
              >
                <Select
                  mode="tags"
                  allowClear
                  options={DEFAULT_EXCLUDE_DIRS.map((x) => ({ label: x, value: x }))}
                  placeholder={t("policy.excludePh")}
                />
              </Form.Item>
            </Col>
          </Row>
        </Card>
      </Form>

      <div className="page-toolbar">
        <Button type="primary" onClick={save} loading={loading}>
          {t("policy.save")}
        </Button>
        <Button onClick={load} disabled={loading}>
          {t("policy.reload")}
        </Button>
      </div>
    </div>
  );
}
