import { Button, Card, Col, Form, Input, Row, Select, Space, Tabs, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { createRequest, listCredentials, setGitSource } from "../api/client";
import RollbackPlanField from "../components/RollbackPlanField";
import { encodeRollbackPlan } from "../constants/rollbackPlans";
import { useI18n } from "../i18n/LocaleContext";
import { DEFAULT_REVIEW_ROLES, loadReviewRoleOptions, mergeRequiredReviewRoles, reviewRoleTagRender } from "../utils/reviewRoles";
import RequestBatch from "./RequestBatch";

export default function RequestNew() {
  const { t } = useI18n();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "batch" ? "batch" : "single";
  const [form] = Form.useForm();
  const [reviewRoleOptions, setReviewRoleOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [credOptions, setCredOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        setReviewRoleOptions(await loadReviewRoleOptions());
      } catch {
        setReviewRoleOptions([]);
      }
      try {
        const c = await listCredentials();
        setCredOptions(
          (c.items || []).map((x) => ({
            label: t("requestNew.credNamed", {
              name: String(x.name || x.credential_id),
              type: String(x.type || t("requestNew.credFallback")),
            }),
            value: String(x.credential_id || ""),
          })).filter((x) => x.value),
        );
      } catch {
        setCredOptions([]);
      }
    })();
  }, [t]);

  const onFinish = async (v: Record<string, string>) => {
    setSaving(true);
    try {
      const rollback_plan = encodeRollbackPlan(v.rollback_plan, v.rollback_plan_notes);
      const include = String(v.include_paths || "")
        .split(/[,\n;]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await createRequest({
        project: v.project,
        title: v.title || v.project,
        owner: v.owner,
        environment: v.environment,
        purpose: v.purpose,
        business_criticality: v.business_criticality,
        exposure: v.exposure,
        rollback_plan,
        required_review_roles: mergeRequiredReviewRoles(v.required_review_roles as unknown as string[]),
        scan_scope: {
          mode: include.length ? "include_paths" : "auto",
          include_paths: include,
        },
      });
      const requestId = (res as { request_id: string }).request_id;
      try {
        await setGitSource(requestId, {
          repo_url: v.repo_url,
          ref: v.ref,
          credential_id: v.credential_id || undefined,
        });
      } catch (e: unknown) {
        message.warning(
          (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
            || t("requestNew.gitSaveFail"),
        );
        nav(`/requests/${requestId}`);
        return;
      }
      message.success(t("requestNew.created"));
      nav(`/requests/${requestId}`);
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("requestNew.createFail"));
    } finally {
      setSaving(false);
    }
  };

  const singleForm = (
    <Card className="panel-card">
        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
          initialValues={{
            environment: "dev",
            business_criticality: "low",
            exposure: "internal",
            required_review_roles: DEFAULT_REVIEW_ROLES,
            ref: "main",
          }}
        >
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name="project" label={t("requestNew.project")} rules={[{ required: true }]}>
                <Input placeholder={t("requestNew.projectPh")} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="title" label={t("requestNew.reqTitle")}>
                <Input placeholder={t("requestNew.titlePh")} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="owner" label={t("common.owner")}>
                <Input placeholder={t("requestNew.ownerPh")} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name="repo_url"
                label={t("requestNew.repoUrl")}
                rules={[{ required: true, type: "url", message: t("requestNew.repoUrlRule") }]}
              >
                <Input placeholder="https://github.com/org/repo.git" />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="ref" label={t("requestNew.ref")} rules={[{ required: true }]}>
                <Input placeholder="main" />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="purpose" label={t("requestNew.purpose")} rules={[{ required: true }]}>
                <Input placeholder={t("requestNew.purposePh")} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="exposure" label={t("common.exposure")} rules={[{ required: true }]}>
                <Select
                  options={[
                    { label: t("common.internal"), value: "internal" },
                    { label: t("common.public"), value: "public" },
                  ]}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="business_criticality" label={t("common.criticality")} rules={[{ required: true }]}>
                <Select options={["low", "medium", "high", "critical"].map((x) => ({ label: t(`severity.${x}`), value: x }))} />
              </Form.Item>
            </Col>
            <Col xs={24} md={16}>
              <Form.Item
                name="required_review_roles"
                label={t("requestNew.roles")}
                extra={t("requestNew.rolesHint")}
                rules={[{ required: true, type: "array", min: DEFAULT_REVIEW_ROLES.length }]}
              >
                <Select
                  mode="multiple"
                  options={reviewRoleOptions}
                  placeholder={t("requestNew.rolesExtra")}
                  tagRender={reviewRoleTagRender}
                  onChange={(vals) => form.setFieldValue("required_review_roles", mergeRequiredReviewRoles(vals))}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="environment" label={t("common.environment")} rules={[{ required: true }]}>
                <Select options={["dev", "stage", "prod", "other"].map((x) => ({ label: x, value: x }))} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="credential_id" label={t("requestNew.credId")}>
                {credOptions.length > 0 ? (
                  <Select allowClear options={credOptions} placeholder={t("requestNew.credPh")} />
                ) : (
                  <Input placeholder={t("requestNew.credExtra")} />
                )}
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="include_paths"
            label={t("requestNew.scanScope")}
            extra={t("requestNew.scanScopeExtra")}
          >
            <Input.TextArea rows={2} placeholder={t("requestNew.scanScopePh")} />
          </Form.Item>
          <RollbackPlanField />

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={saving}>
                {t("requestNew.createDraft")}
              </Button>
              <Button onClick={() => nav("/requests")}>{t("common.cancel")}</Button>
            </Space>
          </Form.Item>
        </Form>
    </Card>
  );

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("requestNew.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {tab === "batch" ? t("requestNew.batchSubtitle") : t("requestNew.subtitle")}
      </Typography.Paragraph>
      <Tabs
        activeKey={tab}
        onChange={(key) => setParams(key === "batch" ? { tab: "batch" } : {})}
        items={[
          { key: "single", label: t("requestNew.single"), children: singleForm },
          { key: "batch", label: t("requestNew.batch"), children: <RequestBatch embedded /> },
        ]}
      />
    </div>
  );
}
