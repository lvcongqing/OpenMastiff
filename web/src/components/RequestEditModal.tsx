import { Col, Form, Input, Modal, Row, Select, message } from "antd";
import { useEffect, useState } from "react";
import { listCredentials, patchRequest, setGitSource } from "../api/client";
import { ROLE_LABELS } from "../constants/display";
import { decodeRollbackPlan, encodeRollbackPlan } from "../constants/rollbackPlans";
import { useI18n } from "../i18n/LocaleContext";
import { canEditRequestRoles, canEditRequestSource } from "../utils/requestActions";
import { DEFAULT_REVIEW_ROLES, loadReviewRoleOptions, mergeRequiredReviewRoles, reviewRoleTagRender } from "../utils/reviewRoles";
import RollbackPlanField from "./RollbackPlanField";

type Props = {
  open: boolean;
  request: Record<string, unknown> | null;
  source?: Record<string, unknown> | null;
  onCancel: () => void;
  onSaved: () => void;
};

export default function RequestEditModal({ open, request, source, onCancel, onSaved }: Props) {
  const { t } = useI18n();
  const [form] = Form.useForm();
  const [saving, setSaving] = useState(false);
  const [reviewRoleOptions, setReviewRoleOptions] = useState<Array<{ label: string; value: string }>>([]);
  const [credOptions, setCredOptions] = useState<Array<{ label: string; value: string }>>([]);
  const status = String(request?.status || "");
  const sourceEditable = canEditRequestSource(status);
  const rolesEditable = canEditRequestRoles(status);
  const git = ((source?.git || {}) as Record<string, unknown>) || {};

  useEffect(() => {
    if (!open) return;
    (async () => {
      try {
        setReviewRoleOptions(await loadReviewRoleOptions());
      } catch {
        const existing = ((request?.required_review_roles as string[]) || []).map((role) => ({
          label: ROLE_LABELS[role] || role,
          value: role,
        }));
        setReviewRoleOptions(existing);
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
  }, [open, t]);

  useEffect(() => {
    if (!open || !request) return;
    const decoded = decodeRollbackPlan(String(request.rollback_plan || ""));
    const scope = (request.scan_scope || {}) as { include_paths?: string[] };
    form.setFieldsValue({
      project: request.project,
      title: request.title,
      owner: request.owner,
      purpose: request.purpose,
      environment: request.environment,
      exposure: request.exposure,
      business_criticality: request.business_criticality,
      required_review_roles: mergeRequiredReviewRoles((request.required_review_roles as string[]) || []),
      include_paths: Array.isArray(scope.include_paths) ? scope.include_paths.join("\n") : "",
      rollback_plan: decoded.key,
      rollback_plan_notes: decoded.notes,
      repo_url: git.repo_url,
      ref: git.ref || "main",
      credential_id: git.credential_id,
    });
  }, [open, request, form, git.repo_url, git.ref, git.credential_id]);

  const submit = async () => {
    if (!request?.request_id) return;
    const v = await form.validateFields();
    setSaving(true);
    try {
      const include = String(v.include_paths || "")
        .split(/[,\n;]/)
        .map((s: string) => s.trim())
        .filter(Boolean);
      const body: Record<string, unknown> = {
        project: v.project,
        title: v.title || v.project,
        owner: v.owner,
        purpose: v.purpose,
        environment: v.environment,
        exposure: v.exposure,
        business_criticality: v.business_criticality,
        rollback_plan: encodeRollbackPlan(String(v.rollback_plan || ""), v.rollback_plan_notes),
      };
      if (rolesEditable) {
        body.required_review_roles = mergeRequiredReviewRoles(v.required_review_roles);
      }
      if (sourceEditable) {
        body.scan_scope = {
          mode: include.length ? "include_paths" : "auto",
          include_paths: include,
        };
      }
      await patchRequest(String(request.request_id), body);
      if (sourceEditable && v.repo_url) {
        await setGitSource(String(request.request_id), {
          repo_url: v.repo_url,
          ref: v.ref || "main",
          credential_id: v.credential_id || undefined,
        });
      }
      message.success(t("edit.saved"));
      onSaved();
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("edit.saveFail"));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={t("edit.title")}
      open={open}
      onCancel={onCancel}
      onOk={submit}
      confirmLoading={saving}
      width={760}
      destroyOnClose
    >
      <Form form={form} layout="vertical">
        <Row gutter={16}>
          <Col xs={24} md={12}>
            <Form.Item name="project" label={t("edit.project")} rules={[{ required: true }]}>
              <Input />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="title" label={t("edit.reqTitle")}>
              <Input />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="owner" label={t("common.owner")}>
              <Input />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="purpose" label={t("edit.purpose")} rules={[{ required: true }]}>
              <Input />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item name="environment" label={t("common.environment")} rules={[{ required: true }]}>
              <Select options={["dev", "stage", "prod", "other"].map((x) => ({ label: x, value: x }))} />
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
              <Select options={["low", "medium", "high", "critical"].map((x) => ({ label: x, value: x }))} />
            </Form.Item>
          </Col>
          {rolesEditable && (
            <Col xs={24} md={12}>
              <Form.Item
                name="required_review_roles"
                label={t("edit.roles")}
                extra={t("edit.rolesHint")}
                rules={[{ required: true, type: "array", min: DEFAULT_REVIEW_ROLES.length }]}
              >
                <Select
                  mode="multiple"
                  options={reviewRoleOptions}
                  tagRender={reviewRoleTagRender}
                  onChange={(vals) => form.setFieldValue("required_review_roles", mergeRequiredReviewRoles(vals))}
                />
              </Form.Item>
            </Col>
          )}
          <Col xs={24} md={12}>
            <Form.Item
              name="repo_url"
              label={t("edit.repoUrl")}
              extra={sourceEditable ? t("edit.repoHint") : t("edit.approvedLock")}
              rules={[{ type: "url", message: t("edit.repoRule") }]}
            >
              <Input placeholder="https://github.com/org/repo.git" disabled={!sourceEditable} />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="ref" label={t("edit.ref")}>
              <Input placeholder="main" disabled={!sourceEditable} />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="credential_id" label={t("edit.credOptional")}>
              {credOptions.length > 0 ? (
                <Select allowClear options={credOptions} placeholder={t("edit.credPh")} disabled={!sourceEditable} />
              ) : (
                <Input placeholder={t("edit.credExtra")} disabled={!sourceEditable} />
              )}
            </Form.Item>
          </Col>
          <Col span={24}>
            <Form.Item name="include_paths" label={t("edit.scanScope")}>
              <Input.TextArea rows={2} placeholder={t("edit.scanEmpty")} disabled={!sourceEditable} />
            </Form.Item>
          </Col>
        </Row>
        <RollbackPlanField />
      </Form>
    </Modal>
  );
}
