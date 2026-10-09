import { Alert, Button, Card, Form, Input, Modal, Select, Space, Table, Tag, Typography, Upload, message } from "antd";
import type { FormInstance } from "antd/es/form";
import { useState } from "react";
import {
  apiErrorMessage,
  createLegalReview,
  decideLegalReview,
  decideRequest,
  uploadLegalAttachment,
} from "../api/client";
import { ROLE_LABELS } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";
import {
  LegalReviewItem,
  RoleReviewEntry,
  isRoleReviewDone,
  mergeRoleReviews,
  roleReviewStatusColor,
  roleReviewStatusLabel,
} from "../utils/roleReviews";

function defaultWaiverExpiry(): string {
  const d = new Date();
  d.setDate(d.getDate() + 90);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function WaiverFields({ form }: { form: FormInstance }) {
  const { t } = useI18n();
  const decision = Form.useWatch("decision", form);
  const required = decision === "Waived";
  return (
    <div style={{ display: required ? "block" : "none" }}>
      <Form.Item
        name="risk_acceptor"
        label={t("review.riskAcceptor")}
        rules={[{ required, message: t("review.riskRequired") }]}
      >
        <Input placeholder={t("review.riskPh")} />
      </Form.Item>
      <Form.Item
        name="compensating_controls"
        label={t("review.controls")}
        rules={[{ required, message: t("review.controlsRequired") }]}
      >
        <Input.TextArea rows={3} placeholder={t("review.controlsPh")} />
      </Form.Item>
      <Form.Item name="expires_at" label={t("review.expires")} rules={[{ required, message: t("review.expiresRequired") }]}>
        <Input type="datetime-local" />
      </Form.Item>
    </div>
  );
}

type Props = {
  requestId: string;
  gateStatus: string;
  requiredRoles: string[];
  roleReviews: Record<string, RoleReviewEntry>;
  legalItems: LegalReviewItem[];
  myReviewRoles: string[];
  onRefresh: () => void;
  onOpenFindings?: () => void;
};

export default function ReviewTab({
  requestId,
  gateStatus,
  requiredRoles,
  roleReviews,
  legalItems,
  myReviewRoles,
  onRefresh,
  onOpenFindings,
}: Props) {
  const { t } = useI18n();
  const merged = mergeRoleReviews(requiredRoles, roleReviews, legalItems, gateStatus);
  const needsLegalGate = gateStatus === "PendingLegal";
  const showLegalWorkflow = needsLegalGate || requiredRoles.includes("legal");

  const [decisionOpen, setDecisionOpen] = useState(false);
  const [legalModal, setLegalModal] = useState<{ id: string } | null>(null);
  const [dForm] = Form.useForm();
  const [lForm] = Form.useForm();

  const pendingLegal = legalItems.find((x) => x.status === "Pending");
  const rolesForTable = [...new Set([...requiredRoles, ...(needsLegalGate || merged.legal ? ["legal"] : [])])];

  return (
    <Card className="panel-card">
      <Typography.Paragraph type="secondary">
        {t("review.pageHint")}
      </Typography.Paragraph>

      <Space style={{ marginBottom: 12 }} wrap>
        {gateStatus === "Fail" && onOpenFindings && (
          <Button type="primary" ghost onClick={onOpenFindings}>
            {t("review.batchFp")}
          </Button>
        )}
        <Button
          type="primary"
          disabled={requiredRoles.length === 0 && !showLegalWorkflow}
          onClick={() => {
            dForm.resetFields();
            if (myReviewRoles.length > 0) dForm.setFieldValue("review_role", myReviewRoles[0]);
            setDecisionOpen(true);
          }}
        >
          {t("review.enter")}
        </Button>
        {showLegalWorkflow && !pendingLegal && (
          <Button
            onClick={async () => {
              try {
                await createLegalReview(requestId);
                message.success(t("review.legalStarted"));
                onRefresh();
              } catch (e: unknown) {
                message.error(apiErrorMessage(e));
              }
            }}
          >
            {t("review.startLegal")}
          </Button>
        )}
      </Space>

      <Table
        size="small"
        pagination={false}
        rowKey="role"
        dataSource={rolesForTable.map((r) => ({ role: r, ...(merged[r] || {}) }))}
        columns={[
          { title: t("review.role"), dataIndex: "role", width: 120, render: (r: string) => ROLE_LABELS[r] || r },
          {
            title: t("common.status"),
            render: (_: unknown, row: RoleReviewEntry & { role: string }) => (
              <Tag color={roleReviewStatusColor(row)}>{roleReviewStatusLabel(row)}</Tag>
            ),
          },
          { title: t("review.decision"), dataIndex: "decision", width: 100, render: (v: string) => v || t("common.none") },
          { title: t("review.comment"), dataIndex: "comment", ellipsis: true, render: (v: string) => v || t("common.none") },
          { title: t("review.reviewer"), dataIndex: "updated_by", width: 100, render: (v: string) => v || t("common.none") },
          {
            title: t("common.actions"),
            width: 100,
            render: (_: unknown, row: RoleReviewEntry & { role: string }) => {
              if (isRoleReviewDone(row)) return t("common.none");
              if (!myReviewRoles.includes(row.role)) return t("common.none");
              return (
                <Button
                  type="link"
                  size="small"
                  onClick={() => {
                    dForm.resetFields();
                    dForm.setFieldsValue({ review_role: row.role });
                    setDecisionOpen(true);
                  }}
                >
                  {t("review.decide")}
                </Button>
              );
            },
          },
        ]}
      />

      {showLegalWorkflow && (
        <>
          <Typography.Title level={5} style={{ marginTop: 20 }}>
            {t("review.legalSection")}
          </Typography.Title>
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            message={t("review.legalHint")}
          />
          {legalItems.length === 0 ? (
            <Typography.Text type="secondary">{t("review.notStarted")}</Typography.Text>
          ) : (
            <Table
              size="small"
              rowKey={(r) => String(r.legal_review_id || r.updated_at || r.created_at)}
              pagination={false}
              dataSource={legalItems}
              columns={[
                { title: t("common.status"), dataIndex: "status", width: 90 },
                { title: t("review.decision"), dataIndex: "decision", width: 90 },
                { title: t("review.rationale"), dataIndex: "rationale", ellipsis: true },
                { title: t("review.decidedBy"), dataIndex: "decided_by", width: 100, render: (v) => v || t("common.none") },
                {
                  title: t("common.actions"),
                  width: 80,
                  render: (_: unknown, row: LegalReviewItem & { legal_review_id?: string }) =>
                    row.status === "Pending" ? (
                      <Button
                        type="link"
                        size="small"
                        onClick={() => {
                          setLegalModal({ id: String(row.legal_review_id) });
                          lForm.resetFields();
                        }}
                      >
                        {t("review.decide")}
                      </Button>
                    ) : (
                      t("common.none")
                    ),
                },
              ]}
            />
          )}
        </>
      )}

      <Modal
        title={t("review.conclusions")}
        open={decisionOpen}
        onCancel={() => setDecisionOpen(false)}
        width={560}
        onOk={async () => {
          try {
            const v = await dForm.validateFields();
            await decideRequest(requestId, {
              decision: v.decision,
              comment: v.comment,
              review_role: v.review_role,
              risk_acceptor: v.risk_acceptor,
              compensating_controls: v.compensating_controls,
              expires_at: v.expires_at ? new Date(v.expires_at).toISOString() : undefined,
            });
            message.success(t("review.saved"));
            setDecisionOpen(false);
            onRefresh();
          } catch (e: unknown) {
            if ((e as { errorFields?: unknown })?.errorFields) return;
            message.error(apiErrorMessage(e));
          }
        }}
      >
        <Form form={dForm} layout="vertical">
          {requiredRoles.length > 0 && (
            <Form.Item name="review_role" label={t("review.reviewRole")} rules={[{ required: true }]}>
              <Select
                options={requiredRoles.map((r) => ({
                  label: `${ROLE_LABELS[r] || r}${myReviewRoles.includes(r) ? "" : t("review.noPerm")}`,
                  value: r,
                  disabled: !myReviewRoles.includes(r),
                }))}
              />
            </Form.Item>
          )}
          {gateStatus === "Fail" && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              message={t("review.gateHint")}
              action={
                onOpenFindings ? (
                  <Button size="small" onClick={() => { setDecisionOpen(false); onOpenFindings(); }}>
                    {t("review.openFindings")}
                  </Button>
                ) : null
              }
            />
          )}
          <Form.Item name="decision" label={t("review.decision")} rules={[{ required: true }]}>
            <Select
              options={[
                { label: t("review.pass"), value: "Approved", disabled: gateStatus === "Fail" },
                { label: t("review.reject"), value: "Rejected" },
                { label: t("review.conditional"), value: "ConditionalApproved", disabled: gateStatus === "Fail" },
                { label: t("review.waive"), value: "Waived" },
              ]}
              onChange={(val) => {
                if (val === "Waived" && !dForm.getFieldValue("expires_at")) {
                  dForm.setFieldValue("expires_at", defaultWaiverExpiry());
                }
              }}
            />
          </Form.Item>
          <Form.Item name="comment" label={t("review.comment")} extra={t("review.commentHint")}>
            <Input.TextArea rows={3} />
          </Form.Item>
          <WaiverFields form={dForm} />
        </Form>
      </Modal>

      <Modal
        title={t("review.legalTitle")}
        open={!!legalModal}
        onCancel={() => setLegalModal(null)}
        onOk={async () => {
          try {
            const v = await lForm.validateFields();
            const file = v.attachment?.fileList?.[0]?.originFileObj as File | undefined;
            if (file) {
              await uploadLegalAttachment(legalModal!.id, file);
            }
            await decideLegalReview(legalModal!.id, { decision: v.decision, rationale: v.rationale });
            message.success(t("review.submitted"));
            setLegalModal(null);
            onRefresh();
          } catch (e: unknown) {
            if ((e as { errorFields?: unknown })?.errorFields) return;
            message.error(apiErrorMessage(e));
          }
        }}
      >
        <Form form={lForm} layout="vertical">
          <Form.Item name="decision" label={t("review.decision")} rules={[{ required: true }]}>
            <Select options={[{ label: t("review.allow"), value: "Allowed" }, { label: t("review.deny"), value: "Denied" }]} />
          </Form.Item>
          <Form.Item name="rationale" label={t("review.rationale")} rules={[{ required: true }]}>
            <Input.TextArea rows={4} />
          </Form.Item>
          <Form.Item name="attachment" label={t("review.attachment")}>
            <Upload maxCount={1} beforeUpload={() => false}>
              <Button>{t("review.pickFile")}</Button>
            </Upload>
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}
