import { Button, Card, Col, Form, Input, Popconfirm, Row, Select, Space, Table, Tag, Typography, message } from "antd";
import { DeleteOutlined, EditOutlined } from "@ant-design/icons";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { deleteRequest, getRequest, listRequests } from "../api/client";
import RequestEditModal from "../components/RequestEditModal";
import { GATE_STATUS_LABELS, REQUEST_STATUS_LABELS, ROLE_LABELS, displayGateStatus } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";
import { canDeleteRequest, canEditRequest, canManageRequests } from "../utils/requestActions";

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

const gateColors: Record<string, string> = {
  Pass: "success",
  Fail: "error",
  PendingLegal: "warning",
  Unknown: "default",
};

export default function RequestsList() {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<{ total: number; items: Record<string, unknown>[] }>({ total: 0, items: [] });
  const [form] = Form.useForm();
  const canManage = canManageRequests();
  const [editOpen, setEditOpen] = useState(false);
  const [editing, setEditing] = useState<{
    request: Record<string, unknown>;
    source: Record<string, unknown> | null;
  } | null>(null);
  const statusCount = data.items.reduce<Record<string, number>>((acc, cur) => {
    const s = String(cur.status || "Unknown");
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const load = async (vals?: Record<string, string>) => {
    setLoading(true);
    try {
      const res = await listRequests({
        limit: 50,
        offset: 0,
        status: vals?.status,
        gate_status: vals?.gate_status,
        project: vals?.project,
        created_by: vals?.created_by,
        risk_level: vals?.risk_level,
      });
      setData(res);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("requests.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("requests.subtitle")}
      </Typography.Paragraph>
      <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
        <Col xs={24} md={8}>
          <Card size="small" className="panel-card">
            <Typography.Text type="secondary">{t("requests.total")}</Typography.Text>
            <div className="stat-value">{data.total}</div>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small" className="panel-card">
            <Typography.Text type="secondary">{t("requests.pendingReview")}</Typography.Text>
            <div className="stat-value">{(statusCount.Reviewing || 0) + (statusCount.LegalReviewing || 0)}</div>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small" className="panel-card">
            <Typography.Text type="secondary">{t("requests.approved")}</Typography.Text>
            <div className="stat-value">{statusCount.Approved || 0}</div>
          </Card>
        </Col>
      </Row>
      <Card className="panel-card filter-card">
        <Form
          form={form}
          layout="inline"
          style={{ marginBottom: 0, flexWrap: "wrap", gap: 8 }}
          onFinish={(v) => load(v as Record<string, string>)}
        >
        <Form.Item name="project">
          <Input placeholder={t("requests.projectPh")} allowClear style={{ width: 140 }} />
        </Form.Item>
        <Form.Item name="status">
          <Select
            allowClear
            placeholder={t("requests.statusPh")}
            style={{ width: 160 }}
            options={[
              "Draft",
              "Submitted",
              "Scanning",
              "Reviewing",
              "LegalReviewing",
              "Blocked",
              "Approved",
              "ConditionalApproved",
              "Remediating",
              "ReReview",
              "Rejected",
              "Waived",
            ].map((s) => ({ label: REQUEST_STATUS_LABELS[s] || s, value: s }))}
          />
        </Form.Item>
        <Form.Item name="created_by">
          <Input placeholder={t("requests.createdByPh")} allowClear style={{ width: 120 }} />
        </Form.Item>
        <Form.Item name="risk_level">
          <Select
            allowClear
            placeholder={t("requests.riskPh")}
            style={{ width: 110 }}
            options={["low", "medium", "high"].map((s) => ({ label: s, value: s }))}
          />
        </Form.Item>
        <Form.Item name="gate_status">
          <Select
            allowClear
            placeholder={t("requests.gatePh")}
            style={{ width: 140 }}
            options={["Pass", "Fail", "PendingLegal", "Unknown"].map((s) => ({ label: GATE_STATUS_LABELS[s] || s, value: s }))}
          />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button type="primary" htmlType="submit">
              {t("common.filter")}
            </Button>
            <Button onClick={() => { form.resetFields(); load(); }}>{t("common.reset")}</Button>
            {canManageRequests() && (
              <Link to="/requests/new">
                <Button type="primary">{t("requests.new")}</Button>
              </Link>
            )}
          </Space>
        </Form.Item>
        </Form>
      </Card>

      <Card className="panel-card">
        <Table
          rowKey="request_id"
          loading={loading}
          dataSource={data.items}
          scroll={{ x: "max-content" }}
          pagination={{ total: data.total, pageSize: 50, showTotal: (n) => t("common.totalN", { n }) }}
          columns={[
          {
            title: t("common.title"),
            dataIndex: "title",
            width: 180,
            render: (title: string, row: Record<string, unknown>) => (
              <Link to={`/requests/${String(row.request_id || "")}`}>{title || String(row.project || "")}</Link>
            ),
          },
          { title: t("common.project"), dataIndex: "project", width: 140 },
          { title: t("common.owner"), dataIndex: "owner", width: 100, render: (v: string) => v || "—" },
          { title: t("common.createdBy"), dataIndex: "created_by", width: 100, render: (v: string) => v || "—" },
          { title: t("requests.riskPh"), dataIndex: "risk_level", width: 80, render: (v: string) => v || "—" },
          {
            title: t("requests.reviewRoles"),
            dataIndex: "required_review_roles",
            width: 220,
            render: (roles: string[]) =>
              roles && roles.length ? (
                <Space size={[4, 4]} wrap>
                  {roles.map((r) => (
                    <Tag key={r}>{ROLE_LABELS[r] || r}</Tag>
                  ))}
                </Space>
              ) : (
                <Typography.Text type="secondary">—</Typography.Text>
              ),
          },
          {
            title: t("common.status"),
            dataIndex: "status",
            width: 140,
            render: (s: string) => <Tag color={statusColors[s] || "default"}>{REQUEST_STATUS_LABELS[s] || s}</Tag>,
          },
          {
            title: "Gate",
            dataIndex: "gate_status",
            width: 120,
            render: (_: unknown, row: Record<string, unknown>) => {
              const g = displayGateStatus(row as { effective_gate_status?: string; gate_status?: string });
              return <Tag color={gateColors[g] || "default"}>{GATE_STATUS_LABELS[g] || g}</Tag>;
            },
          },
          { title: t("common.environment"), dataIndex: "environment", width: 90 },
          {
            title: t("common.updatedAt"),
            dataIndex: "updated_at",
            width: 200,
            render: (v: string) => (v ? String(v).replace("T", " ").slice(0, 19) : "—"),
          },
          ...(canManage
            ? [
                {
                  title: t("common.actions"),
                  key: "actions",
                  width: 140,
                  fixed: "right" as const,
                  render: (_: unknown, row: Record<string, unknown>) => {
                    const status = String(row.status || "");
                    const id = String(row.request_id || "");
                    return (
                      <Space size={4}>
                        <Button
                          type="link"
                          size="small"
                          icon={<EditOutlined />}
                          disabled={!canEditRequest(status)}
                          onClick={async () => {
                            try {
                              const bundle = await getRequest(id);
                              setEditing({ request: bundle.request, source: bundle.source });
                              setEditOpen(true);
                            } catch {
                              message.error(t("requests.loadFail"));
                            }
                          }}
                        >
                          {t("common.edit")}
                        </Button>
                        <Popconfirm
                          title={t("requests.deleteTitle")}
                          description={t("requests.deleteDesc")}
                          disabled={!canDeleteRequest(status)}
                          onConfirm={async () => {
                            try {
                              await deleteRequest(id);
                              message.success(t("requests.deleted"));
                              load(form.getFieldsValue() as Record<string, string>);
                            } catch (e: unknown) {
                              message.error(
                                (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("requests.deleteFail"),
                              );
                            }
                          }}
                        >
                          <Button type="link" size="small" danger icon={<DeleteOutlined />} disabled={!canDeleteRequest(status)}>
                            {t("common.delete")}
                          </Button>
                        </Popconfirm>
                      </Space>
                    );
                  },
                },
              ]
            : []),
          ]}
        />
      </Card>
      <RequestEditModal
        open={editOpen}
        request={editing?.request || null}
        source={editing?.source}
        onCancel={() => {
          setEditOpen(false);
          setEditing(null);
        }}
        onSaved={() => {
          setEditOpen(false);
          setEditing(null);
          load(form.getFieldsValue() as Record<string, string>);
        }}
      />
      <Typography.Text type="secondary" className="muted">
        {t("requests.hint")}
      </Typography.Text>
    </div>
  );
}
