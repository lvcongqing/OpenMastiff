import { Card, Select, Space, Table, Tag, Typography } from "antd";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { reviewInbox } from "../api/client";
import { GATE_STATUS_LABELS, REQUEST_STATUS_LABELS, ROLE_LABELS, displayGateStatus } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";

const statusColors: Record<string, string> = {
  Reviewing: "blue",
  Blocked: "error",
  LegalReviewing: "orange",
};

const gateColors: Record<string, string> = {
  Pass: "success",
  Fail: "error",
  PendingLegal: "warning",
  Unknown: "default",
};

export default function ReviewInbox() {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<{ total: number; items: Record<string, unknown>[] }>({ total: 0, items: [] });
  const [roleFilter, setRoleFilter] = useState<string | undefined>(undefined);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const r = await reviewInbox({ limit: 100 });
        setData(r);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("inbox.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("inbox.subtitlePrefix")} <Typography.Text code>{t("inbox.reviewing")}</Typography.Text>、
        <Typography.Text code>{t("inbox.blocked")}</Typography.Text>、
        <Typography.Text code>{t("inbox.legal")}</Typography.Text> {t("inbox.subtitleSuffix")}
      </Typography.Paragraph>
      <Card size="small" className="panel-card filter-card">
        <Space>
          <Typography.Text type="secondary">{t("inbox.filterRole")}</Typography.Text>
          <Select
            allowClear
            placeholder={t("inbox.allRoles")}
            style={{ width: 220 }}
            value={roleFilter}
            onChange={(v) => setRoleFilter(v)}
            options={Array.from(
              new Set(
                data.items
                  .flatMap((x) => ((x.required_review_roles as string[]) || []).map((r) => String(r)))
                  .filter(Boolean)
              )
            ).map((x) => ({ label: ROLE_LABELS[x] || x, value: x }))}
          />
        </Space>
      </Card>
      <Card className="panel-card">
        <Table
          rowKey="request_id"
          loading={loading}
          dataSource={data.items.filter((x) => !roleFilter || ((x.required_review_roles as string[]) || []).includes(roleFilter))}
          scroll={{ x: "max-content" }}
          pagination={{ total: data.total, pageSize: 100 }}
          columns={[
          {
            title: t("inbox.requestId"),
            dataIndex: "request_id",
            render: (id: string) => <Link to={`/requests/${id}`}>{id}</Link>,
          },
          { title: t("common.project"), dataIndex: "project" },
          {
            title: t("common.status"),
            dataIndex: "status",
            render: (s: string) => <Tag color={statusColors[s] || "default"}>{REQUEST_STATUS_LABELS[s] || s}</Tag>,
          },
          {
            title: t("requests.reviewRoles"),
            dataIndex: "required_review_roles",
            render: (roles: string[]) =>
              roles && roles.length ? (
                <Space size={[4, 4]} wrap>
                  {roles.map((r) => (
                    <Tag key={r}>{ROLE_LABELS[r] || r}</Tag>
                  ))}
                </Space>
              ) : (
                t("common.none")
              ),
          },
          {
            title: t("common.gate"),
            dataIndex: "gate_status",
            render: (_: unknown, row: Record<string, unknown>) => {
              const g = displayGateStatus(row as { effective_gate_status?: string; gate_status?: string });
              return <Tag color={gateColors[g] || "default"}>{GATE_STATUS_LABELS[g] || g}</Tag>;
            },
          },
          {
            title: t("common.updatedAt"),
            dataIndex: "updated_at",
            render: (v: string) => (v ? String(v).replace("T", " ").slice(0, 19) : t("common.none")),
          },
          ]}
        />
      </Card>
    </div>
  );
}
