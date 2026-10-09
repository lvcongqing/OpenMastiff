import { Card, Col, Row, Statistic, Typography } from "antd";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { listRequests, reviewInbox } from "../api/client";
import { useI18n } from "../i18n/LocaleContext";
import { canManageRequests } from "../utils/requestActions";

export default function Dashboard() {
  const nav = useNavigate();
  const { t } = useI18n();
  const [total, setTotal] = useState<number | null>(null);
  const [inbox, setInbox] = useState<number | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [r, i] = await Promise.all([listRequests({ limit: 1 }), reviewInbox({ limit: 1 })]);
        setTotal(r.total);
        setInbox(i.total);
      } catch {
        setTotal(null);
        setInbox(null);
      }
    })();
  }, []);

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("dashboard.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("dashboard.subtitle", { port: "18000" })}
      </Typography.Paragraph>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={8}>
          <Card className="panel-card" hoverable onClick={() => nav("/requests")}>
            <Statistic title={t("dashboard.requestTotal")} value={total ?? "—"} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={8}>
          <Card className="panel-card" hoverable onClick={() => nav("/review/inbox")}>
            <Statistic title={t("dashboard.inbox")} value={inbox ?? "—"} />
          </Card>
        </Col>
        {canManageRequests() && (
          <Col xs={24} sm={12} lg={8}>
            <Card className="panel-card" hoverable onClick={() => nav("/requests/new")}>
              <Statistic title={t("dashboard.shortcut")} value={t("dashboard.newRequest")} valueStyle={{ fontSize: 18 }} />
            </Card>
          </Col>
        )}
      </Row>
    </div>
  );
}
