import { Alert, Button, Card, Form, Input, Space, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getBootstrapStatus, login, me } from "../api/client";
import { setAuthToken, setAuthUser } from "../auth";
import BrandMark from "../components/BrandMark";
import LanguageSwitcher from "../components/LanguageSwitcher";
import ThemeSwitcher from "../components/ThemeSwitcher";
import { useI18n } from "../i18n/LocaleContext";

export default function LoginPage() {
  const [form] = Form.useForm();
  const nav = useNavigate();
  const { t } = useI18n();
  const [authMode, setAuthMode] = useState<"ldap" | "http">("ldap");

  useEffect(() => {
    (async () => {
      try {
        const s = await getBootstrapStatus();
        setAuthMode(s.auth_mode || "ldap");
      } catch {
        setAuthMode("ldap");
      }
    })();
  }, []);

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
      <Card className="panel-card" style={{ width: 440, maxWidth: "100%" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
          <BrandMark size={56} />
          <Space size={8}>
            <LanguageSwitcher compact />
            <ThemeSwitcher compact />
          </Space>
        </div>
        <Typography.Title level={4} style={{ marginTop: 0 }}>
          {authMode === "http" ? t("login.httpTitle") : t("login.ldapTitle")}
        </Typography.Title>
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={authMode === "http" ? t("login.httpHint") : t("login.ldapHint")}
        />
        <Form
          form={form}
          layout="vertical"
          onFinish={async (v) => {
            try {
              const res = await login({ username: v.username, password: v.password });
              setAuthToken(res.access_token);
              setAuthUser(res.user);
              // Validate the freshly issued token before redirecting to app pages.
              await me();
              message.success(t("login.success"));
              nav("/", { replace: true });
            } catch (e: unknown) {
              message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("login.failed"));
            }
          }}
        >
          <Form.Item name="username" label={t("common.username")} rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="password" label={t("common.password")} rules={[{ required: true }]}>
            <Input.Password />
          </Form.Item>
          <Button type="primary" htmlType="submit" block>
            {t("common.login")}
          </Button>
        </Form>
      </Card>
    </div>
  );
}
