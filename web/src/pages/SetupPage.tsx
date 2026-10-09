import { Alert, Button, Card, Descriptions, Form, Input, InputNumber, Modal, Select, Space, Steps, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { initBootstrap, validateBootstrap } from "../api/client";
import BrandMark from "../components/BrandMark";
import LanguageSwitcher from "../components/LanguageSwitcher";
import ThemeSwitcher from "../components/ThemeSwitcher";
import { useI18n } from "../i18n/LocaleContext";

export default function SetupPage() {
  const { t } = useI18n();
  const [form] = Form.useForm();
  const nav = useNavigate();
  const [step, setStep] = useState(0);
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<null | {
    ok: boolean;
    ldap: { ok: boolean; detail: string };
    mongo: { ok: boolean; detail: string };
    redis: { ok: boolean; detail: string };
    storage: { ok: boolean; detail: string };
  }>(null);
  const authMode = Form.useWatch("auth_mode", form) as "ldap" | "http" | undefined;
  const stepItems = [{ title: t("setup.stepAuth") }, { title: t("setup.stepInfra") }, { title: t("setup.stepSecurity") }];

  const generateJwtSecret = () => {
    if (typeof window !== "undefined" && window.crypto?.getRandomValues) {
      const bytes = new Uint8Array(48);
      window.crypto.getRandomValues(bytes);
      return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    }
    return `auto-${Date.now()}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
  };

  useEffect(() => {
    const current = form.getFieldValue("jwt_secret");
    if (!current) {
      form.setFieldValue("jwt_secret", generateJwtSecret());
    }
  }, [form]);

  const validateCurrentStep = async () => {
    if (step === 0) {
      const names =
        authMode === "ldap"
          ? [
              "auth_mode",
              "default_role",
              "admin_users",
              "admin_username",
              "ldap_server",
              "ldap_bind_username",
              "ldap_account_base",
              "ldap_account_pattern",
              "ldap_account_ssh_username",
            ]
          : ["auth_mode", "default_role", "admin_users", "admin_username", "admin_password"];
      await form.validateFields(names);
      return;
    }
    if (step === 1) {
      await form.validateFields(["mongo_uri", "redis_url", "blob_root", "work_root", "scanner_mode"]);
      return;
    }
    await form.validateFields(["jwt_secret", "jwt_expire_hours"]);
  };

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
      <Card className="panel-card" style={{ width: 820, maxWidth: "100%" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
          <BrandMark size={52} />
          <Space>
            <LanguageSwitcher compact />
            <ThemeSwitcher compact />
          </Space>
        </div>
        <Typography.Title level={4} style={{ marginTop: 0 }}>
          {t("setup.title")}
        </Typography.Title>
        <Typography.Paragraph className="page-subtitle" style={{ marginBottom: 12 }}>
          {t("setup.subtitle")}
        </Typography.Paragraph>
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={t("setup.first")}
        />
        <Steps items={stepItems} current={step} style={{ marginBottom: 20 }} />
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            auth_mode: "http",
            default_role: "viewer",
            scanner_mode: "local",
            jwt_expire_hours: 8,
            ldap_server: "ldap://ldap.example.com:389",
            ldap_bind_username: "cn=readonly,dc=example,dc=com",
            ldap_account_base: "ou=people,dc=example,dc=com",
            ldap_account_pattern: "(&(objectClass=inetOrgPerson)(uid=${username}))",
            ldap_account_ssh_username: "uid",
            mongo_uri: "mongodb://localhost:27017/supplychain",
            redis_url: "redis://localhost:6379/8",
            blob_root: "/opt/openMastiff/data/blobs",
            work_root: "/opt/openMastiff/data/work",
          }}
          onFinish={async () => {
            try {
              const authModeNow = (form.getFieldValue("auth_mode") as "ldap" | "http" | undefined) || "ldap";
              const requiredNames =
                authModeNow === "ldap"
                  ? [
                      "auth_mode",
                      "admin_username",
                      "default_role",
                      "mongo_uri",
                      "redis_url",
                      "blob_root",
                      "work_root",
                      "scanner_mode",
                      "jwt_expire_hours",
                      "ldap_server",
                      "ldap_bind_username",
                      "ldap_account_base",
                      "ldap_account_pattern",
                      "ldap_account_ssh_username",
                    ]
                  : [
                      "auth_mode",
                      "admin_username",
                      "admin_password",
                      "default_role",
                      "mongo_uri",
                      "redis_url",
                      "blob_root",
                      "work_root",
                      "scanner_mode",
                      "jwt_expire_hours",
                    ];
              await form.validateFields(requiredNames);

              const allValues = form.getFieldsValue(true);
              const payload: Record<string, unknown> = {
                auth_mode: allValues.auth_mode,
                admin_username: allValues.admin_username,
                admin_password: allValues.auth_mode === "http" ? allValues.admin_password : "",
                default_role: allValues.default_role,
                admin_users: (allValues.admin_users || "")
                  .split(",")
                  .map((s: string) => s.trim())
                  .filter(Boolean),
                database: {
                  mongo_uri: allValues.mongo_uri,
                  redis_url: allValues.redis_url,
                },
                storage: {
                  blob_root: allValues.blob_root,
                  work_root: allValues.work_root,
                },
                scanner_mode: allValues.scanner_mode,
                jwt_secret: allValues.jwt_secret,
                jwt_expire_hours: allValues.jwt_expire_hours,
              };
              if (allValues.auth_mode === "ldap") {
                payload.ldap = {
                  server: allValues.ldap_server,
                  bind_username: allValues.ldap_bind_username,
                  bind_password: allValues.ldap_bind_password || "",
                  account_base: allValues.ldap_account_base,
                  account_pattern: allValues.ldap_account_pattern,
                  account_ssh_username: allValues.ldap_account_ssh_username,
                };
              }
              const res = await initBootstrap(payload);
              message.success(t("setup.done"));
              Modal.success({
                title: t("setup.restart"),
                content: (
                  <div>
                    <p>{res.restart_hint || t("setup.restartHint")}</p>
                    <p>{t("setup.restartServices", { list: (res.restart_services || ["api", "worker", "beat"]).join(" / ") })}</p>
                  </div>
                ),
              });
              nav("/login", { replace: true });
            } catch (e: unknown) {
              message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("setup.fail"));
            }
          }}
        >
          {step === 0 && (
            <>
              <Typography.Title level={5}>{t("setup.stepAuth")}</Typography.Title>
              <Form.Item name="auth_mode" label={t("setup.authMode")} rules={[{ required: true }]}>
                <Select options={[{ label: "LDAP", value: "ldap" }, { label: t("setup.httpLocal"), value: "http" }]} />
              </Form.Item>
              <Form.Item name="default_role" label={t("setup.defaultRole")} rules={[{ required: true }]}>
                <Select
                  options={[
                    { label: t("role.admin"), value: "admin" },
                    { label: t("role.legal"), value: "legal" },
                    { label: t("role.project_manager"), value: "project_manager" },
                    { label: t("role.rd_manager"), value: "rd_manager" },
                    { label: t("role.quality_manager"), value: "quality_manager" },
                    { label: t("role.product_manager"), value: "product_manager" },
                    { label: t("role.viewer"), value: "viewer" },
                  ]}
                />
              </Form.Item>
              <Form.Item name="admin_users" label={t("setup.adminList")}>
                <Input placeholder="alice,bob" />
              </Form.Item>
              <Form.Item name="admin_username" label={t("setup.adminUser")} rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              {authMode === "http" && (
                <Form.Item name="admin_password" label={t("setup.adminPass")} rules={[{ required: true }]}>
                  <Input.Password />
                </Form.Item>
              )}

              {authMode === "ldap" && (
                <>
                  <Typography.Title level={5}>{t("setup.ldap")}</Typography.Title>
                  <Form.Item name="ldap_server" label="LDAP Server" rules={[{ required: true }]}>
                    <Input />
                  </Form.Item>
                  <Form.Item name="ldap_bind_username" label="Bind Username" rules={[{ required: true }]}>
                    <Input />
                  </Form.Item>
                  <Form.Item name="ldap_bind_password" label="Bind Password">
                    <Input.Password />
                  </Form.Item>
                  <Form.Item name="ldap_account_base" label="Account Base" rules={[{ required: true }]}>
                    <Input />
                  </Form.Item>
                  <Form.Item name="ldap_account_pattern" label="Account Pattern" rules={[{ required: true }]}>
                    <Input />
                  </Form.Item>
                  <Form.Item name="ldap_account_ssh_username" label="Account Username Attribute" rules={[{ required: true }]}>
                    <Input />
                  </Form.Item>
                </>
              )}
            </>
          )}

          {step === 1 && (
            <>
              <Typography.Title level={5}>{t("setup.db")}</Typography.Title>
              <Form.Item name="mongo_uri" label="Mongo URI" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="redis_url" label="Redis URL" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="blob_root" label="Blob Root" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="work_root" label="Work Root" rules={[{ required: true }]}>
                <Input />
              </Form.Item>
              <Form.Item name="scanner_mode" label="Scanner Mode" rules={[{ required: true }]}>
                <Select options={[{ label: "local", value: "local" }, { label: "docker", value: "docker" }]} />
              </Form.Item>

              <Button
                onClick={async () => {
                  try {
                    await form.validateFields(["mongo_uri", "redis_url", "blob_root", "work_root", "scanner_mode"]);
                    if (authMode === "ldap") {
                      await form.validateFields([
                        "ldap_server",
                        "ldap_bind_username",
                        "ldap_account_base",
                        "ldap_account_pattern",
                        "ldap_account_ssh_username",
                      ]);
                    }
                    const v = form.getFieldsValue(true);
                    const body: Record<string, unknown> = {
                      auth_mode: v.auth_mode,
                      database: { mongo_uri: v.mongo_uri, redis_url: v.redis_url },
                      storage: { blob_root: v.blob_root, work_root: v.work_root },
                    };
                    if (v.auth_mode === "ldap") {
                      body.ldap = {
                        server: v.ldap_server,
                        bind_username: v.ldap_bind_username,
                        bind_password: v.ldap_bind_password || "",
                        account_base: v.ldap_account_base,
                        account_pattern: v.ldap_account_pattern,
                        account_ssh_username: v.ldap_account_ssh_username,
                      };
                    }
                    setValidating(true);
                    const res = await validateBootstrap(body);
                    setValidationResult(res);
                    if (res.ok) message.success(t("setup.validateOk"));
                    else message.warning(t("setup.validatePartial"));
                  } catch (e: unknown) {
                    if ((e as { errorFields?: unknown })?.errorFields) return;
                    message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("setup.validateFail"));
                  } finally {
                    setValidating(false);
                  }
                }}
                loading={validating}
              >
                {t("setup.testConn")}
              </Button>
              {validationResult && (
                <Descriptions
                  bordered
                  size="small"
                  column={1}
                  style={{ marginTop: 12 }}
                  items={[
                    { key: "ldap", label: "LDAP", children: `${validationResult.ldap.ok ? "OK" : "FAIL"} - ${validationResult.ldap.detail}` },
                    { key: "mongo", label: "Mongo", children: `${validationResult.mongo.ok ? "OK" : "FAIL"} - ${validationResult.mongo.detail}` },
                    { key: "redis", label: "Redis", children: `${validationResult.redis.ok ? "OK" : "FAIL"} - ${validationResult.redis.detail}` },
                    { key: "storage", label: "Storage", children: `${validationResult.storage.ok ? "OK" : "FAIL"} - ${validationResult.storage.detail}` },
                  ]}
                />
              )}
            </>
          )}

          {step === 2 && (
            <>
              <Typography.Title level={5}>{t("setup.security")}</Typography.Title>
              <Form.Item name="jwt_secret" label={t("setup.jwt")} rules={[{ min: 8 }]}>
                <Input.Password placeholder={t("setup.jwtHint")} />
              </Form.Item>
              <Button
                onClick={() => {
                  const next = generateJwtSecret();
                  form.setFieldValue("jwt_secret", next);
                  message.success(t("setup.jwtRegen"));
                }}
                style={{ marginBottom: 12 }}
              >
                {t("setup.jwtRegenBtn")}
              </Button>
              <Form.Item name="jwt_expire_hours" label={t("setup.jwtHours")} rules={[{ required: true }]}>
                <InputNumber min={1} max={168} style={{ width: 240 }} />
              </Form.Item>
            </>
          )}

          <Space style={{ width: "100%", display: "flex", justifyContent: "space-between", marginTop: 8 }}>
            <Button disabled={step === 0} onClick={() => setStep((s) => Math.max(0, s - 1))}>
              {t("setup.prev")}
            </Button>
            {step < 2 ? (
              <Button
                type="primary"
                onClick={async () => {
                  try {
                    await validateCurrentStep();
                    setStep((s) => Math.min(2, s + 1));
                  } catch {
                    // form will show validation messages
                  }
                }}
              >
                {t("setup.next")}
              </Button>
            ) : (
              <Button type="primary" htmlType="submit">
                {t("setup.init")}
              </Button>
            )}
          </Space>
        </Form>
      </Card>
    </div>
  );
}
