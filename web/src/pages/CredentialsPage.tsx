import { Button, Card, Form, Input, Modal, Popconfirm, Radio, Space, Table, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { createCredential, deleteCredential, listCredentials, updateCredential } from "../api/client";
import { useI18n } from "../i18n/LocaleContext";

export default function CredentialsPage() {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [items, setItems] = useState<Record<string, unknown>[]>([]);
  const [total, setTotal] = useState(0);
  const [open, setOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form] = Form.useForm();
  const ctype = Form.useWatch("type", form) as "http_token" | "ssh_key" | undefined;

  const load = async () => {
    setLoading(true);
    try {
      const r = await listCredentials();
      setItems(r.items);
      setTotal(r.total);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submit = async () => {
    try {
      const v = await form.validateFields();
      if (editingId) {
        await updateCredential(editingId, {
          name: v.name,
          http_username: v.http_username,
          http_token: v.http_token,
          ssh_private_key_path: v.ssh_private_key_path,
        });
        message.success(t("credentials.updated"));
      } else {
        await createCredential(v);
        message.success(t("credentials.created"));
      }
      setOpen(false);
      setEditingId(null);
      form.resetFields();
      load();
    } catch (e: unknown) {
      if ((e as { errorFields?: unknown })?.errorFields) return;
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("common.failed"));
    }
  };

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("credentials.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("credentials.hint")}
      </Typography.Paragraph>
      <div className="page-toolbar">
        <Button
          type="primary"
          onClick={() => {
            setOpen(true);
            setEditingId(null);
            form.resetFields();
            form.setFieldsValue({ type: "http_token", http_username: "git" });
          }}
        >
          {t("credentials.create")}
        </Button>
        <Button onClick={load}>{t("common.refresh")}</Button>
      </div>
      <Card className="panel-card">
        <Table
          rowKey="credential_id"
          loading={loading}
          dataSource={items}
          pagination={{ total, pageSize: 100 }}
          columns={[
            { title: t("common.name"), dataIndex: "name" },
            { title: t("common.type"), dataIndex: "type" },
            { title: "ID", dataIndex: "credential_id", ellipsis: true },
            { title: t("common.createdAt"), dataIndex: "created_at" },
            {
              title: t("common.actions"),
              width: 140,
              render: (_: unknown, r: Record<string, unknown>) => (
                <Space>
                  <Button
                    type="link"
                    size="small"
                    onClick={() => {
                      setEditingId(String(r.credential_id));
                      form.resetFields();
                      form.setFieldsValue({
                        name: r.name,
                        type: r.type,
                        http_username: "git",
                      });
                      setOpen(true);
                    }}
                  >
                    {t("credentials.update")}
                  </Button>
                  <Popconfirm
                    title={t("credentials.confirmDelete")}
                    onConfirm={async () => {
                      try {
                        await deleteCredential(String(r.credential_id));
                        message.success(t("credentials.deleted"));
                        load();
                      } catch (e: unknown) {
                        message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("credentials.deleteFail"));
                      }
                    }}
                  >
                    <Button type="link" danger size="small">
                      {t("common.delete")}
                    </Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Modal title={editingId ? t("credentials.edit") : t("credentials.create")} open={open} onCancel={() => { setOpen(false); setEditingId(null); }} onOk={submit} width={560} destroyOnClose>
        <Form form={form} layout="vertical" initialValues={{ type: "http_token", http_username: "git" }}>
          <Form.Item name="name" label={t("common.name")} rules={[{ required: true }]}>
            <Input placeholder={t("credentials.namePh")} />
          </Form.Item>
          <Form.Item name="type" label={t("common.type")} rules={[{ required: true }]}>
            <Radio.Group
              disabled={!!editingId}
              options={[
                { label: t("credentials.httpToken"), value: "http_token" },
                { label: t("credentials.sshPath"), value: "ssh_key" },
              ]}
            />
          </Form.Item>
          {ctype !== "ssh_key" ? (
            <>
              <Form.Item name="http_username" label={t("credentials.userOptional")}>
                <Input placeholder={t("credentials.defaultGit")} />
              </Form.Item>
              <Form.Item name="http_token" label="Token / PAT" rules={[{ required: !editingId }]}>
                <Input.Password placeholder={editingId ? t("credentials.tokenKeep") : t("credentials.tokenHint")} />
              </Form.Item>
            </>
          ) : (
            <Form.Item name="ssh_private_key_path" label={t("credentials.absPath")} rules={[{ required: true }]}>
              <Input placeholder="/home/git/.ssh/id_rsa" />
            </Form.Item>
          )}
        </Form>
      </Modal>
    </div>
  );
}
