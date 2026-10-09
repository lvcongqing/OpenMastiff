import { Button, Card, Checkbox, Form, Input, Modal, Space, Table, Tag, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { addUserToRole, createRole, listRoles, removeUserFromRole } from "../api/client";
import { ROLE_LABELS } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";

type RoleItem = { role: string; name_zh: string; permissions: string[]; users: string[] };

const roleColor: Record<string, string> = {
  admin: "red",
  legal: "orange",
  project_manager: "blue",
  rd_manager: "cyan",
  quality_manager: "purple",
  product_manager: "geekblue",
  viewer: "default",
};

export default function RolesPage() {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [items, setItems] = useState<RoleItem[]>([]);
  const [availablePermissions, setAvailablePermissions] = useState<string[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [addUserRole, setAddUserRole] = useState("");
  const [createForm] = Form.useForm();
  const [addUserForm] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      const r = await listRoles();
      setItems(r.items || []);
      setAvailablePermissions(r.available_permissions || []);
    } catch (e: unknown) {
      message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("rolesPage.loadFail"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="page-shell">
      <h1 className="page-title">{t("rolesPage.title")}</h1>
      <Typography.Paragraph type="secondary" className="page-subtitle">
        {t("rolesPage.subtitle")}
      </Typography.Paragraph>
      <div className="page-toolbar">
        <Button
          type="primary"
          onClick={() => {
            createForm.resetFields();
            setCreateOpen(true);
          }}
        >
          {t("rolesPage.create")}
        </Button>
        <Button onClick={load}>{t("common.refresh")}</Button>
      </div>
      <Card className="panel-card">
        <Table
          rowKey="role"
          loading={loading}
          dataSource={items}
          pagination={{ pageSize: 20 }}
          columns={[
            { title: t("rolesPage.roleKey"), dataIndex: "role", render: (r: string) => <Typography.Text code>{r}</Typography.Text> },
            { title: t("rolesPage.roleName"), dataIndex: "name_zh", render: (n: string, row: RoleItem) => <Tag color={roleColor[row.role] || "default"}>{n || ROLE_LABELS[row.role] || row.role}</Tag> },
            {
              title: t("rolesPage.users"),
              dataIndex: "users",
              render: (users: string[], row: RoleItem) => (
                <Space wrap>
                  {(users || []).map((u) => (
                    <Tag
                      key={u}
                      closable
                      onClose={(e) => {
                        e.preventDefault();
                        Modal.confirm({
                          title: t("rolesPage.removeUser"),
                          content: t("rolesPage.removeConfirm", { role: row.name_zh || row.role, user: u }),
                          onOk: async () => {
                            await removeUserFromRole(row.role, u);
                            message.success(t("rolesPage.removed"));
                            load();
                          },
                        });
                      }}
                    >
                      {u}
                    </Tag>
                  ))}
                  <Button
                    size="small"
                    onClick={() => {
                      addUserForm.resetFields();
                      setAddUserRole(row.role);
                    }}
                  >
                    {t("rolesPage.addUser")}
                  </Button>
                </Space>
              ),
            },
            { title: t("rolesPage.perms"), dataIndex: "permissions", render: (perms: string[]) => <Typography.Text type="secondary">{(perms || []).join(", ") || t("common.none")}</Typography.Text> },
          ]}
        />
      </Card>

      <Modal
        title={t("rolesPage.create")}
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={async () => {
          try {
            const v = await createForm.validateFields();
            await createRole({ role: v.role, name_zh: v.name_zh, permissions: v.permissions || [] });
            message.success(t("rolesPage.created"));
            setCreateOpen(false);
            load();
          } catch (e: unknown) {
            if ((e as { errorFields?: unknown })?.errorFields) return;
            message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("rolesPage.createFail"));
          }
        }}
      >
        <Form form={createForm} layout="vertical">
          <Form.Item name="role" label={t("rolesPage.keyEn")} rules={[{ required: true }]}>
            <Input placeholder={t("rolesPage.keyPh")} />
          </Form.Item>
          <Form.Item name="name_zh" label={t("rolesPage.nameZh")} rules={[{ required: true }]}>
            <Input placeholder={t("rolesPage.namePh")} />
          </Form.Item>
          <Form.Item name="permissions" label={t("rolesPage.permsOptional")}>
            <Checkbox.Group
              options={availablePermissions.map((x) => ({ label: x, value: x }))}
              style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0,1fr))", gap: 8 }}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t("rolesPage.addUserTitle", { role: ROLE_LABELS[addUserRole] || addUserRole || "-" })}
        open={!!addUserRole}
        onCancel={() => setAddUserRole("")}
        onOk={async () => {
          try {
            const v = await addUserForm.validateFields();
            await addUserToRole(addUserRole, v.username);
            message.success(t("rolesPage.added"));
            setAddUserRole("");
            load();
          } catch (e: unknown) {
            if ((e as { errorFields?: unknown })?.errorFields) return;
            message.error((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail || t("rolesPage.addFail"));
          }
        }}
      >
        <Form form={addUserForm} layout="vertical">
          <Form.Item name="username" label={t("rolesPage.username")} rules={[{ required: true }]}>
            <Input placeholder={t("rolesPage.userPh")} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
