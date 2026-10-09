import { Alert, Form, Input, Select, Typography } from "antd";
import { getRollbackPlan, rollbackSelectOptions } from "../constants/rollbackPlans";
import { useI18n } from "../i18n/LocaleContext";

export default function RollbackPlanField() {
  const { t } = useI18n();
  const selected = Form.useWatch("rollback_plan") as string | undefined;
  const meta = getRollbackPlan(selected);
  const options = rollbackSelectOptions();

  return (
    <>
      <Form.Item name="rollback_plan" label={t("rollback.field")} rules={[{ required: true, message: t("rollback.required") }]}>
        <Select
          placeholder={t("rollback.extra")}
          options={options}
          optionRender={(option) => (
            <div style={{ whiteSpace: "normal", padding: "4px 0" }}>
              <div>{option.data.label}</div>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {String((option.data as { summary?: string }).summary || "")}
              </Typography.Text>
            </div>
          )}
        />
      </Form.Item>
      {meta && (
        <Alert type="info" showIcon style={{ marginBottom: 16 }} message={meta.label} description={meta.detail} />
      )}
      {selected === "other" && (
        <Form.Item
          name="rollback_plan_notes"
          label={t("rollback.notes")}
          rules={[{ required: true, message: t("rollback.notesRequired") }]}
        >
          <Input.TextArea rows={3} placeholder={t("rollback.notesPh")} />
        </Form.Item>
      )}
    </>
  );
}
