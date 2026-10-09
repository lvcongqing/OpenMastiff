import { Button, Dropdown, message } from "antd";
import { CloudDownloadOutlined, DownOutlined } from "@ant-design/icons";
import type { MenuProps } from "antd";
import { downloadArtifact } from "../api/client";
import { useI18n } from "../i18n/LocaleContext";
import { listVisibleReports, type OutputMeta } from "../utils/scanReports";

export default function ScanReportsMenu({
  scanRunId,
  outputs,
  includeLogs = false,
}: {
  scanRunId: string;
  outputs: Record<string, OutputMeta>;
  includeLogs?: boolean;
}) {
  const { t } = useI18n();
  const reports = listVisibleReports(outputs, { includeLogs });
  if (!reports.length) return <span>—</span>;

  const grouped = new Map<string, { name: string; label: string }[]>();
  for (const it of reports) {
    const list = grouped.get(it.group) || [];
    list.push({ name: it.name, label: it.label });
    grouped.set(it.group, list);
  }

  const groupLabel: Record<string, string> = {
    overview: t("reports.groupOverview"),
    security: t("reports.groupSecurity"),
    sbom: t("reports.groupSbom"),
    other: t("reports.groupOther"),
  };

  const items: MenuProps["items"] = [];
  for (const group of ["overview", "security", "sbom", "other"]) {
    const list = grouped.get(group);
    if (!list?.length) continue;
    items.push({ type: "group", label: groupLabel[group] || group, key: `g-${group}` });
    for (const it of list) {
      items.push({
        key: it.name,
        label: it.label,
        icon: <CloudDownloadOutlined />,
        onClick: async () => {
          try {
            await downloadArtifact(scanRunId, it.name);
          } catch {
            message.error(t("scan.downloadFail"));
          }
        },
      });
    }
  }

  return (
    <Dropdown menu={{ items }} trigger={["click"]} placement="bottomRight">
      <Button size="small" onClick={(e) => e.stopPropagation()}>
        {t("request.reports")}（{reports.length}）
        <DownOutlined />
      </Button>
    </Dropdown>
  );
}
