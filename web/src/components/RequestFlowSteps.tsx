import { Card, Steps, Typography } from "antd";
import { gateLabel, roleLabel, statusLabel } from "../constants/display";
import { useI18n } from "../i18n/LocaleContext";
import { isRoleReviewDone } from "../utils/roleReviews";

type Props = {
  status: string;
  gate: string;
  /** 扫描原始门禁（法务放行后与 gate 可能不同） */
  scannerGate?: string;
  requiredRoles: string[];
  roleReviews: Record<string, { status?: string; decision?: string | null }>;
  hasSource: boolean;
};

export default function RequestFlowSteps({ status, gate, scannerGate, requiredRoles, roleReviews, hasSource }: Props) {
  const { t } = useI18n();
  const st = String(status);
  const g = String(gate);
  const joinRoles = (keys: string[]) => keys.map((k) => roleLabel(k)).join(t("common.listSep"));

  const inDraft = st === "Draft";
  const inSubmitted = st === "Submitted";
  const inScanning = st === "Scanning";
  const gateFailed = g === "Fail";
  const gatePass = g === "Pass";
  const gatePendingLegal = g === "PendingLegal";
  const roleRejected = (r: string) => {
    const rv = roleReviews[r] || {};
    const rs = String(rv.status || "");
    return rs === "Rejected" || rv.decision === "Rejected" || rv.decision === "Denied";
  };
  const rolesPending = requiredRoles.filter((r) => !isRoleReviewDone(roleReviews[r]));
  const allRolesApproved = requiredRoles.length > 0 && rolesPending.length === 0;
  const anyRejected = requiredRoles.some((r) => roleRejected(r));

  const reviewStepStatus = (() => {
    if (requiredRoles.length === 0) return { status: "wait" as const, desc: t("flow.noRoleReview") };
    if (st === "Rejected" && anyRejected) return { status: "error" as const, desc: t("flow.hasReject") };
    if (st === "Approved" && allRolesApproved) return { status: "finish" as const, desc: t("flow.allPass") };
    if (allRolesApproved) return { status: "finish" as const, desc: t("flow.allPass") };
    if (["Reviewing", "ReReview"].includes(st) && rolesPending.length) {
      return { status: "process" as const, desc: t("flow.waitPrefix") + joinRoles(rolesPending) };
    }
    if (st === "Scanning" || st === "Submitted" || (st === "Draft" && hasSource)) {
      return { status: "wait" as const, desc: t("flow.waitReview") };
    }
    return { status: "process" as const, desc: joinRoles(rolesPending) || t("flow.pending") };
  })();

  const finalStep = (() => {
    if (st === "Approved") return { status: "finish" as const, sub: t("flow.approved") };
    if (st === "Rejected") return { status: "error" as const, sub: t("flow.rejected") };
    if (st === "Waived" || st === "ConditionalApproved") return { status: "finish" as const, sub: statusLabel(st) };
    return { status: "wait" as const, sub: t("flow.open") };
  })();

  let gateStepStatus: "wait" | "process" | "finish" | "error" = "wait";
  if (inDraft || inScanning || inSubmitted) gateStepStatus = "wait";
  else if (gateFailed) gateStepStatus = "error";
  else if (gatePass) gateStepStatus = "finish";
  else if (gatePendingLegal) gateStepStatus = "process";
  else if (g === "Unknown") gateStepStatus = "process";
  else gateStepStatus = "finish";

  return (
    <Card className="panel-card" size="small" style={{ marginBottom: 12 }}>
      <Typography.Text type="secondary" style={{ display: "block", marginBottom: 8 }}>
        {t("flow.title")}
      </Typography.Text>
      <Steps
        size="small"
        items={[
          {
            title: t("flow.draft"),
            description: inDraft ? t("flow.editing") : t("flow.created"),
            status: inDraft ? "process" : "finish",
          },
          {
            title: t("flow.scan"),
            description: inDraft
              ? hasSource
                ? t("flow.canSubmit")
                : t("flow.needUpload")
              : inSubmitted
                ? t("flow.queued")
                : inScanning
                  ? t("flow.running")
                  : t("flow.done"),
            status: inScanning || inSubmitted ? "process" : inDraft ? "wait" : "finish",
          },
          {
            title: t("flow.gate"),
            description:
              scannerGate === "PendingLegal" && gate === "Pass"
                ? t("flow.legalReleased")
                : g === "Unknown" && !inDraft && !inScanning && !inSubmitted
                  ? t("flow.pendingJudge")
                  : gateFailed
                    ? t("flow.failed")
                    : gateLabel(g),
            status: inDraft || inScanning || inSubmitted ? "wait" : gateStepStatus,
          },
          {
            title: t("flow.signoff"),
            description: requiredRoles.length ? reviewStepStatus.desc : t("flow.unconfigured"),
            status: reviewStepStatus.status,
          },
          {
            title: t("flow.conclusion"),
            description: finalStep.sub,
            status: finalStep.status,
          },
        ]}
      />
    </Card>
  );
}
