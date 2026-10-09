import { t } from "../i18n";

/** 合并 legal_reviews 与 role_reviews，供各 UI 统一展示会签进度 */

export type RoleReviewEntry = {
  status?: string;
  decision?: string | null;
  comment?: string | null;
  updated_by?: string | null;
  updated_at?: string | null;
  source?: string;
};

export type LegalReviewItem = {
  legal_review_id?: string;
  status?: string;
  decision?: string;
  rationale?: string;
  decided_by?: string;
  updated_at?: string;
  created_at?: string;
};

function legalToRoleEntry(lr: LegalReviewItem): RoleReviewEntry {
  const st = String(lr.status || "");
  if (st === "Allowed") {
    return {
      status: "Approved",
      decision: "Allowed",
      comment: lr.rationale ?? null,
      updated_by: lr.decided_by ?? null,
      updated_at: String(lr.updated_at || lr.created_at || ""),
      source: "legal_review",
    };
  }
  if (st === "Denied") {
    return {
      status: "Rejected",
      decision: "Denied",
      comment: lr.rationale ?? null,
      updated_by: lr.decided_by ?? null,
      updated_at: String(lr.updated_at || lr.created_at || ""),
      source: "legal_review",
    };
  }
  return {
    status: "Pending",
    decision: null,
    comment: null,
    updated_by: null,
    updated_at: String(lr.updated_at || lr.created_at || ""),
    source: "legal_review",
  };
}

function latestLegal(legalItems: LegalReviewItem[]): LegalReviewItem | undefined {
  if (!legalItems.length) return undefined;
  return [...legalItems].sort(
    (a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || ""))
  )[0];
}

function latestDecidedLegal(legalItems: LegalReviewItem[]): LegalReviewItem | undefined {
  const sorted = [...legalItems].sort(
    (a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || ""))
  );
  return sorted.find((x) => x.status === "Allowed" || x.status === "Denied");
}

export function mergeRoleReviews(
  requiredRoles: string[],
  roleReviews: Record<string, RoleReviewEntry>,
  legalItems: LegalReviewItem[],
  gateStatus?: string
): Record<string, RoleReviewEntry> {
  const merged: Record<string, RoleReviewEntry> = { ...roleReviews };
  const needsLegal = requiredRoles.includes("legal") || gateStatus === "PendingLegal";
  const decided = latestDecidedLegal(legalItems);
  const latest = latestLegal(legalItems);

  if (decided) {
    merged.legal = legalToRoleEntry(decided);
  } else if (latest?.status === "Pending" && needsLegal) {
    merged.legal = legalToRoleEntry(latest);
  } else if (needsLegal && !merged.legal) {
    merged.legal = { status: "Pending", decision: null, source: "legal_review" };
  }

  return merged;
}

export function isRoleReviewDone(entry?: RoleReviewEntry): boolean {
  if (!entry) return false;
  const st = String(entry.status || "Pending");
  if (st === "Approved" || st === "Rejected") return true;
  if (entry.decision === "Allowed" || entry.decision === "Approved") return true;
  if (entry.decision === "Denied" || entry.decision === "Rejected") return true;
  return false;
}

export function roleReviewStatusLabel(entry?: RoleReviewEntry): string {
  if (!entry || !isRoleReviewDone(entry)) return t("reviewState.pending");
  const st = String(entry.status || "");
  if (st === "Approved" && entry.decision === "Allowed") return t("reviewState.legalAllowed");
  if (st === "Rejected" && entry.decision === "Denied") return t("reviewState.legalDenied");
  if (st === "Approved" || entry.decision === "Approved" || entry.decision === "Allowed") return t("reviewState.approved");
  if (st === "Rejected" || entry.decision === "Rejected" || entry.decision === "Denied") return t("reviewState.rejected");
  return st || t("reviewState.pending");
}

export function roleReviewStatusColor(entry?: RoleReviewEntry): string {
  if (!entry || !isRoleReviewDone(entry)) return "processing";
  const st = String(entry.status || "");
  if (st === "Approved" || entry.decision === "Allowed" || entry.decision === "Approved") return "success";
  if (st === "Rejected" || entry.decision === "Denied" || entry.decision === "Rejected") return "error";
  return "processing";
}
