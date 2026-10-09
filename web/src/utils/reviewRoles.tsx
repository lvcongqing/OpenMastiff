import { Tag } from "antd";
import type { ReactNode, MouseEvent } from "react";
import { listReviewRoles } from "../api/client";
import { ROLE_LABELS } from "../constants/display";

const NON_REVIEW_ROLES = new Set(["user", "viewer"]);

export const DEFAULT_REVIEW_ROLES = ["project_manager", "rd_manager", "product_manager", "legal", "security"];

export function mergeRequiredReviewRoles(selected?: string[]) {
  const extra = (selected || []).map((x) => String(x).trim()).filter(Boolean);
  return [...new Set([...DEFAULT_REVIEW_ROLES, ...extra])];
}

export function isDefaultReviewRole(role: string) {
  return DEFAULT_REVIEW_ROLES.includes(role);
}

export function fallbackReviewRoleOptions() {
  return Object.entries(ROLE_LABELS)
    .filter(([role]) => !NON_REVIEW_ROLES.has(role))
    .map(([value, label]) => ({ value, label }));
}

export async function loadReviewRoleOptions() {
  try {
    const r = await listReviewRoles();
    const items = (r.items || [])
      .map((x) => ({
        value: String(x.role || "").trim(),
        label: String(x.name_zh || ROLE_LABELS[x.role] || x.role),
      }))
      .filter((x) => x.value && !NON_REVIEW_ROLES.has(x.value));
    if (items.length) return items;
  } catch {
    /* 普通用户不能调管理员角色接口，走公开审核角色列表的兜底 */
  }
  return fallbackReviewRoleOptions();
}

export function reviewRoleTagRender(props: {
  label: ReactNode;
  value: string | number;
  closable: boolean;
  onClose: (event?: MouseEvent<HTMLElement>) => void;
}) {
  const { label, value, closable, onClose } = props;
  const locked = isDefaultReviewRole(String(value));
  return (
    <Tag style={{ marginInlineEnd: 4 }} closable={closable && !locked} onClose={onClose}>
      {label}
    </Tag>
  );
}
