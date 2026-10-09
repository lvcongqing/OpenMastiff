import { getAuthUser } from "../auth";

const MANAGE_ROLES = new Set(["admin", "project_manager", "rd_manager", "product_manager", "user"]);

export function userRoles() {
  const user = getAuthUser();
  return (user?.roles && user.roles.length ? user.roles : [user?.role || ""]).filter(Boolean).map(String);
}

export function hasPermission(perm: string) {
  const user = getAuthUser();
  if ((user?.permissions || []).includes(perm)) return true;
  return false;
}

export function canManageRequests() {
  if (hasPermission("request.manage")) return true;
  return userRoles().some((r) => MANAGE_ROLES.has(r));
}

export function canEditRequest(status?: string) {
  return String(status || "") !== "Scanning";
}

export function canEditRequestSource(status?: string) {
  const s = String(status || "");
  return s !== "Scanning" && s !== "Approved";
}

export function canEditRequestRoles(status?: string) {
  const s = String(status || "");
  return s === "Draft" || s === "ReReview";
}

export function canDeleteRequest(status?: string) {
  return String(status || "") !== "Scanning";
}
