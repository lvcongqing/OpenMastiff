import axios from "axios";
import { clearAuthToken, getAuthToken } from "../auth";
import { t } from "../i18n";

function baseURL(): string {
  const v = import.meta.env.VITE_API_BASE;
  if (v && String(v).length > 0) return String(v).replace(/\/$/, "");
  return "/api";
}

export const api = axios.create({
  baseURL: baseURL(),
  timeout: 120000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = getAuthToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (resp) => resp,
  (err) => {
    if (err?.response?.status === 401) {
      clearAuthToken();
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  }
);

export async function createRequest(body: Record<string, unknown>) {
  const { data } = await api.post("/requests", body);
  return data;
}

export async function downloadBatchTemplate() {
  const { data } = await api.get("/requests/batch/template", { responseType: "blob" });
  return data as Blob;
}

export async function parseBatchRequests(file: File) {
  const fd = new FormData();
  fd.append("artifact_file", file);
  const { data } = await api.post("/requests/batch/parse", fd, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 180000,
  });
  return data as {
    total: number;
    error_count: number;
    warning_count: number;
    items: Record<string, unknown>[];
    default_review_roles: string[];
  };
}

export async function createBatchRequests(body: { items: Record<string, unknown>[]; submit?: boolean }) {
  const { data } = await api.post("/requests/batch", body, { timeout: 300000 });
  return data as {
    ok: boolean;
    submit: boolean;
    created: Array<Record<string, unknown>>;
    failed: Array<Record<string, unknown>>;
    created_count: number;
    failed_count: number;
  };
}

export async function listRequests(params: {
  limit?: number;
  offset?: number;
  status?: string;
  gate_status?: string;
  project?: string;
  created_by?: string;
  risk_level?: string;
}) {
  const { data } = await api.get("/requests", { params });
  return data as { total: number; items: Record<string, unknown>[] };
}

export async function getRequest(requestId: string) {
  const { data } = await api.get(`/requests/${requestId}`);
  return data as {
    request: Record<string, unknown>;
    source: Record<string, unknown> | null;
    latest_scan_run: Record<string, unknown> | null;
  };
}

export async function getReviewBrief(requestId: string) {
  const { data } = await api.get(`/requests/${requestId}/review-brief`);
  return data as Record<string, unknown>;
}

export async function patchRequest(requestId: string, body: Record<string, unknown>) {
  const { data } = await api.patch(`/requests/${requestId}`, body);
  return data;
}

export async function deleteRequest(requestId: string) {
  const { data } = await api.delete(`/requests/${requestId}`);
  return data as { ok: boolean; request_id: string };
}

export async function uploadSource(requestId: string, file: File) {
  const fd = new FormData();
  fd.append("artifact_file", file);
  const { data } = await api.post(`/requests/${requestId}/source/upload`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function setGitSource(
  requestId: string,
  body: { repo_url: string; ref: string; credential_id?: string | null }
) {
  const { data } = await api.post(`/requests/${requestId}/source/git`, body);
  return data;
}

export async function submitRequest(requestId: string) {
  const { data } = await api.post(`/requests/${requestId}/submit`);
  return data as { request_id: string; status: string; scan_run_id: string };
}

export async function triggerScan(requestId: string) {
  const { data } = await api.post(`/requests/${requestId}/trigger-scan`);
  return data as { request_id: string; status: string; scan_run_id: string };
}

export async function listScanRuns(requestId: string) {
  const { data } = await api.get(`/requests/${requestId}/scan-runs`);
  return data as { items: Record<string, unknown>[] };
}

export async function getScanRun(scanRunId: string) {
  const { data } = await api.get(`/scan-runs/${scanRunId}`);
  return data as Record<string, unknown>;
}

export async function getScanConsole(scanRunId: string) {
  const { data } = await api.get(`/scan-runs/${scanRunId}/console`);
  return data as {
    scan_run_id: string;
    request_id: string;
    status: string;
    live: boolean;
    text: string;
    bytes: number;
    truncated: boolean;
  };
}

export function artifactUrl(scanRunId: string, name: string) {
  const base = baseURL();
  const path = `/scan-runs/${scanRunId}/artifacts/${encodeURIComponent(name)}`;
  return base ? `${base.replace(/\/$/, "")}${path}` : path;
}

export async function getArtifactText(scanRunId: string, name: string) {
  const { data } = await api.get(`/scan-runs/${scanRunId}/artifacts/${encodeURIComponent(name)}`, {
    responseType: "text",
    transformResponse: [(raw) => raw],
  });
  if (typeof data === "string") return data;
  if (data == null) return "";
  return JSON.stringify(data, null, 2);
}

export async function downloadArtifact(scanRunId: string, name: string) {
  const { data } = await api.get(`/scan-runs/${scanRunId}/artifacts/${encodeURIComponent(name)}`, {
    responseType: "blob",
  });
  const blob = new Blob([data]);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${scanRunId}-${name}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function listAuditEvents(requestId: string, limit = 200) {
  const { data } = await api.get(`/requests/${requestId}/audit-events`, { params: { limit } });
  return data as { total: number; items: Record<string, unknown>[] };
}

export async function listRemediations(requestId: string) {
  const { data } = await api.get(`/requests/${requestId}/remediations`);
  return data as { items: Record<string, unknown>[] };
}

export async function listFindings(requestId: string, scanRunId?: string) {
  const params = scanRunId ? { scan_run_id: scanRunId } : {};
  const { data } = await api.get(`/requests/${requestId}/findings`, { params });
  return data as { items: Record<string, unknown>[] };
}

export async function disposeFindings(
  requestId: string,
  body: {
    disposition: "open" | "false_positive" | "accepted_risk" | "confirmed";
    fingerprints?: string[];
    rule_id?: string;
    category?: string;
    reason?: string;
  }
) {
  const { data } = await api.post(`/requests/${requestId}/findings/disposition`, body);
  return data as {
    ok: boolean;
    updated: number;
    disposition: string;
    gate_status?: string;
    status?: string;
    open_high?: number;
    overall?: Record<string, unknown>;
  };
}

export function apiErrorMessage(err: unknown, fallback = "Failed"): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const parts = detail
      .map((x) => {
        if (typeof x === "string") return x;
        const item = x as { msg?: string; loc?: unknown };
        return item.msg || "";
      })
      .filter(Boolean);
    if (parts.length) return parts.join("；");
  }
  if (detail && typeof detail === "object") return JSON.stringify(detail);
  return fallback;
}

export async function createRemediation(
  requestId: string,
  body: {
    title: string;
    severity?: string;
    owner?: string;
    due_at?: string | null;
    finding_fingerprints?: string[];
  }
) {
  const { data } = await api.post(`/requests/${requestId}/remediations`, body);
  return data;
}

export async function closeRemediation(remediationId: string) {
  const { data } = await api.post(`/remediations/${remediationId}/close`);
  return data;
}

export async function listLegalReviews(requestId: string) {
  const { data } = await api.get(`/requests/${requestId}/legal-reviews`);
  return data as { items: Record<string, unknown>[] };
}

export async function createLegalReview(requestId: string) {
  const { data } = await api.post(`/requests/${requestId}/legal-reviews`);
  return data;
}

export async function decideLegalReview(legalReviewId: string, body: { decision: string; rationale: string }) {
  const { data } = await api.post(`/legal-reviews/${legalReviewId}/decision`, body);
  return data;
}

export async function uploadLegalAttachment(legalReviewId: string, file: File) {
  const fd = new FormData();
  fd.append("artifact_file", file);
  const { data } = await api.post(`/legal-reviews/${legalReviewId}/attachment`, fd, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function decideRequest(
  requestId: string,
  body: Record<string, unknown>
) {
  const { data } = await api.post(`/requests/${requestId}/decision`, body);
  return data;
}

export async function reviewInbox(params?: { limit?: number; offset?: number }) {
  const { data } = await api.get("/review/inbox", { params });
  return data as { total: number; items: Record<string, unknown>[] };
}

export async function getPolicy() {
  const { data } = await api.get("/policy");
  return data as { sha256: string; raw: Record<string, unknown> };
}

export async function putPolicy(raw: Record<string, unknown>) {
  const { data } = await api.put("/policy", { raw });
  return data as { sha256: string; raw: Record<string, unknown> };
}

export async function listCredentials() {
  const { data } = await api.get("/credentials");
  return data as { total: number; items: Record<string, unknown>[] };
}

export async function createCredential(body: Record<string, unknown>) {
  const { data } = await api.post("/credentials", body);
  return data;
}

export async function deleteCredential(credentialId: string) {
  const { data } = await api.delete(`/credentials/${credentialId}`);
  return data;
}

export async function updateCredential(credentialId: string, body: Record<string, unknown>) {
  const { data } = await api.patch(`/credentials/${credentialId}`, body);
  return data;
}

export async function exportEvidence(requestId: string) {
  const { data } = await api.post(`/requests/${requestId}/export`);
  return data as { export_id: string };
}

export function exportDownloadUrl(exportId: string) {
  const base = baseURL();
  const path = `/exports/${exportId}`;
  return base ? `${base.replace(/\/$/, "")}${path}` : path;
}

export async function downloadExport(exportId: string) {
  const { data } = await api.get(`/exports/${exportId}`, {
    responseType: "blob",
  });
  const blob = new Blob([data], { type: "application/zip" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `evidence-${exportId}.zip`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

async function blobError(err: unknown, fallback: string): Promise<never> {
  const data = (err as { response?: { data?: unknown } })?.response?.data;
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    const text = await data.text();
    try {
      const parsed = JSON.parse(text) as { detail?: unknown };
      throw Object.assign(new Error(apiErrorMessage({ response: { data: parsed } }, fallback)), {
        response: { data: parsed },
      });
    } catch (inner) {
      if ((inner as { response?: unknown }).response) throw inner;
    }
  }
  throw err;
}

export async function downloadReviewReport(requestId: string, filenameHint = "", filePrefix = "intake-review") {
  try {
    const { data } = await api.get(`/requests/${requestId}/review-report`, {
      responseType: "blob",
    });
    const blob = new Blob([data], { type: "application/pdf" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const safe = String(filenameHint || requestId)
      .replace(/[\\/:*?"<>|]+/g, "_")
      .slice(0, 80);
    a.download = `${filePrefix}-${safe || requestId}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    await blobError(err, t("request.reportFail"));
  }
}

export async function login(body: { username: string; password: string }) {
  const { data } = await api.post("/auth/login", body);
  return data as {
    access_token: string;
    token_type: string;
    user: {
      username: string;
      display_name: string;
      role: "admin" | "legal" | "project_manager" | "rd_manager" | "quality_manager" | "product_manager" | "viewer";
      roles?: string[];
      role_name_zh?: string;
    };
  };
}

export async function me() {
  const { data } = await api.get("/auth/me");
  return data as {
    user:
      | {
          username: string;
          display_name: string;
          role: "admin" | "legal" | "project_manager" | "rd_manager" | "quality_manager" | "product_manager" | "viewer";
          roles?: string[];
          role_name_zh?: string;
        }
      | null;
  };
}

export async function listRoles() {
  const { data } = await api.get("/auth/roles");
  return data as {
    items: Array<{ role: string; name_zh: string; permissions: string[]; users: string[] }>;
    available_permissions?: string[];
  };
}

export async function listReviewRoles() {
  const { data } = await api.get("/auth/review-roles");
  return data as { items: Array<{ role: string; name_zh: string }> };
}

export async function createRole(body: { role: string; name_zh: string; permissions?: string[] }) {
  const { data } = await api.post("/auth/roles", body);
  return data as { role: string; name_zh: string; permissions: string[] };
}

export async function addUserToRole(role: string, username: string) {
  const { data } = await api.post(`/auth/roles/${encodeURIComponent(role)}/users`, { username });
  return data as { username: string; role: string };
}

export async function removeUserFromRole(role: string, username: string) {
  const { data } = await api.delete(`/auth/roles/${encodeURIComponent(role)}/users/${encodeURIComponent(username)}`);
  return data as {
    username: string;
    role: string;
  };
}

async function fetchBootstrapStatus(url: string) {
  const { data, headers } = await axios.get(url, {
    headers: { Accept: "application/json" },
    validateStatus: (s) => s === 200,
  });
  const ct = String(headers?.["content-type"] || "");
  if (ct && !ct.includes("json")) {
    throw new Error("bootstrap status is not JSON");
  }
  if (!data || typeof data !== "object" || typeof (data as { initialized?: unknown }).initialized !== "boolean") {
    throw new Error("bootstrap status is not JSON");
  }
  return data as { initialized: boolean; auth_mode: "ldap" | "http"; config_file: string };
}

export async function getBootstrapStatus() {
  const candidates = Array.from(new Set([`${baseURL()}/bootstrap/status`, "/api/bootstrap/status"]));
  let last: unknown;
  for (const url of candidates) {
    try {
      return await fetchBootstrapStatus(url);
    } catch (e) {
      last = e;
    }
  }
  throw last instanceof Error ? last : new Error("bootstrap status unavailable");
}

export async function initBootstrap(body: Record<string, unknown>) {
  const { data } = await axios.post(`${baseURL()}/bootstrap/init`, body, {
    headers: { "Content-Type": "application/json" },
  });
  return data as {
    ok: boolean;
    initialized: boolean;
    restart_required?: boolean;
    restart_services?: string[];
    restart_hint?: string;
  };
}

export async function validateBootstrap(body: Record<string, unknown>) {
  const { data } = await axios.post(`${baseURL()}/bootstrap/validate`, body, {
    headers: { "Content-Type": "application/json" },
  });
  return data as {
    ok: boolean;
    ldap: { ok: boolean; detail: string };
    mongo: { ok: boolean; detail: string };
    redis: { ok: boolean; detail: string };
    storage: { ok: boolean; detail: string };
  };
}
