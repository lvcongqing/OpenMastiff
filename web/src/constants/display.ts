import { t } from "../i18n";

const ROLE_KEYS = [
  "admin",
  "legal",
  "project_manager",
  "rd_manager",
  "quality_manager",
  "product_manager",
  "user",
  "viewer",
  "security",
] as const;

const STATUS_KEYS = [
  "Draft",
  "Submitted",
  "Scanning",
  "Reviewing",
  "LegalReviewing",
  "Blocked",
  "Approved",
  "ConditionalApproved",
  "Remediating",
  "ReReview",
  "Rejected",
  "Waived",
] as const;

const GATE_KEYS = ["Pass", "Fail", "PendingLegal", "Unknown"] as const;

const CATEGORY_KEYS = [
  "gosec",
  "eslint",
  "bandit",
  "pmd",
  "cargo_audit",
  "cppcheck",
  "license",
  "maintenance",
  "cve",
] as const;

const DISPOSITION_KEYS = ["open", "false_positive", "accepted_risk", "confirmed"] as const;

function mapLabels(prefix: string, keys: readonly string[]): Record<string, string> {
  return Object.fromEntries(keys.map((k) => [k, t(`${prefix}.${k}`)]));
}

/** Live maps — call inside render so language switches apply. */
export function roleLabels(): Record<string, string> {
  return mapLabels("role", ROLE_KEYS);
}

export function requestStatusLabels(): Record<string, string> {
  return mapLabels("status", STATUS_KEYS);
}

export function gateStatusLabels(): Record<string, string> {
  return mapLabels("gate", GATE_KEYS);
}

export function findingCategoryLabels(): Record<string, string> {
  return mapLabels("category", CATEGORY_KEYS);
}

export function dispositionLabels(): Record<string, string> {
  return mapLabels("disposition", DISPOSITION_KEYS);
}

export function roleLabel(key: string): string {
  return t(`role.${key}`);
}

export function statusLabel(key: string): string {
  return t(`status.${key}`);
}

export function gateLabel(key: string): string {
  return t(`gate.${key}`);
}

export function categoryLabel(key: string): string {
  return t(`category.${key}`);
}

export function dispositionLabel(key: string): string {
  return t(`disposition.${key}`);
}

export const MAINT_SOURCE_LABELS: Record<string, string> = {
  github: "GitHub",
  gitee: "Gitee",
  atomgit: "AtomGit",
  gitcode: "GitCode",
  gitlab: "GitLab",
  kernel: "kernel.org",
  apache: "Apache",
  bitbucket: "Bitbucket",
  savannah: "Savannah",
  sourcehut: "SourceHut",
  codeberg: "Codeberg",
  gitea: "Gitea",
  pypi: "PyPI",
  npm: "npm",
  crates: "crates.io",
  go: "Go module",
  debian: "Debian",
  maven: "Maven",
  git: "Git",
};

export const DISPOSITION_COLORS: Record<string, string> = {
  open: "default",
  false_positive: "green",
  accepted_risk: "gold",
  confirmed: "red",
};

/** Backward-compatible accessors used by older call sites. */
export const ROLE_LABELS = new Proxy({} as Record<string, string>, {
  get: (_target, prop: string) => (typeof prop === "string" ? roleLabel(prop) : undefined),
  ownKeys: () => [...ROLE_KEYS],
  getOwnPropertyDescriptor: (_target, prop) =>
    typeof prop === "string" ? { configurable: true, enumerable: true, value: roleLabel(prop) } : undefined,
});

export const REQUEST_STATUS_LABELS = new Proxy({} as Record<string, string>, {
  get: (_target, prop: string) => (typeof prop === "string" ? statusLabel(prop) : undefined),
  ownKeys: () => [...STATUS_KEYS],
  getOwnPropertyDescriptor: (_target, prop) =>
    typeof prop === "string" ? { configurable: true, enumerable: true, value: statusLabel(prop) } : undefined,
});

export const GATE_STATUS_LABELS = new Proxy({} as Record<string, string>, {
  get: (_target, prop: string) => (typeof prop === "string" ? gateLabel(prop) : undefined),
  ownKeys: () => [...GATE_KEYS],
  getOwnPropertyDescriptor: (_target, prop) =>
    typeof prop === "string" ? { configurable: true, enumerable: true, value: gateLabel(prop) } : undefined,
});

export const FINDING_CATEGORY_LABELS = new Proxy({} as Record<string, string>, {
  get: (_target, prop: string) => (typeof prop === "string" ? categoryLabel(prop) : undefined),
  ownKeys: () => [...CATEGORY_KEYS],
  getOwnPropertyDescriptor: (_target, prop) =>
    typeof prop === "string" ? { configurable: true, enumerable: true, value: categoryLabel(prop) } : undefined,
});

export const DISPOSITION_LABELS = new Proxy({} as Record<string, string>, {
  get: (_target, prop: string) => (typeof prop === "string" ? dispositionLabel(prop) : undefined),
  ownKeys: () => [...DISPOSITION_KEYS],
  getOwnPropertyDescriptor: (_target, prop) =>
    typeof prop === "string" ? { configurable: true, enumerable: true, value: dispositionLabel(prop) } : undefined,
});

/** 展示用 Gate：优先 effective_gate_status（法务复核后可能已由待法务变为通过） */
export function displayGateStatus(req: {
  effective_gate_status?: string;
  gate_status?: string;
}): string {
  return String(req.effective_gate_status || req.gate_status || "Unknown");
}
