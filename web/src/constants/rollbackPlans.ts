import { t } from "../i18n";

export type RollbackPlan = {
  value: string;
  label: string;
  summary: string;
  detail: string;
};

const ROLLBACK_VALUES = [
  "version_downgrade",
  "remove_dependency",
  "replace_alternative",
  "feature_flag_off",
  "isolate_degrade",
  "registry_rollback",
  "hotfix_patch",
  "other",
] as const;

function planOf(value: string): RollbackPlan {
  return {
    value,
    label: t(`rollback.${value}.label`),
    summary: t(`rollback.${value}.summary`),
    detail: t(`rollback.${value}.detail`),
  };
}

function knownValue(value: string) {
  return (ROLLBACK_VALUES as readonly string[]).includes(value);
}

/** 开源组件引入场景下的标准回滚策略；写入 rollback_plan 字段的是 value。 */
export function rollbackPlans(): RollbackPlan[] {
  return ROLLBACK_VALUES.map(planOf);
}

/** Snapshot of plans; prefer rollbackPlans() in render so language switches apply. */
export const ROLLBACK_PLANS: RollbackPlan[] = rollbackPlans();

export function getRollbackPlan(value?: string): RollbackPlan | undefined {
  if (!value || !knownValue(value)) return undefined;
  return planOf(value);
}

export function encodeRollbackPlan(value: string, notes?: string): string {
  if (value === "other") {
    const text = (notes || "").trim();
    return text ? `other:${text}` : "other";
  }
  return value;
}

export function decodeRollbackPlan(raw?: string): { key?: string; notes?: string } {
  const text = String(raw || "").trim();
  if (!text) return {};
  if (knownValue(text) && text !== "other") return { key: text };
  if (text === "other") return { key: "other", notes: "" };
  if (text.startsWith("other:")) return { key: "other", notes: text.slice("other:".length) };
  return { key: "other", notes: text };
}

export function rollbackSelectOptions() {
  return rollbackPlans().map((p) => ({
    value: p.value,
    label: p.label,
    summary: p.summary,
  }));
}

export const ROLLBACK_SELECT_OPTIONS = rollbackSelectOptions();
