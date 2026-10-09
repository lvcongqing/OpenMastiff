import type { Locale, MessageTree } from "./types";

export function lookup(tree: MessageTree, key: string): string | undefined {
  const parts = key.split(".");
  let cur: string | MessageTree | undefined = tree;
  for (let i = 0; i < parts.length; i++) {
    if (!cur || typeof cur === "string") return undefined;
    const rest = parts.slice(i).join(".");
    const exact = cur[rest];
    if (typeof exact === "string") return exact;
    cur = cur[parts[i]];
  }
  return typeof cur === "string" ? cur : undefined;
}

export function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, name: string) =>
    vars[name] === undefined || vars[name] === null ? `{${name}}` : String(vars[name]),
  );
}

export function detectLocale(fallback: Locale): Locale {
  try {
    const stored = localStorage.getItem("openmastiff.locale");
    if (stored === "zh-CN" || stored === "en-US") return stored;
  } catch {
    /* ignore */
  }
  try {
    const nav = (navigator.language || "").toLowerCase();
    if (nav.startsWith("zh")) return "zh-CN";
    if (nav) return "en-US";
  } catch {
    /* ignore */
  }
  return fallback;
}
