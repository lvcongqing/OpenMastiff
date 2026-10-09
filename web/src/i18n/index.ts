import dayjs from "dayjs";
import "dayjs/locale/zh-cn";
import "dayjs/locale/en";
import zhCN from "./zh-CN";
import enUS from "./en-US";
import { detectLocale, interpolate, lookup } from "./lookup";
import { DEFAULT_LOCALE, LOCALE_STORAGE_KEY, type Locale, type MessageTree, type TFunction } from "./types";

const DICTS: Record<Locale, MessageTree> = {
  "zh-CN": zhCN,
  "en-US": enUS,
};

type Listener = () => void;
const listeners = new Set<Listener>();

let currentLocale: Locale = DEFAULT_LOCALE;

function persist(locale: Locale) {
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    /* ignore */
  }
}

function applyDocument(locale: Locale) {
  if (typeof document === "undefined") return;
  document.documentElement.lang = locale === "zh-CN" ? "zh-CN" : "en";
  const title = lookup(DICTS[locale], "brand.documentTitle") || "OpenMastiff";
  document.title = title;
}

export const t: TFunction = (key, vars) => {
  const raw = lookup(DICTS[currentLocale], key) ?? lookup(DICTS["zh-CN"], key);
  if (raw == null) {
    const fallback = key.includes(".") ? key.slice(key.lastIndexOf(".") + 1) : key;
    return interpolate(fallback, vars);
  }
  return interpolate(raw, vars);
};

export function getLocale(): Locale {
  return currentLocale;
}

export function setLocale(locale: Locale) {
  if (locale !== "zh-CN" && locale !== "en-US") return;
  currentLocale = locale;
  persist(locale);
  dayjs.locale(locale === "zh-CN" ? "zh-cn" : "en");
  applyDocument(locale);
  listeners.forEach((fn) => fn());
}

export function subscribeLocale(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function initLocale() {
  currentLocale = detectLocale(DEFAULT_LOCALE);
  dayjs.locale(currentLocale === "zh-CN" ? "zh-cn" : "en");
  applyDocument(currentLocale);
}

export type { Locale, TFunction };
export { LOCALES } from "./types";
