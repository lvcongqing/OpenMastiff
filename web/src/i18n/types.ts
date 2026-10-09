export type Locale = "zh-CN" | "en-US";

export type MessageTree = { [key: string]: string | MessageTree };

export type TFunction = (key: string, vars?: Record<string, string | number>) => string;

export const LOCALES: { id: Locale; short: string; name: string }[] = [
  { id: "zh-CN", short: "中", name: "简体中文" },
  { id: "en-US", short: "EN", name: "English" },
];

export const LOCALE_STORAGE_KEY = "openmastiff.locale";
export const DEFAULT_LOCALE: Locale = "zh-CN";
