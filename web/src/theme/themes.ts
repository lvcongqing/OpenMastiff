export type ThemeId = "huaqing" | "salan" | "zhanlan" | "qiubo" | "songshi";

export type ThemeOption = {
  id: ThemeId;
  name: string;
  hex: string;
};

export type ThemeSurfaces = {
  primary: string;
  pageBg: string;
  headerBg: string;
  siderFrom: string;
  siderTo: string;
  tableHead: string;
  onPrimary: string;
  onSider: string;
  onHeader: string;
  menuDark: boolean;
  connector: string;
};

export const THEMES: ThemeOption[] = [
  { id: "huaqing", name: "huaqing", hex: "#183f89" },
  { id: "salan", name: "salan", hex: "#182876" },
  { id: "zhanlan", name: "zhanlan", hex: "#1f3d55" },
  { id: "qiubo", name: "qiubo", hex: "#68AEC6" },
  { id: "songshi", name: "songshi", hex: "#6ca9ae" },
];

export const DEFAULT_THEME_ID: ThemeId = "huaqing";
export const THEME_STORAGE_KEY = "openmastiff.theme";

export function isThemeId(v: string | null | undefined): v is ThemeId {
  return THEMES.some((t) => t.id === v);
}

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}

function rgbToHex(r: number, g: number, b: number): string {
  return `#${[r, g, b].map((n) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, "0")).join("")}`;
}

function mixHex(hex: string, whiteAmt: number): string {
  const [r, g, b] = hexToRgb(hex);
  const m = (c: number) => c + (255 - c) * whiteAmt;
  return rgbToHex(m(r), m(g), m(b));
}

function mixBlack(hex: string, blackAmt: number): string {
  const [r, g, b] = hexToRgb(hex);
  const m = (c: number) => c * (1 - blackAmt);
  return rgbToHex(m(r), m(g), m(b));
}

function luminance(hex: string): number {
  const [r, g, b] = hexToRgb(hex).map((c) => c / 255);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function themeById(id: ThemeId): ThemeOption {
  return THEMES.find((t) => t.id === id) || THEMES[0];
}

export function themeSurfaces(hex: string): ThemeSurfaces {
  const light = luminance(hex) > 0.42;
  const onInk = light ? "#12303a" : "#ffffff";
  return {
    primary: hex,
    pageBg: mixHex(hex, light ? 0.88 : 0.91),
    headerBg: light ? mixBlack(hex, 0.08) : mixHex(hex, 0.1),
    siderFrom: mixBlack(hex, light ? 0.06 : 0.1),
    siderTo: hex,
    tableHead: "#f6f7f9",
    onPrimary: onInk,
    onSider: onInk,
    onHeader: onInk,
    menuDark: !light,
    // 白卡片上的步骤连接线：浅色主题压暗主色，深色主题沿用主色
    connector: light ? mixBlack(hex, 0.38) : hex,
  };
}

export function applyThemeVars(hex: string) {
  const root = document.documentElement;
  const s = themeSurfaces(hex);
  root.dataset.themeMenu = s.menuDark ? "dark" : "light";
  root.style.setProperty("--om-primary", s.primary);
  root.style.setProperty("--om-bg", s.pageBg);
  root.style.setProperty("--om-header", s.headerBg);
  root.style.setProperty("--om-sider-from", s.siderFrom);
  root.style.setProperty("--om-sider-to", s.siderTo);
  root.style.setProperty("--om-table-head", s.tableHead);
  root.style.setProperty("--om-on-primary", s.onPrimary);
  root.style.setProperty("--om-on-sider", s.onSider);
  root.style.setProperty("--om-on-header", s.onHeader);
  root.style.setProperty("--om-connector", s.connector);
  root.style.background = s.pageBg;
}
