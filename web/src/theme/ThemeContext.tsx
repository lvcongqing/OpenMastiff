import { ConfigProvider, theme as antdTheme } from "antd";
import enUS from "antd/locale/en_US";
import zhCN from "antd/locale/zh_CN";
import { useI18n } from "../i18n/LocaleContext";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  DEFAULT_THEME_ID,
  THEME_STORAGE_KEY,
  ThemeId,
  ThemeSurfaces,
  applyThemeVars,
  isThemeId,
  themeById,
  themeSurfaces,
} from "./themes";

type ThemeContextValue = {
  themeId: ThemeId;
  setThemeId: (id: ThemeId) => void;
  hex: string;
  surfaces: ThemeSurfaces;
};

const defaultSurfaces = themeSurfaces(themeById(DEFAULT_THEME_ID).hex);

const ThemeContext = createContext<ThemeContextValue>({
  themeId: DEFAULT_THEME_ID,
  setThemeId: () => undefined,
  hex: themeById(DEFAULT_THEME_ID).hex,
  surfaces: defaultSurfaces,
});

export function useAppTheme() {
  return useContext(ThemeContext);
}

function readStoredTheme(): ThemeId {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (isThemeId(raw)) return raw;
  } catch {
    /* ignore */
  }
  return DEFAULT_THEME_ID;
}

export function AppThemeProvider({ children }: { children: ReactNode }) {
  const { locale } = useI18n();
  const [themeId, setThemeIdState] = useState<ThemeId>(readStoredTheme);
  const current = themeById(themeId);
  const surfaces = useMemo(() => themeSurfaces(current.hex), [current.hex]);
  const antdLocale = locale === "en-US" ? enUS : zhCN;

  useEffect(() => {
    applyThemeVars(current.hex);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, themeId);
    } catch {
      /* ignore */
    }
  }, [themeId, current.hex]);

  const setThemeId = (id: ThemeId) => setThemeIdState(id);

  const value = useMemo(
    () => ({ themeId, setThemeId, hex: current.hex, surfaces }),
    [themeId, current.hex, surfaces],
  );

  return (
    <ThemeContext.Provider value={value}>
      <ConfigProvider
        locale={antdLocale}
        theme={{
          algorithm: antdTheme.defaultAlgorithm,
          token: {
            colorPrimary: current.hex,
            colorInfo: current.hex,
            colorLink: current.hex,
            colorText: "#1f2937",
            colorTextSecondary: "#6b7280",
            colorTextHeading: "#111827",
            colorBgLayout: surfaces.pageBg,
            colorBgBase: "#ffffff",
            colorBgContainer: "#ffffff",
            colorSplit: "rgba(15, 23, 42, 0.28)",
            colorBorderSecondary: "#e5e7eb",
            borderRadius: 8,
            fontFamily: '"Inter", "Segoe UI", system-ui, -apple-system, sans-serif',
            fontSize: 14,
          },
          components: {
            Layout: {
              headerBg: surfaces.headerBg,
              headerColor: surfaces.onHeader,
              bodyBg: surfaces.pageBg,
              siderBg: surfaces.siderTo,
            },
            Button: {
              controlHeight: 32,
              borderRadius: 8,
              fontWeight: 500,
              primaryShadow: "none",
              defaultShadow: "none",
            },
            Table: {
              headerBg: "#f6f7f9",
              headerColor: "#4b5563",
              headerSplitColor: "transparent",
              rowHoverBg: "#f9fafb",
              cellPaddingBlock: 11,
              cellPaddingInline: 14,
            },
            Card: {
              headerFontSize: 15,
              headerHeight: 46,
              borderRadiusLG: 10,
            },
            Tabs: {
              itemColor: "#6b7280",
              itemSelectedColor: current.hex,
              itemHoverColor: current.hex,
              inkBarColor: current.hex,
              titleFontSize: 14,
            },
            Modal: {
              titleFontSize: 16,
              borderRadiusLG: 10,
            },
          },
        }}
      >
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  );
}
