import { Tooltip } from "antd";
import { useI18n } from "../i18n/LocaleContext";
import { THEMES } from "../theme/themes";
import { useAppTheme } from "../theme/ThemeContext";

export default function ThemeSwitcher({ compact = false }: { compact?: boolean }) {
  const { themeId, setThemeId } = useAppTheme();
  const { t } = useI18n();

  return (
    <div className="theme-switcher" aria-label={t("theme.aria")}>
      {!compact && <span className="theme-switcher-label">{t("theme.label")}</span>}
      {THEMES.map((item) => {
        const name = t(`theme.${item.id}`);
        return (
          <Tooltip key={item.id} title={`${name} ${item.hex}`}>
            <button
              type="button"
              className={`theme-dot${themeId === item.id ? " is-active" : ""}`}
              style={{ background: item.hex }}
              aria-label={name}
              aria-pressed={themeId === item.id}
              onClick={() => setThemeId(item.id)}
            />
          </Tooltip>
        );
      })}
    </div>
  );
}
