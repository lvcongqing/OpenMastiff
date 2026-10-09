import { LOCALES } from "../i18n";
import { useI18n } from "../i18n/LocaleContext";

export default function LanguageSwitcher({ compact = false }: { compact?: boolean }) {
  const { locale, setLocale, t } = useI18n();

  return (
    <div className="lang-switcher" role="group" aria-label={t("lang.label")}>
      {!compact ? <span className="lang-switcher-label">{t("lang.label")}</span> : null}
      {LOCALES.map((item) => (
        <button
          key={item.id}
          type="button"
          className={locale === item.id ? "is-active" : ""}
          aria-pressed={locale === item.id}
          aria-label={item.name}
          onClick={() => setLocale(item.id)}
        >
          {item.short}
        </button>
      ))}
    </div>
  );
}
