import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { getLocale, setLocale as setStoredLocale, subscribeLocale, t as translate } from "./index";
import type { Locale, TFunction } from "./types";

type LocaleContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: TFunction;
};

const LocaleContext = createContext<LocaleContextValue>({
  locale: "zh-CN",
  setLocale: () => undefined,
  t: translate,
});

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(getLocale);

  useEffect(() => subscribeLocale(() => setLocaleState(getLocale())), []);

  const value = useMemo<LocaleContextValue>(
    () => ({
      locale,
      setLocale: setStoredLocale,
      t: translate,
    }),
    [locale],
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useI18n() {
  return useContext(LocaleContext);
}
