import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import {
  I18nContext,
  detectInitialLocale,
  setCurrentLocale,
  translate,
  type I18nContextValue,
  type Locale,
} from "@/lib/i18n";

function normalizeLocale(value: string | null | undefined): Locale {
  return value === "ja" ? "ja" : "en";
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectInitialLocale);

  useEffect(() => {
    setCurrentLocale(locale);
    if (typeof globalThis.localStorage !== "undefined") {
      globalThis.localStorage.setItem("tukuyomi_admin_locale", locale);
    }
    if (typeof document !== "undefined") {
      document.documentElement.lang = locale === "ja" ? "ja" : "en";
      document.documentElement.dataset.locale = locale;
      document.body.dataset.locale = locale;
    }
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(normalizeLocale(next));
  }, []);

  const tx = useCallback((key: string, vars?: Record<string, string | number | boolean | null | undefined>) => translate(locale, key, vars), [locale]);

  const value = useMemo<I18nContextValue>(() => ({ locale, setLocale, tx }), [locale, setLocale, tx]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
