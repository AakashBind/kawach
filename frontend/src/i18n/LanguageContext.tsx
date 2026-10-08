import React, { createContext, useContext, useState, useEffect, useMemo, ReactNode } from 'react';
import { Language, LanguageOption, Translations } from './types';
import { en } from './locales/en';
import { hi } from './locales/hi';
import { mr } from './locales/mr';
import { de } from './locales/de';

export const SUPPORTED_LANGUAGES: LanguageOption[] = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'hi', name: 'Hindi', nativeName: 'हिन्दी' },
  { code: 'mr', name: 'Marathi', nativeName: 'मराठी' },
  { code: 'de', name: 'German', nativeName: 'Deutsch' },
];

const LOCAL_STORAGE_KEY = 'scamshield_preferred_lang';

const LOCALE_MAP: Record<Language, Translations> = {
  en,
  hi,
  mr,
  de,
};

function detectInitialLanguage(): Language {
  // 1. Saved user preference
  try {
    const saved = localStorage.getItem(LOCAL_STORAGE_KEY) as Language | null;
    if (saved && (saved === 'en' || saved === 'hi' || saved === 'mr' || saved === 'de')) {
      return saved;
    }
  } catch {}

  // 2. Browser language detection
  try {
    const browserLangs = navigator.languages || [navigator.language || 'en'];
    for (const lang of browserLangs) {
      const lower = lang.toLowerCase();
      if (lower.startsWith('hi')) return 'hi';
      if (lower.startsWith('mr')) return 'mr';
      if (lower.startsWith('de')) return 'de';
      if (lower.startsWith('en')) return 'en';
    }
  } catch {}

  // 3. Fallback to English
  return 'en';
}

function getNestedTranslation(obj: any, path: string): string | undefined {
  const parts = path.split('.');
  let curr = obj;
  for (const part of parts) {
    if (curr === undefined || curr === null) return undefined;
    curr = curr[part];
  }
  return typeof curr === 'string' ? curr : undefined;
}

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string, params?: Record<string, string | number>) => string;
  translations: Translations;
  languages: LanguageOption[];
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [language, setLanguageState] = useState<Language>(detectInitialLanguage);

  const setLanguage = (lang: Language) => {
    if (LOCALE_MAP[lang]) {
      setLanguageState(lang);
      try {
        localStorage.setItem(LOCAL_STORAGE_KEY, lang);
      } catch {}
    }
  };

  useEffect(() => {
    // Keep document.documentElement.lang synchronized
    document.documentElement.lang = language;
  }, [language]);

  const activeTranslations = useMemo(() => LOCALE_MAP[language] || en, [language]);

  const t = (key: string, params?: Record<string, string | number>): string => {
    // Look up in selected language first, then fallback to English, then return key itself
    let text = getNestedTranslation(activeTranslations, key);
    if (!text) {
      text = getNestedTranslation(en, key) || key;
    }

    if (params) {
      for (const [pKey, pVal] of Object.entries(params)) {
        text = text.replace(new RegExp(`\\{\\{?${pKey}\\}?\\}`, 'g'), String(pVal));
      }
    }
    return text;
  };

  return (
    <LanguageContext.Provider
      value={{
        language,
        setLanguage,
        t,
        translations: activeTranslations,
        languages: SUPPORTED_LANGUAGES,
      }}
    >
      {children}
    </LanguageContext.Provider>
  );
};

export const useTranslation = () => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useTranslation must be used within a LanguageProvider');
  }
  return context;
};

export const useLanguage = useTranslation;
