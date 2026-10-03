import i18n from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'
import sharedEn from './locales/en.json'
import sharedTr from './locales/tr.json'

/**
 * Every user-facing string lives in en.json AND tr.json, added in the same
 * change (see `checkLocales` in ./testing). Shared strings (common actions,
 * the app shell, theme and language controls) live here; each app merges in
 * its own feature namespaces.
 */
export type Messages = { [key: string]: string | Messages }

export const SUPPORTED_LANGUAGES = ['en', 'tr'] as const
export type Language = (typeof SUPPORTED_LANGUAGES)[number]

/** Stored per origin; the account app's language setting writes the same key. */
export const LANGUAGE_STORAGE_KEY = 'kutup-lang'

export function mergeMessages(base: Messages, extra: Messages): Messages {
  const out: Messages = { ...base }
  for (const [key, value] of Object.entries(extra)) {
    const existing = out[key]
    if (typeof value === 'object' && typeof existing === 'object') {
      out[key] = mergeMessages(existing, value)
    } else if (existing !== undefined) {
      throw new Error(`locale key "${key}" is defined by both the shared and the app messages`)
    } else {
      out[key] = value
    }
  }
  return out
}

export function initI18n(app: { en: Messages; tr: Messages }) {
  void i18n
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      resources: {
        en: { translation: mergeMessages(sharedEn, app.en) },
        tr: { translation: mergeMessages(sharedTr, app.tr) },
      },
      fallbackLng: 'en',
      supportedLngs: [...SUPPORTED_LANGUAGES],
      interpolation: { escapeValue: false },
      detection: {
        order: ['localStorage', 'navigator'],
        lookupLocalStorage: LANGUAGE_STORAGE_KEY,
        caches: ['localStorage'],
      },
    })
  i18n.on('languageChanged', (lng) => {
    document.documentElement.lang = lng
  })
  return i18n
}

export { i18n }
