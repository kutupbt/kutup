import { i18n, mergeMessages } from '@kutup/i18n'
import { initReactI18next } from 'react-i18next'
import sharedEn from '@kutup/i18n/locales/en.json'
import en from '../../locales/en.json'

/**
 * Test-only: the real English messages, so assertions read the copy people
 * (and the Playwright specs) see rather than raw keys. Import it before
 * rendering; it initialises the global i18next instance once.
 */
if (!i18n.isInitialized) {
  void i18n.use(initReactI18next).init({
    resources: { en: { translation: mergeMessages(sharedEn, en) } },
    lng: 'en',
    fallbackLng: 'en',
    interpolation: { escapeValue: false },
    initAsync: false,
  })
}
