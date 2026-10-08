// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { LANGUAGE_STORAGE_KEY, initI18n } from './index'

describe('initI18n', () => {
  it("sets the page's language to the one detected at start, and follows changes", async () => {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, 'tr')
    const i18n = initI18n({ en: {}, tr: {} })
    expect(document.documentElement.lang).toBe('tr')
    await i18n.changeLanguage('en')
    expect(document.documentElement.lang).toBe('en')
  })
})
