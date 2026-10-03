import { describe, expect, it } from 'vitest'
import { mergeMessages } from '@kutup/i18n'
import { checkLocales } from '@kutup/i18n/testing'
import sharedEn from '@kutup/i18n/locales/en.json'
import sharedTr from '@kutup/i18n/locales/tr.json'
import en from './locales/en.json'
import tr from './locales/tr.json'

describe('locales', () => {
  it('define every key the app uses, identically in en and tr, none empty', () => {
    const report = checkLocales({
      en: mergeMessages(sharedEn, en),
      tr: mergeMessages(sharedTr, tr),
      sourceDirs: [__dirname],
    })
    expect(report).toEqual({ onlyInEn: [], onlyInTr: [], empty: [], missing: [] })
  })
})
