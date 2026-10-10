import { describe, expect, it } from 'vitest'
import { mergeMessages } from '@kutup/i18n'
import { checkLocales } from '@kutup/i18n/testing'
import sharedEn from '@kutup/i18n/locales/en.json'
import sharedTr from '@kutup/i18n/locales/tr.json'
import en from './locales/en.json'
import tr from './locales/tr.json'
import editorsEn from '@kutup/editors/locales/en.json'
import editorsTr from '@kutup/editors/locales/tr.json'

describe('locales', () => {
  it('define every key the app uses, identically in en and tr, none empty', () => {
    const report = checkLocales({
      // As main.tsx loads them: the file page's strings too.
      en: mergeMessages(mergeMessages(sharedEn, en), editorsEn),
      tr: mergeMessages(mergeMessages(sharedTr, tr), editorsTr),
      sourceDirs: [__dirname],
    })
    expect(report).toEqual({ onlyInEn: [], onlyInTr: [], empty: [], missing: [] })
  })
})
