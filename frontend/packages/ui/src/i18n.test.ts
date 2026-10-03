import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { checkLocales } from '@kutup/i18n/testing'
import en from '@kutup/i18n/locales/en.json'
import tr from '@kutup/i18n/locales/tr.json'

describe('shared locales', () => {
  it('cover every key the ui package uses, in both languages', () => {
    const report = checkLocales({ en, tr, sourceDirs: [join(__dirname)] })
    expect(report).toEqual({ onlyInEn: [], onlyInTr: [], empty: [], missing: [] })
  })
})
