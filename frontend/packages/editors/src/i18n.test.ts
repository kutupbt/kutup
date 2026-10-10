import { describe, expect, it } from 'vitest'
import { mergeMessages } from '@kutup/i18n'
import { checkLocales } from '@kutup/i18n/testing'
import sharedEn from '@kutup/i18n/locales/en.json'
import sharedTr from '@kutup/i18n/locales/tr.json'
import driveEn from '../../../apps/drive/src/locales/en.json'
import driveTr from '../../../apps/drive/src/locales/tr.json'
import officeEn from '../../../apps/office/src/locales/en.json'
import officeTr from '../../../apps/office/src/locales/tr.json'
import en from './locales/en.json'
import tr from './locales/tr.json'

// The file page runs in Drive and in Office: every key it asks for must be
// there in both, as each app's main.tsx merges the messages.
describe.each([
  ['Drive', driveEn, driveTr],
  ['Office', officeEn, officeTr],
])('the file page in %s', (_app, appEn, appTr) => {
  it('finds every key it uses, identically in en and tr, none empty', () => {
    const report = checkLocales({
      en: mergeMessages(mergeMessages(sharedEn, appEn), en),
      tr: mergeMessages(mergeMessages(sharedTr, appTr), tr),
      sourceDirs: [__dirname],
    })
    expect(report).toEqual({ onlyInEn: [], onlyInTr: [], empty: [], missing: [] })
  })
})
