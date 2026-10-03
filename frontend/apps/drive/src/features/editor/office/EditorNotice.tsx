// SPDX-License-Identifier: AGPL-3.0-or-later
// Part of Kutup's client-side OnlyOffice integration (see ./LICENSE.md).

import { Info } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { appUrl } from '@kutup/session/apps'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@kutup/ui/components/dialog'

const EDITOR_SOURCE = 'https://github.com/kutupbt/onlyoffice-editor'
const CONVERTER_SOURCE = 'https://github.com/kutupbt/onlyoffice-x2t-wasm'

/**
 * The editor's Appropriate Legal Notices, always one click away in the office
 * editor's header. ONLYOFFICE's additional terms (its LICENSE, from 9.4) ask
 * that the interface identify ONLYOFFICE as the original developer, say the
 * version may be modified, and give access to the licence; AGPL §13 asks
 * for the source of what people use over the network.
 */
export function EditorNotice() {
  const { t } = useTranslation()
  const licence = appUrl('office', '/onlyoffice/LICENSE.md')
  const terms = appUrl('office', '/onlyoffice/ONLYOFFICE-ADDITIONAL-TERMS.md')
  const link = 'font-medium text-primary underline underline-offset-2 hover:no-underline'
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" title={t('editor.office.about.open')} aria-label={t('editor.office.about.open')}>
          <Info />
          <span className="hidden text-xs md:inline">ONLYOFFICE</span>
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('editor.office.about.title')}</DialogTitle>
          <DialogDescription>{t('editor.office.about.developer')}</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 text-sm">
          <p>{t('editor.office.about.modified')}</p>
          <p>{t('editor.office.about.licence')}</p>
          <ul className="space-y-1.5">
            <li>
              <a className={link} href={licence} target="_blank" rel="noreferrer">
                {t('editor.office.about.licenceLink')}
              </a>
            </li>
            <li>
              <a className={link} href={terms} target="_blank" rel="noreferrer">
                {t('editor.office.about.termsLink')}
              </a>
            </li>
            <li>
              <a className={link} href={EDITOR_SOURCE} target="_blank" rel="noreferrer">
                {t('editor.office.about.editorSource')}
              </a>
            </li>
            <li>
              <a className={link} href={CONVERTER_SOURCE} target="_blank" rel="noreferrer">
                {t('editor.office.about.converterSource')}
              </a>
            </li>
          </ul>
          <p className="text-xs text-muted-foreground">{t('editor.office.about.trademark')}</p>
        </div>
      </DialogContent>
    </Dialog>
  )
}
