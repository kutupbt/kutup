import { Flag, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { ReportLinkDialog } from './ReportLinkDialog'

/**
 * What a public link's page says above its content: who shared it, that
 * nobody checked it, and a way to report it. The page is on Kutup's own
 * address, so a link must not pass off what someone put in it (a "sign in"
 * form, a payment request) as Kutup's own.
 */
export function PublicNotice({ owner, token }: { owner: string; token: string }) {
  const { t } = useTranslation()
  const [reporting, setReporting] = useState(false)
  return (
    <div role="note" data-testid="public-notice" className="flex items-start gap-2.5 border-b border-border bg-muted/60 px-4 py-2 text-sm md:px-6">
      <ShieldAlert className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      <p className="min-w-0 flex-1">
        <span className="font-medium">{t('publicNotice.sharedBy', { owner })}</span>{' '}
        <span className="text-muted-foreground">{t('publicNotice.unchecked')}</span>
      </p>
      <Button variant="ghost" size="sm" className="-my-1 shrink-0" onClick={() => setReporting(true)}>
        <Flag /> {t('reportLink.button')}
      </Button>
      <ReportLinkDialog token={token} open={reporting} onClose={() => setReporting(false)} />
    </div>
  )
}
