import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import api from '@kutup/session/client'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Checkbox } from '@kutup/ui/components/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Label } from '@kutup/ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@kutup/ui/components/select'
import { Textarea } from '@kutup/ui/components/textarea'

const REASONS = ['phishing', 'malware', 'illegal', 'abuse', 'other'] as const
type Reason = (typeof REASONS)[number]

/** The server's limit on what a reporter may write (link_reports.rs). */
const MAX_DETAILS = 2000

/**
 * Report a public link to the server's administrators, without an account.
 * They cannot see what an end-to-end encrypted link shows unless the
 * reporter hands them the whole link, key included: offered, and on.
 */
export function ReportLinkDialog({ token, open, onClose }: { token: string; open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  const [reason, setReason] = useState<Reason | null>(null)
  const [details, setDetails] = useState('')
  const [shareLink, setShareLink] = useState(true)
  const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | 'failed'>('idle')

  function send() {
    setStatus('sending')
    api
      .post(`/share/${encodeURIComponent(token)}/report`, {
        reason,
        details: details.trim(),
        link: shareLink ? window.location.href : null,
      })
      .then(() => setStatus('sent'), () => setStatus('failed'))
  }

  function close() {
    onClose()
    // Fresh for the next report, once the dialog has gone.
    setTimeout(() => {
      setReason(null)
      setDetails('')
      setShareLink(true)
      setStatus('idle')
    }, 200)
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('reportLink.title')}</DialogTitle>
          <DialogDescription>{t('reportLink.description')}</DialogDescription>
        </DialogHeader>
        {status === 'sent' ? (
          <>
            <Alert variant="info" title={t('reportLink.sentTitle')}>
              {t('reportLink.sent')}
            </Alert>
            <DialogFooter>
              <Button onClick={close}>{t('common.close')}</Button>
            </DialogFooter>
          </>
        ) : (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              if (reason && status !== 'sending') send()
            }}
          >
            <Field label={t('reportLink.reason')} required>
              {(props) => (
                <Select value={reason ?? undefined} onValueChange={(v) => setReason(v as Reason)}>
                  <SelectTrigger {...props} data-testid="report-reason">
                    <SelectValue placeholder={t('reportLink.choose')} />
                  </SelectTrigger>
                  <SelectContent>
                    {REASONS.map((r) => (
                      <SelectItem key={r} value={r}>
                        {t(`reportLink.reasons.${r}`)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </Field>
            <Field label={t('reportLink.details')} description={t('reportLink.detailsHint')}>
              {(props) => (
                <Textarea {...props} value={details} maxLength={MAX_DETAILS} rows={3} onChange={(e) => setDetails(e.target.value)} />
              )}
            </Field>
            <div className="flex items-start gap-2">
              <Checkbox id="report-share-link" checked={shareLink} onCheckedChange={(v) => setShareLink(v === true)} />
              <div>
                <Label htmlFor="report-share-link">{t('reportLink.shareLink')}</Label>
                <p className="text-xs text-muted-foreground">{t('reportLink.shareLinkHint')}</p>
              </div>
            </div>
            {status === 'failed' ? <Alert variant="error">{t('reportLink.failed')}</Alert> : null}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={!reason} loading={status === 'sending'}>
                {t('reportLink.send')}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
