import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useSendForwardingCode, useVerifyForwarding, type MailForwarding } from '@kutup/mail-core/forwardings'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Field } from '@kutup/ui/components/field'
import { Input } from '@kutup/ui/components/input'
import { formatInstant } from '@kutup/ui/lib/format'
import { forwardingErrorMessage } from './forwardingText'

/** What the server's answer to a code says, as the dialog shows it. */
function codeProblem(error: unknown): { code: string; attemptsLeft?: number } | null {
  const data = (error as { response?: { data?: { code?: unknown; attemptsLeft?: unknown } } }).response?.data
  if (typeof data?.code !== 'string') return null
  return { code: data.code, attemptsLeft: typeof data.attemptsLeft === 'number' ? data.attemptsLeft : undefined }
}

/**
 * The forwarding's verification: the 6-digit code mailed to the destination
 * (docs/plans/mail-forwarding.md, "Verification"). Nothing is forwarded
 * before it is entered; a new code can be sent, the last one then void.
 */
export function ForwardingCodeDialog({ forwarding, onClose }: { forwarding: MailForwarding; onClose: () => void }) {
  const { t, i18n } = useTranslation()
  const verify = useVerifyForwarding()
  const resend = useSendForwardingCode()
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [shown, setShown] = useState(forwarding)
  const wellFormed = /^\d{6}$/.test(code)

  function submit() {
    if (!wellFormed) return setError(t('forwarding.code.sixDigits'))
    setError(null)
    verify.mutate(
      { id: forwarding.id, code },
      {
        onSuccess: (done) => {
          toast.success(t(done.kind === 'outside' ? 'forwarding.code.verifiedOutside' : 'forwarding.code.verified', { to: done.forwardeeEmail }))
          onClose()
        },
        onError: (e) => {
          const problem = codeProblem(e)
          setCode('')
          if (problem?.code === 'codeWrong') setError(t('forwarding.code.wrong', { count: problem.attemptsLeft ?? 0 }))
          else if (problem?.code === 'codeVoid') setError(t('forwarding.code.void'))
          else if (problem?.code === 'codeExpired') setError(t('forwarding.code.expired'))
          else setError(forwardingErrorMessage(e, t))
        },
      },
    )
  }

  function sendAgain() {
    setError(null)
    resend.mutate(forwarding.id, {
      onSuccess: (now) => {
        setShown(now)
        setCode('')
        toast.success(t('forwarding.code.sent', { to: forwarding.forwardeeEmail }))
      },
      onError: (e) => setError(codeProblem(e)?.code === 'rateLimited' ? t('forwarding.code.tooSoon') : forwardingErrorMessage(e, t)),
    })
  }

  const busy = verify.isPending || resend.isPending
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent data-testid="forwarding-code-dialog">
        <DialogHeader>
          <DialogTitle>{t('forwarding.code.title')}</DialogTitle>
          <DialogDescription>{t('forwarding.code.description', { to: forwarding.forwardeeEmail })}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <Field
            label={t('forwarding.code.label')}
            description={
              shown.codeExpiresAt
                ? t('forwarding.code.expiresAt', { time: formatInstant(shown.codeExpiresAt, i18n.language) ?? '' })
                : t('forwarding.code.noLiveCode')
            }
          >
            {(props) => (
              <Input
                {...props}
                value={code}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                autoFocus
                className="w-40 font-mono tracking-widest"
                onChange={(e) => {
                  setCode(e.target.value.replace(/\D/g, '').slice(0, 6))
                  setError(null)
                }}
              />
            )}
          </Field>
          {error ? (
            <Alert variant="error" data-testid="forwarding-code-error">
              {error}
            </Alert>
          ) : null}
          <DialogFooter className="gap-2 sm:justify-between">
            <Button type="button" variant="ghost" onClick={sendAgain} loading={resend.isPending} disabled={busy}>
              {t('forwarding.code.sendAgain')}
            </Button>
            <div className="flex gap-2">
              <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
                {t('forwarding.code.later')}
              </Button>
              <Button type="submit" loading={verify.isPending} disabled={busy || !wellFormed}>
                {t('forwarding.code.verify')}
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
