import { AlertTriangle, Info, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from './button'
import { ConfirmDestructive } from './confirm-destructive'

/**
 * The account's state in this app (docs/plans/rollback-protection.md), under
 * the header:
 * - `blocked`: the server showed an older history, or another one, than
 *   this app knows. Changes to contacts, labels, saved keys and the like
 *   stop until the person decides; "Continue with the server's data" asks
 *   once more, since a restore from a backup looks the same as an attack.
 * - `tooOld`: this app had not been used for so long that its history could
 *   not be checked; it now follows the server. A notice, dismissable.
 */
export function HeadStateBanner({
  state,
  onContinue,
  onDismiss,
}: {
  state: { kind: 'blocked'; reason: 'rollback' | 'fork' } | { kind: 'tooOld' } | null
  /** Re-anchors on the server's history; rejects when that failed. */
  onContinue: () => Promise<void>
  onDismiss: () => void
}) {
  const { t } = useTranslation()
  const [confirming, setConfirming] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)
  if (!state) return null

  if (state.kind === 'tooOld') {
    return (
      <div className="flex items-start gap-2.5 border-b border-border bg-muted/60 px-4 py-2.5 text-sm md:px-8">
        <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <p className="min-w-0 flex-1">{t('accountHead.tooOld')}</p>
        <Button variant="ghost" size="icon" className="-my-1 size-7" aria-label={t('accountHead.dismiss')} onClick={onDismiss}>
          <X />
        </Button>
      </div>
    )
  }

  return (
    <div role="alert" className="flex flex-wrap items-start gap-x-3 gap-y-2 border-b border-status-warn bg-status-warn/10 px-4 py-3 text-sm md:px-8">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-status-warn" aria-hidden />
      <div className="min-w-0 flex-1 space-y-1">
        <p className="font-medium">{t('accountHead.blockedTitle')}</p>
        <p className="text-muted-foreground">{t('accountHead.blockedBody')}</p>
      </div>
      <Button variant="outline" size="sm" onClick={() => setConfirming(true)}>
        {t('accountHead.continue')}
      </Button>
      <ConfirmDestructive
        open={confirming}
        onOpenChange={(open) => {
          setConfirming(open)
          if (!open) setError(null)
        }}
        title={t('accountHead.confirmTitle')}
        description={t('accountHead.confirmBody')}
        warning={t(state.reason === 'fork' ? 'accountHead.forkDetail' : 'accountHead.rollbackDetail')}
        warningVariant="warn"
        submit={t('accountHead.continue')}
        pending={pending}
        error={error}
        errorFallback={t('accountHead.continueFailed')}
        onConfirm={() => {
          setPending(true)
          setError(null)
          onContinue()
            .then(() => setConfirming(false))
            .catch((failure: unknown) => setError(failure))
            .finally(() => setPending(false))
        }}
      />
    </div>
  )
}
