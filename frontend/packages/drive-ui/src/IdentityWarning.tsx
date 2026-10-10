import { ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAcceptIdentity, useIdentityStatus } from '@kutup/drive-core/identityStatus'
import type { ClaimedKeys, IdentityNotConfirmed } from '@kutup/drive-core/identityPins'
import { personOf, usePeople } from '@kutup/drive-core/people'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'

// What Drive says when it cannot vouch for who someone is
// (docs/plans/drive-identity-pins.md): their keys are not signed by their
// account, or their account is not the one met before. Drive warns; it does
// not refuse (decided 2026-10-10, as Proton Drive does).

/** A red shield beside a person, when their identity is in doubt; nothing otherwise. */
export function IdentityWarningIcon({ account, claimed }: { account: string | null | undefined; claimed?: ClaimedKeys }) {
  const { t } = useTranslation()
  const status = useIdentityStatus(account, claimed)
  const people = usePeople()
  const kind = status.data?.kind
  if (!account || (kind !== 'changed' && kind !== 'invalid')) return null
  const name = personOf(people.data, account).name
  const label = t(`identityCheck.${kind}.title`, { name })
  return (
    <span role="img" aria-label={label} title={label} data-testid="identity-warning" className="inline-flex shrink-0 text-destructive">
      <ShieldAlert className="size-4" aria-hidden />
    </span>
  )
}

/** Above a file or folder someone shared: why it may not be from who it says, and what to do. */
export function IdentityBanner({ account, claimed }: { account: string | null | undefined; claimed?: ClaimedKeys }) {
  const { t } = useTranslation()
  const status = useIdentityStatus(account, claimed)
  const accept = useAcceptIdentity()
  const people = usePeople()
  const kind = status.data?.kind
  if (!account || (kind !== 'changed' && kind !== 'invalid')) return null
  const name = personOf(people.data, account).name
  return (
    <div role="alert" data-testid="identity-banner" className="flex shrink-0 flex-wrap items-start gap-x-3 gap-y-2 border-b border-destructive/30 bg-destructive/10 px-3 py-2 text-sm">
      <ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden />
      <p className="min-w-0 flex-1">
        <span className="font-medium">{t(`identityCheck.${kind}.title`, { name })}</span>{' '}
        <span className="text-muted-foreground">{t(`identityCheck.${kind}.body`, { account })}</span>
      </p>
      {kind === 'changed' ? (
        <Button size="sm" variant="outline" loading={accept.isPending} onClick={() => accept.mutate(account)}>
          {t('identityCheck.accept')}
        </Button>
      ) : null}
      {accept.isError ? <p className="w-full text-xs text-destructive">{t('identityCheck.acceptFailed')}</p> : null}
    </div>
  )
}

/**
 * In a share dialog, when sharing stopped because the recipient's identity
 * is in doubt: why, and the choice to share anyway.
 */
export function IdentityShareWarning({ error, onShareAnyway }: { error: IdentityNotConfirmed; onShareAnyway: () => void }) {
  const { t } = useTranslation()
  const people = usePeople()
  const name = personOf(people.data, error.account).name
  return (
    <Alert variant="error" title={t(`identityCheck.${error.status.kind}.title`, { name })}>
      <p>{t(`identityCheck.${error.status.kind}.shareBody`, { account: error.account })}</p>
      <Button className="mt-2" size="sm" variant="outline" onClick={onShareAnyway} data-testid="identity-share-anyway">
        {t('identityCheck.shareAnyway')}
      </Button>
    </Alert>
  )
}
