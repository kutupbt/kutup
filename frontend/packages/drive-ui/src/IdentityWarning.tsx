import { Shield, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useAcceptIdentity, useIdentityStatus, usePersonSafetyNumber, useVerifyPerson } from '@kutup/drive-core/identityStatus'
import { IdentityKnownElsewhere, IdentityUnproven, type ClaimedKeys, type IdentityNotConfirmed, type RecipientRenamed } from '@kutup/drive-core/identityPins'
import { personOf, usePeople } from '@kutup/drive-core/people'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { LoadingPanel } from '@kutup/ui/components/states'
import { SafetyVerificationDialog } from '@kutup/ui/components/safety-verification'

// What Drive says when it cannot vouch for who someone is
// (docs/plans/drive-identity-pins.md): their keys are not signed by their
// account, or their account is not the one met before. Drive warns; it does
// not refuse (decided 2026-10-10, as Proton Drive does).

/** A shield beside a person: red when their identity is in doubt, green when verified, nothing otherwise. */
export function IdentityWarningIcon({ account, claimed }: { account: string | null | undefined; claimed?: ClaimedKeys }) {
  const { t } = useTranslation()
  const status = useIdentityStatus(account, claimed)
  const people = usePeople()
  const kind = status.data?.kind
  if (!account) return null
  const name = personOf(people.data, account).name
  if (status.data?.kind === 'ok' && status.data.verified) {
    const label = t('identityCheck.verified', { name })
    return (
      <span role="img" aria-label={label} title={label} data-testid="identity-verified" className="inline-flex shrink-0 text-status-ok">
        <ShieldCheck className="size-4" aria-hidden />
      </span>
    )
  }
  if (kind !== 'changed' && kind !== 'invalid') return null
  const label = t(`identityCheck.${kind}.title`, { name })
  return (
    <span role="img" aria-label={label} title={label} data-testid="identity-warning" className="inline-flex shrink-0 text-destructive">
      <ShieldAlert className="size-4" aria-hidden />
    </span>
  )
}

/**
 * Compare the safety number with `account` in person (the same one Chat
 * shows): scanning theirs marks them verified in every app, and accepts a
 * changed identity.
 */
export function VerifyPersonDialog({
  account,
  claimed,
  open,
  onOpenChange,
}: {
  account: string
  claimed?: ClaimedKeys
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const status = useIdentityStatus(account, claimed)
  const number = usePersonSafetyNumber(account, open)
  const verify = useVerifyPerson()
  if (!open) return null
  if (!number.data) {
    // Still looking the person up, or the lookup failed: said inside a
    // dialog, never silently.
    const unproven = number.error instanceof IdentityUnproven
    return (
      <Dialog open onOpenChange={onOpenChange}>
        <DialogContent className="max-w-md" data-testid="drive-safety-pending">
          <DialogHeader>
            <DialogTitle className="break-all">{t('safetyNumber.title', { peer: account })}</DialogTitle>
            <DialogDescription>{t('safetyNumber.description')}</DialogDescription>
          </DialogHeader>
          {number.isError ? (
            <Alert variant="error" title={unproven ? t('identityCheck.cannotVerifyTitle') : t('identityCheck.lookupFailedTitle')}>
              <p>{unproven ? t('identityCheck.cannotVerify', { account }) : t('identityCheck.lookupFailed')}</p>
              {unproven ? null : (
                <Button className="mt-2" size="sm" variant="outline" onClick={() => void number.refetch()}>
                  {t('common.retry')}
                </Button>
              )}
            </Alert>
          ) : (
            <LoadingPanel label={t('common.loading')} />
          )}
        </DialogContent>
      </Dialog>
    )
  }
  const kind = status.data?.kind
  return (
    <SafetyVerificationDialog
      peer={account}
      open={open}
      onOpenChange={onOpenChange}
      testIdPrefix="drive-safety"
      safety={{
        fingerprint: number.data.fingerprint,
        qrPayload: number.data.qrPayload,
        state: kind === 'changed' || kind === 'invalid' ? 'blocked' : kind === 'ok' && status.data?.kind === 'ok' && status.data.verified ? 'verified' : 'unverified',
        canVerifyBlocked: kind === 'changed',
      }}
      onVerify={(scanned) => verify.mutateAsync({ account, scanned })}
    />
  )
}

/** A shield beside a person that opens their verification: gray, green when verified, red in doubt. */
export function VerifyPersonButton({ account, claimed }: { account: string; claimed?: ClaimedKeys }) {
  const { t } = useTranslation()
  const status = useIdentityStatus(account, claimed)
  const people = usePeople()
  const [open, setOpen] = useState(false)
  const name = personOf(people.data, account).name
  const kind = status.data?.kind
  const verified = kind === 'ok' && status.data?.kind === 'ok' && status.data.verified
  const doubt = kind === 'changed' || kind === 'invalid'
  const formerly = status.data?.kind === 'ok' ? status.data.formerly : undefined
  const label = formerlyLabel(
    t,
    doubt ? t(`identityCheck.${kind}.title`, { name }) : verified ? t('identityCheck.verified', { name }) : t('identityCheck.verify', { name }),
    formerly,
  )
  return (
    <>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-7 shrink-0"
        title={label}
        aria-label={label}
        data-testid="identity-verify-open"
        onClick={() => setOpen(true)}
      >
        {doubt ? <ShieldAlert className="text-destructive" /> : verified ? <ShieldCheck className="text-status-ok" /> : <Shield className="text-muted-foreground" />}
      </Button>
      <VerifyPersonDialog account={account} claimed={claimed} open={open} onOpenChange={setOpen} />
    </>
  )
}

/** `label`, with the address the person had before their newest rename. */
export function formerlyLabel(t: (key: string, values?: Record<string, string>) => string, label: string, formerly: string | undefined): string {
  return formerly ? `${label} (${t('identityCheck.renamed.formerly', { formerly })})` : label
}

/** Above a file or folder someone shared: why it may not be from who it says, and what to do. */
export function IdentityBanner({ account, claimed }: { account: string | null | undefined; claimed?: ClaimedKeys }) {
  const { t } = useTranslation()
  const status = useIdentityStatus(account, claimed)
  const accept = useAcceptIdentity()
  const people = usePeople()
  const [verifying, setVerifying] = useState(false)
  const kind = status.data?.kind
  if (account && status.data?.kind === 'renamed') {
    // Shared under a name its person has left: who they are now.
    const now = status.data.now
    return (
      <div role="status" data-testid="identity-renamed" className="flex shrink-0 items-start gap-3 border-b border-border bg-muted px-3 py-2 text-sm">
        <Shield className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <p className="min-w-0 flex-1">{t('identityCheck.renamed.banner', { name: personOf(people.data, now).name, now, account })}</p>
      </div>
    )
  }
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
        <>
          <Button size="sm" variant="outline" onClick={() => setVerifying(true)}>
            {t('identityCheck.verifyInPerson')}
          </Button>
          <Button size="sm" variant="ghost" loading={accept.isPending} onClick={() => accept.mutate(account)}>
            {t('identityCheck.accept')}
          </Button>
          <VerifyPersonDialog account={account} claimed={claimed} open={verifying} onOpenChange={setVerifying} />
        </>
      ) : null}
      {accept.error instanceof IdentityKnownElsewhere ? (
        <p className="w-full text-xs text-destructive">{t('identityCheck.knownElsewhere', { other: accept.error.other })}</p>
      ) : accept.isError ? (
        <p className="w-full text-xs text-destructive">{t('identityCheck.acceptFailed')}</p>
      ) : null}
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

/**
 * In a share dialog, when the address typed is a name its person left
 * (docs/plans/username-renames.md): where they are now, and the choice to
 * share with them there.
 */
export function RecipientRenamedNotice({ error, onUseNow }: { error: RecipientRenamed; onUseNow: (now: string) => void }) {
  const { t } = useTranslation()
  return (
    <div data-testid="recipient-renamed">
      <Alert variant="info">
        <p>{t('identityCheck.renamed.share', { account: error.account, now: error.now })}</p>
        <Button className="mt-2" size="sm" variant="outline" onClick={() => onUseNow(error.now)}>
          {t('identityCheck.renamed.useNow', { now: error.now })}
        </Button>
      </Alert>
    </div>
  )
}
