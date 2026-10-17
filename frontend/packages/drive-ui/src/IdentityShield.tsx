import { Shield, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useIdentityStatus, useIsKutupAccount } from '@kutup/drive-core/identityStatus'
import { cn } from '@kutup/ui/lib/cn'
import { personLabel } from './personLabel'
import { VerifyPersonDialog } from './IdentityWarning'

/**
 * The shield beside a person's Kutup address in Contacts (and Mail's person
 * card): the same state Drive and Chat keep in the account's list of people
 * (docs/plans/drive-identity-pins.md). Gray until compared in person, green
 * once verified, red when the account is not the one met before or its keys
 * are not its own. It opens the safety number to compare.
 *
 * Shown only for a Kutup account: one on this server, or one already in the
 * list. An ordinary email address is never looked up.
 */
export function IdentityShield({ address, name, className }: { address: string; name?: string; className?: string }) {
  const { t } = useTranslation()
  const account = address.trim().toLowerCase()
  const kutup = useIsKutupAccount(account)
  const status = useIdentityStatus(kutup ? account : null)
  const [open, setOpen] = useState(false)
  const kind = status.data?.kind
  // Not looked at yet, or not a person with a Drive identity (an address
  // that only receives mail): nothing to say.
  if (!kutup || !kind || kind === 'unknown') return null
  const who = name || account
  const verified = (status.data?.kind === 'ok' || status.data?.kind === 'renamed') && status.data.verified
  const doubt = kind === 'changed' || kind === 'invalid' || kind === 'someoneElse'
  const state = doubt ? kind : kind === 'unproven' ? 'unproven' : verified ? 'verified' : 'unverified'
  const label = personLabel(
    t,
    doubt ? t(`identityCheck.${kind}.title`, { name: who, account }) : verified ? t('identityCheck.verified', { name: who }) : t('identityCheck.verify', { name: who }),
    status.data,
  )
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title={label}
        aria-label={label}
        data-testid="identity-shield"
        data-state={state}
        className={cn(
          'inline-flex shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium',
          'hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          doubt ? 'text-destructive' : verified ? 'text-status-ok' : 'text-muted-foreground',
          className,
        )}
      >
        {doubt ? (
          <ShieldAlert className="size-4" aria-hidden />
        ) : verified ? (
          <ShieldCheck className="size-4" aria-hidden />
        ) : kind === 'unproven' ? (
          <ShieldQuestion className="size-4" aria-hidden />
        ) : (
          <Shield className="size-4" aria-hidden />
        )}
        <span aria-hidden>{t(`identityCheck.state.${state}`)}</span>
      </button>
      <VerifyPersonDialog account={account} open={open} onOpenChange={setOpen} />
    </>
  )
}
