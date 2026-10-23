import { AlertTriangle, Ban, Loader2, LockKeyhole, LockKeyholeOpen, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { PinnedKeys } from '@kutup/mail-core/api'
import { useProtection } from '@kutup/mail-core/protection'
import { Tooltip } from '@kutup/ui/components/tooltip'

/**
 * The lock on a recipient chip: how mail to them will be protected
 * (docs/plans/mail.md, C3), as Proton shows it while writing. Nothing for
 * mail that goes in clear.
 */
export function RecipientLock({ address, domain, pinned, encrypt = true }: { address: string; domain: string; pinned: PinnedKeys | undefined; encrypt?: boolean }) {
  const { t } = useTranslation()
  const protection = useProtection(address, domain, pinned?.(address), !!pinned)
  if (!pinned || protection.isPending) {
    return <Loader2 className="size-3 animate-spin text-muted-foreground" role="img" aria-label={t('compose.lock.looking')} />
  }
  if (protection.isError) {
    return (
      <Tooltip label={t('compose.lock.lookupFailed')}>
        <AlertTriangle className="size-3 text-muted-foreground" role="img" aria-label={t('compose.lock.lookupFailed')} />
      </Tooltip>
    )
  }
  const value = protection.data
  // Disabled by its owner: nothing can be sent to it (Proton's).
  if (value.kind === 'disabled') {
    const label = t('compose.lock.disabled')
    return (
      <Tooltip label={label}>
        <Ban className="size-3 text-destructive" role="img" aria-label={label} data-testid="recipient-disabled" />
      </Tooltip>
    )
  }
  // The address forwards outside Kutup: its owner turned end-to-end
  // encryption off for it (Proton shows the same open lock).
  if (value.kind === 'kutup' && value.encryptionDisabled) {
    const label = t('compose.lock.encryptionDisabled')
    return (
      <Tooltip label={label}>
        <LockKeyholeOpen className="size-3 text-status-warn" role="img" aria-label={label} data-testid="recipient-encryption-disabled" />
      </Tooltip>
    )
  }
  // Encrypt off for this message: whoever could have had end-to-end mail now
  // gets it readable on the way (docs/plans/mail-encrypt-sign.md).
  if (!encrypt && value.kind !== 'none' && value.kind !== 'pinnedUnusable' && value.kind !== 'pinnedConflict') {
    const label = value.kind === 'kutup' ? t('compose.lock.readableKutup') : t('compose.lock.readableOutside')
    return (
      <Tooltip label={label}>
        <LockKeyholeOpen className="size-3 text-status-warn" role="img" aria-label={label} />
      </Tooltip>
    )
  }
  const [Icon, label, tone] =
    value.kind === 'kutup'
      ? [LockKeyhole, t('compose.endToEnd'), 'text-primary']
      : value.kind === 'pinned'
        ? [ShieldCheck, t('compose.lock.pinned'), 'text-primary']
        : value.kind === 'found'
          ? [LockKeyhole, t(`compose.lock.found.${value.source}`), 'text-primary']
          : value.kind === 'pinnedUnusable'
            ? [ShieldAlert, t('compose.lock.pinnedUnusable'), 'text-destructive']
            : value.kind === 'pinnedConflict'
              ? [ShieldAlert, t('compose.lock.pinnedConflict'), 'text-destructive']
              : [null, '', '']
  if (!Icon) return null
  return (
    <Tooltip label={label}>
      <Icon className={`size-3 ${tone}`} role="img" aria-label={label} />
    </Tooltip>
  )
}
