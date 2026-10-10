import { AlertTriangle, Loader2, LockKeyhole, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { PinnedKeys } from '@kutup/mail-core/api'
import { useProtection } from '@kutup/mail-core/protection'
import { Tooltip } from '@kutup/ui/components/tooltip'

/**
 * The lock on a recipient chip: how mail to them will be protected
 * (docs/plans/mail.md, C3), as Proton shows it while writing. Nothing for
 * mail that goes in clear.
 */
export function RecipientLock({ address, domain, pinned }: { address: string; domain: string; pinned: PinnedKeys | undefined }) {
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
  const [Icon, label, tone] =
    value.kind === 'kutup'
      ? [LockKeyhole, t('compose.endToEnd'), 'text-primary']
      : value.kind === 'pinned'
        ? [ShieldCheck, t('compose.lock.pinned'), 'text-primary']
        : value.kind === 'found'
          ? [LockKeyhole, t(`compose.lock.found.${value.source}`), 'text-primary']
          : value.kind === 'pinnedUnusable'
            ? [ShieldAlert, t('compose.lock.pinnedUnusable'), 'text-destructive']
            : [null, '', '']
  if (!Icon) return null
  return (
    <Tooltip label={label}>
      <Icon className={`size-3 ${tone}`} role="img" aria-label={label} />
    </Tooltip>
  )
}
