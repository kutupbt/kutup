import { useTranslation } from 'react-i18next'
import type { MembersPendingUpgrade } from '@kutup/drive-core/identityPins'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'

/**
 * Removing someone moves the folder, file or album to a new key, which
 * people still on the old (pre-X-Wing) keys can't get: they lose access too.
 * Asks the owner first, naming them (docs/plans/pq-shares.md). They can be
 * shared with again once they have signed in.
 */
export function PendingUpgradeConfirm({
  error,
  busy,
  onConfirm,
  onCancel,
}: {
  error: MembersPendingUpgrade
  busy: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  return (
    <Alert variant="warn" data-testid="pending-upgrade-confirm">
      <p className="font-medium">{t('pendingUpgrade.title', { count: error.accounts.length })}</p>
      <p className="mt-1 text-sm">{t('pendingUpgrade.body')}</p>
      <ul className="mt-2 list-disc ps-5 text-sm">
        {error.accounts.map((account) => (
          <li key={account}>{account}</li>
        ))}
      </ul>
      <div className="mt-3 flex justify-end gap-2">
        <Button size="sm" variant="outline" onClick={onCancel} disabled={busy}>
          {t('common.cancel')}
        </Button>
        <Button size="sm" variant="destructive" onClick={onConfirm} loading={busy}>
          {t('pendingUpgrade.removeToo')}
        </Button>
      </div>
    </Alert>
  )
}
