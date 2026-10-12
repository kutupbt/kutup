import { AlertTriangle, Check, CloudOff, KeyRound, Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Badge } from '@kutup/ui/components/badge'
import type { SyncStatus } from '../sync/vaultSession'

/** Where the vault's edits are: in Drive, on their way, or kept here. */
export function SyncBadge({ status }: { status: SyncStatus }) {
  const { t } = useTranslation()
  switch (status) {
    case 'saved':
      return (
        <Badge variant="ok" role="status">
          <Check className="size-3" aria-hidden />
          {t('sync.saved')}
        </Badge>
      )
    case 'saving':
      return (
        <Badge variant="neutral" role="status">
          <Loader2 className="size-3 animate-spin" aria-hidden />
          {t('sync.saving')}
        </Badge>
      )
    case 'offline':
      return (
        <Badge variant="warn" role="status" title={t('sync.offlineDescription')}>
          <CloudOff className="size-3" aria-hidden />
          {t('sync.offline')}
        </Badge>
      )
    case 'needsKey':
      return (
        <Badge variant="warn" role="status">
          <KeyRound className="size-3" aria-hidden />
          {t('sync.needsKey')}
        </Badge>
      )
    case 'quota':
      return (
        <Badge variant="danger" role="status">
          <AlertTriangle className="size-3" aria-hidden />
          {t('sync.quota')}
        </Badge>
      )
    case 'error':
      return (
        <Badge variant="danger" role="status">
          <AlertTriangle className="size-3" aria-hidden />
          {t('sync.error')}
        </Badge>
      )
  }
}
