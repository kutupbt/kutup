import type { TFunction } from 'i18next'
import type { ChatBackupView } from '@kutup/chat-core/backup'

/** The backup state in a word or two ("Protected", "Backing up"…). */
export function backupStatusLabel(status: ChatBackupView | null, t: TFunction): string {
  switch (status?.state) {
    case 'protected':
      return t('chat.backup.status.protected')
    case 'backingUp':
      return t('chat.backup.status.backingUp')
    case 'offline':
      return t('chat.backup.status.offline')
    case 'mediaPending':
      return t('chat.backup.status.mediaPending')
    case 'needsAttention':
      return t('chat.backup.status.needsAttention')
    default:
      return t('chat.backup.status.starting')
  }
}

export type BackupTone = 'ok' | 'busy' | 'warn' | 'danger'

export function backupTone(status: ChatBackupView | null): BackupTone {
  if (!status) return 'busy'
  if (status.state === 'needsAttention' || status.storageFull) return 'danger'
  if (status.state === 'offline') return 'warn'
  if (status.state === 'protected') return 'ok'
  return 'busy'
}
