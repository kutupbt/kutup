import { ShieldAlert, ShieldCheck, ShieldEllipsis } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { cn } from '@kutup/ui/lib/cn'
import { useChat } from '../../app/chatStore'
import { backupStatusLabel, backupTone } from './backupStatus'

/**
 * The sidebar footer: whether this device's chat history is protected on
 * the server (continuous encrypted backup), opening the details.
 */
export function BackupIndicator() {
  const { t } = useTranslation()
  const chat = useChat()
  if (!chat.capabilities?.backup?.alwaysEnabled) return null
  const status = chat.snapshot.backup
  const tone = backupTone(status)
  const Icon = tone === 'ok' ? ShieldCheck : tone === 'busy' ? ShieldEllipsis : ShieldAlert
  return (
    <Link
      to="/settings/backup"
      className="flex items-center gap-2 rounded-md px-2 py-1.5 text-xs text-chrome-muted hover:bg-chrome-accent hover:text-chrome-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-chrome-accent"
    >
      <Icon className={cn('size-4 shrink-0', tone === 'ok' && 'text-status-ok', tone === 'warn' && 'text-status-warn', tone === 'danger' && 'text-status-danger')} aria-hidden />
      <span className="min-w-0">
        <span className="block font-medium text-chrome-foreground">{t('chat.backup.title')}</span>
        <span className="block truncate">{backupStatusLabel(status, t)}</span>
      </span>
    </Link>
  )
}
