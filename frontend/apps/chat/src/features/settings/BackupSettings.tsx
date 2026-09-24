import { Loader2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { ChatMediaStorageView } from '@kutup/chat-core/service'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { cn } from '@kutup/ui/lib/cn'
import { formatBytes } from '@kutup/ui/lib/format'
import { useChat } from '../../app/chatStore'
import { chatErrorMessage } from '../../lib/errors'
import { groupTitle } from '../../lib/names'
import { backupStatusLabel, backupTone } from './backupStatus'
import { SettingsSection } from './SettingsPage'

/**
 * Continuous encrypted history: whether what this device holds is
 * protected on the server yet. It restores by itself on a new device with
 * the same recovery phrase as Drive; there is nothing to switch on.
 */
export function BackupSettings() {
  const { t, i18n } = useTranslation()
  const { snapshot } = useChat()
  const status = snapshot.backup
  const tone = backupTone(status)
  return (
    <SettingsSection title={t('chat.backup.title')} description={t('chat.backup.recovery')}>
      <div className="max-w-2xl space-y-3 rounded-lg border border-border p-4" data-testid="chat-history-backup-status">
        <div className="flex items-center justify-between gap-3">
          <span className="text-sm font-medium">{t('chat.backup.stateLabel')}</span>
          <span
            className={cn(
              'rounded-full px-2.5 py-1 text-xs font-medium',
              tone === 'danger' && 'bg-destructive/10 text-destructive',
              tone === 'warn' && 'bg-status-warn/15 text-foreground',
              tone === 'ok' && 'bg-status-ok/15 text-foreground',
              tone === 'busy' && 'bg-muted text-muted-foreground',
            )}
            data-testid="chat-backup-state"
            data-current-cursor={status?.currentCursor ?? 0}
          >
            {backupStatusLabel(status, t)}
          </span>
        </div>
        <p className="text-sm text-muted-foreground" data-testid="chat-backup-latest-protected">
          {t('chat.backup.latestProtected', {
            time: status?.latestProtectedAt ? new Date(status.latestProtectedAt).toLocaleString(i18n.language) : t('chat.backup.waiting'),
          })}
        </p>
        {(status?.pendingEvents ?? 0) > 0 ? (
          <p className="text-sm text-status-warn">
            {t('chat.backup.pending', { count: status!.pendingEvents, bytes: formatBytes(status!.pendingBytes, i18n.language) })}
          </p>
        ) : null}
        {status?.state === 'needsAttention' || status?.storageFull ? (
          <p className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
            {t(status.storageFull ? 'chat.backup.full' : 'chat.backup.attention')}
          </p>
        ) : null}
      </div>
    </SettingsSection>
  )
}

/**
 * The chat's storage quota (separate from Drive's), what uses it, and the
 * media stored per conversation, which can be cleared (the messages stay).
 */
export function StorageSettings() {
  const { t, i18n } = useTranslation()
  const { service, snapshot, capabilities, self } = useChat()
  const [storage, setStorage] = useState<ChatMediaStorageView | null>(null)
  const [clearing, setClearing] = useState<{ reference: string; label: string } | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const bytes = (value: number) => formatBytes(value, i18n.language)

  useEffect(() => {
    let cancelled = false
    void service
      ?.chatMediaStorage()
      .then((value) => !cancelled && setStorage(value))
      .catch((error: unknown) => !cancelled && toast.error(chatErrorMessage(error, t)))
    return () => {
      cancelled = true
    }
  }, [service, t])

  const usage = snapshot.backup?.storage
  const used = usage?.usedBytes ?? storage?.totalUsedBytes ?? 0
  const quota = usage?.quotaBytes ?? storage?.totalQuotaBytes ?? 0
  const retention = capabilities?.backup?.deliveryMediaRetentionDays
  const profiles = new Map(snapshot.profiles.map((p) => [p.peer, p]))
  const labelOf = (reference: string) =>
    reference === self!.address
      ? t('chat.noteToSelf')
      : (profiles.get(reference)?.displayName ??
        (snapshot.groups.some((g) => g.request.genesis.conversationId === reference) ? groupTitle(reference, t) : reference))

  return (
    <SettingsSection
      title={t('chat.backup.storageTitle')}
      description={retention === 0 ? t('chat.backup.storageDescriptionUnlimited') : t('chat.backup.storageDescription', { days: retention ?? 45 })}
    >
      {!storage ? (
        <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" aria-hidden /> {t('chat.backup.loading')}
        </p>
      ) : (
        <div className="max-w-2xl space-y-4" data-testid="chat-storage-summary">
          <div className="rounded-lg border border-border p-4">
            <div className="flex justify-between text-sm font-medium">
              <span>{t('chat.backup.used', { bytes: bytes(used) })}</span>
              <span>{bytes(quota)}</span>
            </div>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuemin={0} aria-valuemax={quota} aria-valuenow={used}>
              <div className="h-full bg-primary" style={{ width: `${quota > 0 ? Math.min(100, (used * 100) / quota) : 0}%` }} />
            </div>
            <dl className="mt-3 grid grid-cols-1 gap-2 text-sm sm:grid-cols-3">
              {[
                ['messageHistory', usage?.messageBytes ?? 0],
                ['deliveryMedia', usage?.deliveryMediaBytes ?? storage.chatMediaBytes],
                ['historyMedia', usage?.historyMediaBytes ?? 0],
              ].map(([key, value]) => (
                <div key={key as string} className="rounded-md bg-muted/60 p-2">
                  <dt className="text-xs text-muted-foreground">{t(`chat.backup.${key as string}`)}</dt>
                  <dd>{bytes(value as number)}</dd>
                </div>
              ))}
            </dl>
          </div>
          <ul className="space-y-2">
            {storage.byConversation.map((item) => {
              const label = labelOf(item.conversationReference)
              return (
                <li key={item.conversationReference} className="flex items-center gap-3 rounded-lg border border-border px-3 py-2 text-sm">
                  <span className="min-w-0 flex-1 truncate">{label}</span>
                  <span className="shrink-0 text-muted-foreground">{bytes(item.bytes)}</span>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy !== null}
                    onClick={() => setClearing({ reference: item.conversationReference, label })}
                    aria-label={t('chat.storage.clearFor', { name: label })}
                  >
                    {busy === item.conversationReference ? <Loader2 className="animate-spin" /> : t('chat.storage.clear')}
                  </Button>
                </li>
              )
            })}
            {storage.byConversation.length === 0 ? <p className="py-4 text-sm text-muted-foreground">{t('chat.storage.empty')}</p> : null}
          </ul>
        </div>
      )}
      <ConfirmDestructive
        open={clearing !== null}
        onOpenChange={(open) => !open && setClearing(null)}
        title={t('chat.storage.clearTitle', { name: clearing?.label ?? '' })}
        description={t('chat.storage.clearDescription')}
        submit={t('chat.storage.clear')}
        errorFallback={t('chat.errors.unavailable')}
        onConfirm={() => {
          const target = clearing
          setClearing(null)
          if (!target || !service) return
          setBusy(target.reference)
          void service
            .clearChatMediaConversation(target.reference)
            .then(setStorage)
            .catch((error: unknown) => toast.error(chatErrorMessage(error, t)))
            .finally(() => setBusy(null))
        }}
      />
    </SettingsSection>
  )
}
