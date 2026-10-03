import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { requestLocalChatDeviceReset } from '@kutup/chat-core/local-store'
import { appUrl } from '@kutup/session/apps'
import { useRequiredSession } from '@kutup/session/store'
import { Alert } from '@kutup/ui/components/alert'
import { Button } from '@kutup/ui/components/button'
import { ConfirmDestructive } from '@kutup/ui/components/confirm-destructive'
import { LoadingPanel, Spinner } from '@kutup/ui/components/states'
import { loadReadMarks } from '../state/readState'
import { openChat, reopenChat, useChat } from './chatStore'

/**
 * Opens the chat for the signed-in account and holds everything back until
 * it is ready, explaining why when it cannot be: no Chat on this server, a
 * browser that cannot coordinate tabs, or a device that will not open (with
 * the local repair the old page offered).
 */
export function ChatGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const session = useRequiredSession()
  const chat = useChat()
  const [repairing, setRepairing] = useState(false)

  useEffect(() => {
    loadReadMarks(session.userId)
    openChat(session)
  }, [session])

  if (chat.status === 'ready' && chat.loaded) return <>{children}</>
  if (chat.status !== 'failed') return <LoadingPanel label={t('chat.preparing')} />

  const failure = chat.failure ?? 'unavailable'
  // The server is out of reach, which is nobody's device at fault: wait and
  // retry, and offer nothing destructive.
  if (failure === 'unreachable') {
    return (
      <div className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
        <Alert variant="warn" title={t('chat.unreachable.title')}>
          {t('chat.unreachable.body')}
        </Alert>
        <div className="flex items-center gap-3">
          <Button onClick={() => reopenChat(session)}>{t('chat.unreachable.tryNow')}</Button>
          <span className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
            <Spinner label={t('chat.unreachable.retrying')} className="size-4" />
            {t('chat.unreachable.retrying')}
          </span>
        </div>
      </div>
    )
  }
  return (
    <div className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
      <Alert variant="error" title={t('chat.failed.title')}>
        {t(`chat.errors.${failure}`)}
      </Alert>
      <div className="flex flex-wrap gap-2">
        {failure === 'unavailable' ? (
          <>
            <Button onClick={() => window.location.reload()}>{t('common.retry')}</Button>
            <Button variant="outline" onClick={() => setRepairing(true)}>
              {t('chat.deviceRecovery.action')}
            </Button>
          </>
        ) : failure === 'capabilities' ? (
          <Button onClick={() => window.location.reload()}>{t('common.retry')}</Button>
        ) : (
          <Button variant="outline" asChild>
            <a href={appUrl('drive')}>{t('chat.failed.toDrive')}</a>
          </Button>
        )}
      </div>
      <ConfirmDestructive
        open={repairing}
        onOpenChange={setRepairing}
        title={t('chat.deviceRecovery.title')}
        description={t('chat.deviceRecovery.description')}
        warning={t('chat.deviceRecovery.warning')}
        submit={t('chat.deviceRecovery.confirm')}
        errorFallback={t('chat.deviceRecovery.failed')}
        onConfirm={() => {
          // The reset itself runs as the next open starts, before any keys load.
          requestLocalChatDeviceReset(session.userId)
          window.location.reload()
        }}
      />
    </div>
  )
}
