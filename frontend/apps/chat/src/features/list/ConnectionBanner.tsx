import { CloudOff, RefreshCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@kutup/ui/components/button'
import { useChat } from '../../app/chatStore'

/** A drop shorter than this (a server restart, a network hand-over) goes unmentioned. */
const GRACE_MS = 3_000

/**
 * Signal Desktop's network notice above the conversation list: shown while
 * this tab has no link to the server, so a quiet chat is not mistaken for
 * one with no new messages. Sending still works; messages wait in the outbox.
 */
export function ConnectionBanner() {
  const { t } = useTranslation()
  const { connection, service } = useChat()
  const [shown, setShown] = useState(false)

  useEffect(() => {
    if (connection === 'connected') {
      setShown(false)
      return
    }
    const timer = window.setTimeout(() => setShown(true), GRACE_MS)
    return () => window.clearTimeout(timer)
  }, [connection])

  if (!shown || connection === 'connected') return null
  const offline = connection === 'offline'
  return (
    <div role="status" className="m-2 flex items-start gap-3 rounded-lg border border-border bg-muted/60 p-3 text-sm">
      {offline ? (
        <CloudOff className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
      ) : (
        <RefreshCw className="mt-0.5 size-4 shrink-0 animate-spin text-muted-foreground motion-reduce:animate-none" aria-hidden />
      )}
      <div className="min-w-0 flex-1">
        <p className="font-medium">{offline ? t('chat.connection.offline') : t('chat.connection.connecting')}</p>
        <p className="text-muted-foreground">{t('chat.connection.queued')}</p>
      </div>
      {!offline && service ? (
        <Button size="sm" variant="ghost" className="-my-1 shrink-0" onClick={() => service.reconnect()}>
          {t('chat.connection.retry')}
        </Button>
      ) : null}
    </div>
  )
}
