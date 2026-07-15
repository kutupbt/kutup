import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  CheckCheck,
  Loader2,
  MessageCircle,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useIsMobile } from '@/hooks/useIsMobile'
import { useAppSelector } from '@/store'
import { ChatService, ChatServiceError } from '@/chat/service'
import { isSupportedChat, useChatCapabilities } from '@/chat/capabilities'
import type { ChatCapabilities, ChatHistoryEntry, InboundAttention } from '@/chat/types'
import { cn } from '@/lib/utils'

export default function Chat() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const capabilities = useChatCapabilities()

  useEffect(() => {
    if (capabilities.data && !isSupportedChat(capabilities.data)) {
      navigate('/drive', { replace: true })
    }
  }, [capabilities.data, navigate])

  if (capabilities.isPending) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="sr-only">{t('chat.checkingSupport')}</span>
      </div>
    )
  }
  if (capabilities.isError) {
    return (
      <div className="fixed inset-0 flex flex-col items-center justify-center gap-4 bg-background p-6 text-center">
        <AlertTriangle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-muted-foreground">{t('chat.errors.capabilities')}</p>
        <Button onClick={() => navigate('/drive', { replace: true })}>
          {t('chat.backToFiles')}
        </Button>
      </div>
    )
  }
  if (!capabilities.data || !isSupportedChat(capabilities.data)) return null

  return <SupportedChat capabilities={capabilities.data} />
}

function SupportedChat({ capabilities }: { capabilities: ChatCapabilities }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const auth = useAppSelector((state) => state.auth)
  const masterKey = useMemo(
    () => (auth.masterKey ? new Uint8Array(auth.masterKey) : null),
    [auth.masterKey],
  )
  const [service, setService] = useState<ChatService | null>(null)
  const [history, setHistory] = useState<ChatHistoryEntry[]>([])
  const [attention, setAttention] = useState<InboundAttention[]>([])
  const [selectedPeer, setSelectedPeer] = useState('')
  const [newPeer, setNewPeer] = useState('')
  const [draft, setDraft] = useState('')
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!auth.userId || !auth.username || !masterKey) {
      setError(t('chat.errors.sessionMissing'))
      setLoading(false)
      return
    }

    let cancelled = false
    let opened: ChatService | null = null
    const refresh = async () => {
      if (!opened || cancelled) return
      try {
        const [nextHistory, nextAttention] = await Promise.all([
          opened.history(),
          opened.inboundAttention(),
        ])
        if (!cancelled) {
          setHistory(nextHistory)
          setAttention(nextAttention)
          setError(null)
        }
      } catch (cause) {
        if (!cancelled) setError(errorMessage(cause, t))
      }
    }

    ChatService.open({
      userId: auth.userId,
      username: auth.username,
      masterKey,
      capabilities,
    })
      .then(async (next) => {
        if (cancelled) {
          next.dispose()
          return
        }
        opened = next
        setService(next)
        next.subscribe(() => void refresh())
        await refresh()
      })
      .catch((cause) => {
        if (!cancelled) setError(errorMessage(cause, t))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
      opened?.dispose()
    }
  }, [auth.userId, auth.username, capabilities, masterKey, t])

  const peers = useMemo(() => {
    const latest = new Map<string, ChatHistoryEntry>()
    for (const message of history) latest.set(message.peer, message)
    return Array.from(latest.entries())
      .sort(([, left], [, right]) => right.timestampMs - left.timestampMs)
      .map(([peer, message]) => ({ peer, message }))
  }, [history])

  useEffect(() => {
    if (!selectedPeer && peers[0]) setSelectedPeer(peers[0].peer)
  }, [peers, selectedPeer])

  const messages = useMemo(
    () => history.filter((message) => message.peer === selectedPeer),
    [history, selectedPeer],
  )

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages.length, selectedPeer])

  function startConversation(event: FormEvent) {
    event.preventDefault()
    const peer = newPeer.trim()
    if (!peer) return
    setSelectedPeer(peer)
    setNewPeer('')
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault()
    const text = draft.trim()
    if (!service || !selectedPeer || !text || sending) return
    setSending(true)
    setDraft('')
    try {
      const summary = await service.send(selectedPeer, text)
      if (summary.safetyNumberChanges.length > 0) {
        toast.warning(t('chat.safetyNumberChanged'))
      }
      setHistory(await service.history())
    } catch (cause) {
      setDraft(text)
      toast.error(errorMessage(cause, t))
    } finally {
      setSending(false)
    }
  }

  const showPeerList = !isMobile || !selectedPeer

  return (
    <div className="fixed inset-0 flex bg-background text-foreground">
      {showPeerList && (
        <aside className="flex w-full shrink-0 flex-col border-r bg-sidebar md:w-80">
          <header className="flex h-16 items-center gap-3 border-b px-4">
            <Button variant="ghost" size="icon" onClick={() => navigate('/drive')}>
              <ArrowLeft className="h-5 w-5" />
              <span className="sr-only">{t('chat.backToFiles')}</span>
            </Button>
            <div className="min-w-0 flex-1">
              <h1 className="font-semibold">{t('chat.title')}</h1>
              <p className="truncate text-xs text-muted-foreground">
                {t('chat.encryptedDevice', { device: service?.deviceId ?? '…' })}
              </p>
            </div>
            <ShieldCheck className="h-5 w-5 text-success" aria-label={t('chat.encrypted')} />
          </header>

          <form className="flex gap-2 border-b p-3" onSubmit={startConversation}>
            <Input
              value={newPeer}
              onChange={(event) => setNewPeer(event.target.value)}
              placeholder={t('chat.username')}
              aria-label={t('chat.startAria')}
              autoCapitalize="none"
              autoCorrect="off"
            />
            <Button type="submit" size="icon" disabled={!newPeer.trim()}>
              <Plus className="h-4 w-4" />
              <span className="sr-only">{t('chat.start')}</span>
            </Button>
          </form>

          <div className="flex-1 overflow-y-auto p-2">
            {loading && (
              <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" /> {t('chat.preparing')}
              </div>
            )}
            {!loading && peers.length === 0 && (
              <div className="px-6 py-12 text-center text-sm text-muted-foreground">
                <MessageCircle className="mx-auto mb-3 h-9 w-9 opacity-50" />
                {t('chat.empty')}
              </div>
            )}
            {peers.map(({ peer, message }) => (
              <button
                key={peer}
                type="button"
                onClick={() => setSelectedPeer(peer)}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                  selectedPeer === peer ? 'bg-primary/10' : 'hover:bg-accent',
                )}
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 font-semibold text-primary">
                  {peer.slice(0, 1).toUpperCase()}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{peer}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {message.content.text ?? t('chat.newerClient')}
                  </span>
                </span>
                <span className="text-[11px] text-muted-foreground">
                  {formatTime(message.content.sentAt)}
                </span>
              </button>
            ))}
          </div>
        </aside>
      )}

      {(!isMobile || selectedPeer) && (
        <main className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-16 shrink-0 items-center gap-3 border-b bg-card px-4">
            {isMobile && (
              <Button variant="ghost" size="icon" onClick={() => setSelectedPeer('')}>
                <ArrowLeft className="h-5 w-5" />
              </Button>
            )}
            <span className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/15 font-semibold text-primary">
              {selectedPeer.slice(0, 1).toUpperCase() || '?'}
            </span>
            <div className="min-w-0 flex-1">
              <h2 className="truncate font-semibold">
                {selectedPeer || t('chat.selectConversation')}
              </h2>
              <p className="flex items-center gap-1 text-xs text-muted-foreground">
                <ShieldCheck className="h-3 w-3" /> {t('chat.protocolEncryption')}
              </p>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => void service?.reconcile()}
              disabled={!service}
            >
              <RefreshCw className="h-4 w-4" />
              <span className="sr-only">{t('chat.sync')}</span>
            </Button>
          </header>

          {error && (
            <div className="flex items-center gap-2 border-b border-destructive/20 bg-destructive-faint px-4 py-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span className="flex-1">{error}</span>
            </div>
          )}
          {attention.length > 0 && (
            <div className="flex items-center gap-2 border-b border-warning/30 bg-warning-faint px-4 py-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-warning" />
              {t('chat.attention', { count: attention.length })}
            </div>
          )}

          <div className="flex-1 overflow-y-auto px-4 py-5 md:px-8">
            {!selectedPeer && (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                {t('chat.chooseConversation')}
              </div>
            )}
            <div className="mx-auto flex max-w-3xl flex-col gap-2">
              {messages.map((message) => (
                <MessageBubble
                  key={`${message.direction}:${message.id}`}
                  message={message}
                  newerClientLabel={t('chat.newerClient')}
                />
              ))}
              <div ref={endRef} />
            </div>
          </div>

          <form className="border-t bg-card p-3 md:px-8" onSubmit={sendMessage}>
            <div className="mx-auto flex max-w-3xl items-end gap-2">
              <Input
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                placeholder={
                  selectedPeer
                    ? t('chat.messagePeer', { peer: selectedPeer })
                    : t('chat.selectConversation')
                }
                disabled={!service || !selectedPeer || sending}
                maxLength={16_000}
                autoComplete="off"
              />
              <Button type="submit" size="icon" disabled={!draft.trim() || !service || sending}>
                {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                <span className="sr-only">{t('chat.send')}</span>
              </Button>
            </div>
          </form>
        </main>
      )}
    </div>
  )
}

function MessageBubble({
  message,
  newerClientLabel,
}: {
  message: ChatHistoryEntry
  newerClientLabel: string
}) {
  const outgoing = message.direction === 'outgoing'
  return (
    <div className={cn('flex', outgoing ? 'justify-end' : 'justify-start')}>
      <div
        className={cn(
          'max-w-[82%] rounded-2xl px-3.5 py-2 shadow-sm md:max-w-[70%]',
          outgoing
            ? 'rounded-br-md bg-primary text-primary-foreground'
            : 'rounded-bl-md border bg-card',
        )}
      >
        <p className="whitespace-pre-wrap break-words text-sm">
          {message.content.text ?? newerClientLabel}
        </p>
        <span
          className={cn(
            'mt-1 flex items-center justify-end gap-1 text-[10px]',
            outgoing ? 'text-primary-foreground/70' : 'text-muted-foreground',
          )}
        >
          {formatTime(message.content.sentAt)}
          {outgoing && (message.delivered ? <CheckCheck className="h-3 w-3" /> : <Check className="h-3 w-3" />)}
        </span>
      </div>
    </div>
  )
}

function formatTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(date)
}

function errorMessage(
  error: unknown,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  if (error instanceof ChatServiceError) return t(`chat.errors.${error.code}`)
  return t('chat.errors.unavailable')
}
