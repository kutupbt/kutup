import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  Bookmark,
  Check,
  CheckCheck,
  Copy,
  Loader2,
  MessageCircle,
  MessageSquareWarning,
  Plus,
  QrCode,
  RefreshCw,
  Send,
  ShieldCheck,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { QRCodeSVG } from 'qrcode.react'
import { useIsMobile } from '@/hooks/useIsMobile'
import { useAppSelector } from '@/store'
import { ChatService, ChatServiceError } from '@/chat/service'
import { isSupportedChat, useChatCapabilities } from '@/chat/capabilities'
import {
  conversationKey,
  contactUri,
  directAddress,
  directConversation,
  parseAccountAddress,
  withHomeServer,
} from '@/chat/identity'
import type {
  ChatCapabilities,
  ChatHistoryEntry,
  ContactRecord,
  ConversationId,
  InboundAttention,
} from '@/chat/types'
import { cn } from '@/lib/utils'
import { copyText } from '@/lib/format'

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
  const [contacts, setContacts] = useState<ContactRecord[]>([])
  const [attention, setAttention] = useState<InboundAttention[]>([])
  const [selectedConversation, setSelectedConversation] = useState<ConversationId | null>(null)
  const [newPeer, setNewPeer] = useState('')
  const [draft, setDraft] = useState('')
  const [loading, setLoading] = useState(true)
  const [sending, setSending] = useState(false)
  const [contactUpdating, setContactUpdating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const selfAccount = useMemo(
    () =>
      auth.username
        ? withHomeServer({ username: auth.username }, capabilities.serverName)
        : null,
    [auth.username, capabilities.serverName],
  )
  const selfAddress = selfAccount
    ? directAddress(directConversation(selfAccount))
    : null

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
        const [nextHistory, nextAttention, nextContacts] = await Promise.all([
          opened.history(),
          opened.inboundAttention(),
          opened.contacts(),
        ])
        if (!cancelled) {
          setHistory(nextHistory)
          setAttention(nextAttention)
          setContacts(nextContacts)
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

  const contactsByPeer = useMemo(
    () => new Map(contacts.map((contact) => [contact.peer, contact])),
    [contacts],
  )

  const peers = useMemo(() => {
    const latest = new Map<string, { conversation: ConversationId; message: ChatHistoryEntry }>()
    for (const message of history) {
      latest.set(conversationKey(message.conversation), {
        conversation: message.conversation,
        message,
      })
    }
    return Array.from(latest.values())
      .filter(({ conversation }) => directAddress(conversation) !== selfAddress)
      .filter(({ conversation }) => {
        const address = directAddress(conversation)
        const state = address ? contactsByPeer.get(address)?.state : undefined
        return state !== 'pendingIncoming' && state !== 'rejected'
      })
      .sort((left, right) => right.message.timestampMs - left.message.timestampMs)
  }, [contactsByPeer, history, selfAddress])

  const requests = useMemo(
    () =>
      contacts
        .filter((contact) => contact.state === 'pendingIncoming')
        .flatMap((contact) => {
          const address = parseAccountAddress(contact.peer)
          return address
            ? [{
                contact,
                conversation: directConversation(address),
                message: history
                  .filter((message) => directAddress(message.conversation) === contact.peer)
                  .at(-1),
              }]
            : []
        })
        .sort((left, right) => right.contact.updatedAtMs - left.contact.updatedAtMs),
    [contacts, history],
  )

  useEffect(() => {
    if (!selectedConversation && peers[0]) setSelectedConversation(peers[0].conversation)
  }, [peers, selectedConversation])

  const selectedKey = selectedConversation ? conversationKey(selectedConversation) : null
  const selectedAddress = selectedConversation ? directAddress(selectedConversation) : null
  const selectedLabel = selectedAddress ??
    (selectedConversation?.kind === 'group' ? selectedConversation.groupId : '')
  const noteSelected = selectedAddress === selfAddress
  const selectedContact = selectedAddress ? contactsByPeer.get(selectedAddress) : undefined
  const requestSelected = selectedContact?.state === 'pendingIncoming'
  const blockedSelected = selectedContact?.state === 'blocked'
  const canSend = Boolean(
    selectedConversation && !requestSelected && !blockedSelected,
  )

  const messages = useMemo(
    () =>
      selectedKey
        ? history.filter((message) => conversationKey(message.conversation) === selectedKey)
        : [],
    [history, selectedKey],
  )

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [messages.length, selectedKey])

  function startConversation(event: FormEvent) {
    event.preventDefault()
    const parsed = parseAccountAddress(newPeer)
    const address = parsed ? withHomeServer(parsed, capabilities.serverName) : null
    if (!address) {
      toast.error(t('chat.errors.invalidAddress'))
      return
    }
    setSelectedConversation(directConversation(address))
    setNewPeer('')
  }

  async function sendMessage(event: FormEvent) {
    event.preventDefault()
    const text = draft.trim()
    if (!service || !selectedConversation || !text || sending) return
    setSending(true)
    setDraft('')
    try {
      const summary = await service.send(selectedConversation, text)
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

  async function updateContact(action: 'accept' | 'reject' | 'block' | 'unblock') {
    if (!service || !selectedAddress || contactUpdating) return
    setContactUpdating(true)
    try {
      if (action === 'accept') await service.acceptContact(selectedAddress)
      if (action === 'reject') await service.rejectContact(selectedAddress)
      if (action === 'block') await service.blockContact(selectedAddress)
      if (action === 'unblock') await service.unblockContact(selectedAddress)
      const [nextHistory, nextContacts] = await Promise.all([
        service.history(),
        service.contacts(),
      ])
      setHistory(nextHistory)
      setContacts(nextContacts)
      if (action === 'reject') setSelectedConversation(null)
    } catch (cause) {
      toast.error(errorMessage(cause, t))
    } finally {
      setContactUpdating(false)
    }
  }

  const showPeerList = !isMobile || !selectedConversation

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
            {selfAccount?.server && selfAddress && (
              <Dialog>
                <DialogTrigger asChild>
                  <Button variant="ghost" size="icon" aria-label={t('chat.contact.open')}>
                    <QrCode className="h-5 w-5" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-sm">
                  <DialogHeader>
                    <DialogTitle>{t('chat.contact.title')}</DialogTitle>
                    <DialogDescription>{t('chat.contact.description')}</DialogDescription>
                  </DialogHeader>
                  <div className="flex flex-col items-center gap-4 py-2">
                    <div className="rounded-xl bg-white p-4">
                      <QRCodeSVG value={contactUri(selfAccount)} size={200} />
                    </div>
                    <code className="max-w-full break-all rounded bg-muted px-3 py-2 text-sm">
                      {selfAddress}
                    </code>
                    <Button
                      className="w-full"
                      onClick={() =>
                        void copyText(selfAddress).then(() => toast.success(t('chat.contact.copied')))
                      }
                    >
                      <Copy className="mr-2 h-4 w-4" />
                      {t('chat.contact.copy')}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            )}
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
            <Button type="submit" size="icon" disabled={!parseAccountAddress(newPeer)}>
              <Plus className="h-4 w-4" />
              <span className="sr-only">{t('chat.start')}</span>
            </Button>
          </form>

          {requests.length > 0 && (
            <div className="border-b p-2">
              <div className="flex items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <MessageSquareWarning className="h-4 w-4" />
                {t('chat.requests.title', { count: requests.length })}
              </div>
              {requests.map(({ contact, conversation, message }) => (
                <button
                  key={contact.peer}
                  type="button"
                  onClick={() => setSelectedConversation(conversation)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                    selectedAddress === contact.peer ? 'bg-warning-faint' : 'hover:bg-accent',
                  )}
                >
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-warning-faint font-semibold text-warning">
                    {contact.peer.slice(0, 1).toUpperCase()}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{contact.peer}</span>
                    <span className="block truncate text-xs text-muted-foreground">
                      {message?.content.text ?? t('chat.newerClient')}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          )}

          {selfAccount && (
            <div className="border-b p-2">
              <button
                type="button"
                onClick={() => setSelectedConversation(directConversation(selfAccount))}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                  noteSelected ? 'bg-primary/10' : 'hover:bg-accent',
                )}
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
                  <Bookmark className="h-5 w-5" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">
                    {t('chat.noteToSelf')}
                  </span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {t('chat.noteToSelfDescription')}
                  </span>
                </span>
              </button>
            </div>
          )}

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
            {peers.map(({ conversation, message }) => {
              const key = conversationKey(conversation)
              const label = directAddress(conversation) ??
                (conversation.kind === 'group' ? conversation.groupId : '')
              return (
              <button
                key={key}
                type="button"
                onClick={() => setSelectedConversation(conversation)}
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition-colors',
                  selectedKey === key ? 'bg-primary/10' : 'hover:bg-accent',
                )}
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary/15 font-semibold text-primary">
                  {label.slice(0, 1).toUpperCase()}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{label}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {message.content.text ?? t('chat.newerClient')}
                  </span>
                </span>
                <span className="text-[11px] text-muted-foreground">
                  {formatTime(message.content.sentAt)}
                </span>
              </button>
              )
            })}
          </div>
        </aside>
      )}

      {(!isMobile || selectedConversation) && (
        <main className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-16 shrink-0 items-center gap-3 border-b bg-card px-4">
            {isMobile && (
              <Button variant="ghost" size="icon" onClick={() => setSelectedConversation(null)}>
                <ArrowLeft className="h-5 w-5" />
              </Button>
            )}
            <span className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/15 font-semibold text-primary">
              {selectedLabel.slice(0, 1).toUpperCase() || '?'}
            </span>
            <div className="min-w-0 flex-1">
              <h2 className="truncate font-semibold">
                {noteSelected
                  ? t('chat.noteToSelf')
                  : selectedLabel || t('chat.selectConversation')}
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
            {!noteSelected &&
              selectedContact &&
              selectedContact.state !== 'pendingIncoming' &&
              selectedContact.state !== 'blocked' && (
              <Button
                variant="ghost"
                size="icon"
                onClick={() => void updateContact('block')}
                disabled={contactUpdating}
                aria-label={t('chat.requests.block')}
              >
                {contactUpdating
                  ? <Loader2 className="h-4 w-4 animate-spin" />
                  : <Ban className="h-4 w-4" />}
              </Button>
            )}
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
          {requestSelected && (
            <div className="flex flex-wrap items-center gap-2 border-b border-warning/30 bg-warning-faint px-4 py-3 text-sm">
              <div className="min-w-0 flex-1">
                <p className="font-medium">{t('chat.requests.incoming', { peer: selectedLabel })}</p>
                <p className="text-xs text-muted-foreground">{t('chat.requests.description')}</p>
              </div>
              <Button size="sm" onClick={() => void updateContact('accept')} disabled={contactUpdating}>
                {t('chat.requests.accept')}
              </Button>
              <Button size="sm" variant="outline" onClick={() => void updateContact('reject')} disabled={contactUpdating}>
                {t('chat.requests.reject')}
              </Button>
              <Button size="sm" variant="destructive" onClick={() => void updateContact('block')} disabled={contactUpdating}>
                {t('chat.requests.block')}
              </Button>
            </div>
          )}
          {blockedSelected && (
            <div className="flex items-center gap-3 border-b border-destructive/20 bg-destructive-faint px-4 py-3 text-sm">
              <Ban className="h-4 w-4 text-destructive" />
              <span className="min-w-0 flex-1">{t('chat.requests.blocked', { peer: selectedLabel })}</span>
              <Button size="sm" variant="outline" onClick={() => void updateContact('unblock')} disabled={contactUpdating}>
                {t('chat.requests.unblock')}
              </Button>
            </div>
          )}

          <div className="flex-1 overflow-y-auto px-4 py-5 md:px-8">
            {!selectedConversation && (
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
                  requestSelected
                    ? t('chat.requests.acceptBeforeReply')
                    : blockedSelected
                      ? t('chat.requests.unblockBeforeReply')
                      : selectedConversation
                    ? t('chat.messagePeer', {
                        peer: noteSelected ? t('chat.noteToSelf') : selectedLabel,
                      })
                    : t('chat.selectConversation')
                }
                disabled={!service || !canSend || sending}
                maxLength={16_000}
                autoComplete="off"
              />
              <Button type="submit" size="icon" disabled={!draft.trim() || !service || !canSend || sending}>
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
