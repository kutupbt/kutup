import { Check, Loader2, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { canonicalAccountAddress, conversationKey, directConversation, parseAccountAddress } from '@kutup/chat-core/identity'
import { Button } from '@kutup/ui/components/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@kutup/ui/components/dialog'
import { Input } from '@kutup/ui/components/input'
import { cn } from '@kutup/ui/lib/cn'
import { refreshChat, useChat } from '../../app/chatStore'
import { Avatar } from '../../components/Avatar'
import { chatErrorMessage } from '../../lib/errors'
import { conversationTitle } from '../../lib/names'
import { attachmentFile, uploadAndSend } from '../../lib/sendMedia'
import { useNow } from '../../lib/useNow'
import { activeTimers, conversationList, groupIdOf, type ConversationSummary, type MessageView } from '../../state/views'

/** Signal lets a message go to up to five chats at once. */
const MAX_TARGETS = 5

/**
 * Forward a message, as Signal does: choose up to five chats; the message
 * goes to each marked "Forwarded" (mentions stay behind; an attachment is
 * uploaded again, since the original is its sender's), with each chat's own
 * disappearing-message timer.
 */
export function ForwardDialog({
  view,
  onOpenChange,
}: {
  view: MessageView | null
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const chat = useChat()
  const now = useNow(60_000)
  const self = chat.self!
  const [query, setQuery] = useState('')
  const [chosen, setChosen] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const open = view !== null
  const attachment = view?.entry.content.attachment

  useEffect(() => {
    if (!open) {
      setQuery('')
      setChosen([])
    }
  }, [open])

  const candidates = useMemo(() => {
    const groups = new Map(chat.snapshot.groups.map((group) => [groupIdOf(group), group]))
    const items = conversationList(chat.snapshot, self.address, now).filter((item) => canForwardTo(item))
    // Note to Self is always a place to forward to, even before it has a message.
    if (!items.some((item) => item.kind === 'note')) {
      const conversation = directConversation(parseAccountAddress(self.address)!)
      items.push({
        key: conversationKey(conversation),
        conversation,
        kind: 'note',
        address: self.address,
        last: null,
        activityMs: 0,
        contact: null,
        profile: null,
        groupInfo: null,
      })
    }
    return items

    function canForwardTo(item: ConversationSummary): boolean {
      if (item.kind === 'note') return true
      if (item.kind === 'direct') {
        // Media to another person travels by sealed delivery.
        return item.contact?.state === 'accepted' && (!attachment || chat.capabilities?.sealedSender === true)
      }
      if (item.kind !== 'group' || item.conversation.kind !== 'group') return false
      const group = groups.get(item.conversation.groupId)
      if (!group || group.status !== 'active' || group.left) return false
      const me = group.currentRoster.find((member) => canonicalAccountAddress(member.address) === self.address)
      return group.currentAuthorizationPolicy.applicationSenders === 1 || me?.isAdmin === true
    }
  }, [chat.snapshot, chat.capabilities, self.address, now, attachment])

  const titled = candidates.map((item) => ({
    item,
    title: conversationTitle(item.conversation, item.address, item.profile, self.address, t, item.groupInfo),
  }))
  const needle = query.trim().toLocaleLowerCase()
  const shown = needle ? titled.filter(({ title, item }) => `${title} ${item.address ?? ''}`.toLocaleLowerCase().includes(needle)) : titled

  function toggle(key: string) {
    setChosen((current) =>
      current.includes(key) ? current.filter((k) => k !== key) : current.length < MAX_TARGETS ? [...current, key] : current,
    )
  }

  async function forward() {
    const service = chat.service
    if (!view || !service || chosen.length === 0) return
    setBusy(true)
    const timers = activeTimers(chat.snapshot.history)
    const targets = candidates.filter((item) => chosen.includes(item.key))
    let sent = 0
    try {
      const file = attachment ? await attachmentFile(attachment) : null
      for (const { key, conversation: target } of targets) {
        const timerSeconds = timers.get(key)
        if (file && chat.capabilities) {
          await uploadAndSend(service, chat.capabilities, target, file, {
            timerSeconds,
            durationMs: attachment?.durationMs,
            extras: { forwarded: true },
          })
        } else {
          const text = view.mutation?.editedText ?? view.entry.content.text ?? ''
          await service.send(target, text, undefined, timerSeconds, { forwarded: true })
        }
        sent += 1
      }
      toast.success(t('chat.forward.sent', { count: sent }))
      onOpenChange(false)
    } catch (error) {
      toast.error(sent > 0 ? t('chat.forward.partial', { sent, total: targets.length }) : chatErrorMessage(error, t))
    } finally {
      setBusy(false)
      await refreshChat()
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="sm:max-w-md" data-testid="chat-forward-dialog">
        <DialogHeader>
          <DialogTitle>{t('chat.forward.title')}</DialogTitle>
          <DialogDescription>{t('chat.forward.description', { count: MAX_TARGETS })}</DialogDescription>
        </DialogHeader>
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            className="pl-9"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('chat.forward.search')}
            aria-label={t('chat.forward.search')}
            autoFocus
          />
        </div>
        <ul className="max-h-72 space-y-0.5 overflow-y-auto" aria-label={t('chat.forward.chats')}>
          {shown.length === 0 ? <li className="px-2 py-6 text-center text-sm text-muted-foreground">{t('chat.forward.none')}</li> : null}
          {shown.map(({ item, title }) => {
            const selected = chosen.includes(item.key)
            const full = !selected && chosen.length >= MAX_TARGETS
            return (
              <li key={item.key}>
                <button
                  type="button"
                  role="checkbox"
                  aria-checked={selected}
                  disabled={full || busy}
                  onClick={() => toggle(item.key)}
                  className={cn(
                    'flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm outline-none',
                    'hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50',
                    selected && 'bg-accent',
                  )}
                  data-testid="chat-forward-target"
                >
                  <Avatar
                    name={title}
                    image={item.groupInfo?.avatar?.data ?? item.profile?.avatar}
                    contentType={item.groupInfo?.avatar?.contentType ?? item.profile?.avatarContentType}
                    group={item.conversation.kind === 'group'}
                    size={32}
                  />
                  <span className="min-w-0 flex-1 truncate">{title}</span>
                  <span
                    className={cn(
                      'flex size-5 shrink-0 items-center justify-center rounded-full border',
                      selected ? 'border-primary bg-primary text-primary-foreground' : 'border-input',
                    )}
                    aria-hidden
                  >
                    {selected ? <Check className="size-3.5" /> : null}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button onClick={() => void forward()} disabled={busy || chosen.length === 0} data-testid="chat-forward-send">
            {busy ? <Loader2 className="animate-spin" /> : null}
            {t('chat.forward.send', { count: chosen.length })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
